// Package main is the entry point for the CosmicSec Go Event Broker.
//
// The broker bridges NATS JetStream ↔ Redis Streams, enabling low-latency
// event fan-out from Python microservices to all consumers (AI service,
// notification service, audit pipeline, etc.).
//
// Architecture:
//
//	Python services → Redis Streams → Broker → NATS JetStream → consumers
//	NATS JetStream  → Broker → Redis Streams → Python services
//
// Health & Metrics:
//
//	GET /health   — liveness probe
//	GET /ready    — readiness probe (NATS + Redis connectivity)
//	GET /metrics  — Prometheus text metrics
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	nats "github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	redis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config struct {
	NATSUrl      string
	RedisAddr    string
	RedisPass    string
	HTTPPort     string
	LogLevel     string
	ConsumerName string
}

func loadConfig() Config {
	return Config{
		NATSUrl:      getenv("NATS_URL", "nats://localhost:4222"),
		RedisAddr:    getenv("REDIS_ADDR", "localhost:6379"),
		RedisPass:    getenv("REDIS_PASSWORD", ""),
		HTTPPort:     getenv("BROKER_HTTP_PORT", "8090"),
		LogLevel:     getenv("LOG_LEVEL", "info"),
		ConsumerName: fmt.Sprintf("broker-%s", uuid.New().String()[:8]),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------

var (
	eventsConsumedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cosmicsec_broker_events_consumed_total",
			Help: "Total events consumed from Redis Streams",
		},
		[]string{"stream"},
	)
	eventsPublishedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cosmicsec_broker_events_published_total",
			Help: "Total events published to NATS subjects",
		},
		[]string{"subject"},
	)
	bridgeErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cosmicsec_broker_errors_total",
			Help: "Total bridge errors",
		},
		[]string{"direction", "reason"},
	)
	eventLatencyMs = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "cosmicsec_broker_event_latency_ms",
		Help:    "End-to-end event bridge latency in milliseconds",
		Buckets: prometheus.ExponentialBuckets(0.5, 2, 14),
	})
)

func registerMetrics() {
	prometheus.MustRegister(
		eventsConsumedTotal,
		eventsPublishedTotal,
		bridgeErrorsTotal,
		eventLatencyMs,
	)
}

// ---------------------------------------------------------------------------
// Broker
// ---------------------------------------------------------------------------

// Broker bridges Redis Streams → NATS and NATS → Redis.
type Broker struct {
	cfg    Config
	nc     *nats.Conn
	js     nats.JetStreamContext
	rdb    *redis.Client
	logger *zap.Logger
}

func newBroker(cfg Config, logger *zap.Logger) (*Broker, error) {
	// Connect to NATS
	nc, err := nats.Connect(cfg.NATSUrl,
		nats.Name("cosmicsec-broker"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			logger.Warn("NATS disconnected", zap.Error(err))
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			logger.Info("NATS reconnected")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("NATS connect: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("JetStream context: %w", err)
	}

	// Ensure streams exist
	if err := ensureStreams(js, logger); err != nil {
		return nil, err
	}

	// Connect to Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPass,
	})

	return &Broker{cfg: cfg, nc: nc, js: js, rdb: rdb, logger: logger}, nil
}

func ensureStreams(js nats.JetStreamContext, logger *zap.Logger) error {
	streams := []struct {
		name     string
		subjects []string
	}{
		{"COSMICSEC_EVENTS", []string{"cosmicsec.events.>"}},
		{"COSMICSEC_ALERTS", []string{"cosmicsec.alerts.>"}},
		{"COSMICSEC_SCANS", []string{"cosmicsec.scans.>"}},
	}

	for _, s := range streams {
		_, err := js.StreamInfo(s.name)
		if err == nil {
			continue // already exists
		}
		_, err = js.AddStream(&nats.StreamConfig{
			Name:      s.name,
			Subjects:  s.subjects,
			Retention: nats.LimitsPolicy,
			MaxAge:    24 * time.Hour,
			Storage:   nats.FileStorage,
			Replicas:  1,
		})
		if err != nil {
			return fmt.Errorf("create NATS stream %s: %w", s.name, err)
		}
		logger.Info("created NATS JetStream stream", zap.String("stream", s.name))
	}
	return nil
}

// BridgeRedisToNATS reads from a Redis Stream and publishes to the mapped NATS subject.
func (b *Broker) BridgeRedisToNATS(ctx context.Context, streamKey, natsSubject, group string) {
	b.logger.Info("starting Redis→NATS bridge",
		zap.String("stream", streamKey),
		zap.String("subject", natsSubject),
	)

	// Ensure consumer group
	b.rdb.XGroupCreateMkStream(ctx, streamKey, group, "$")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgs, err := b.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    group,
			Consumer: b.cfg.ConsumerName,
			Streams:  []string{streamKey, ">"},
			Count:    50,
			Block:    5 * time.Second,
		}).Result()
		if err != nil {
			if err != redis.Nil {
				bridgeErrorsTotal.WithLabelValues("redis_to_nats", "xreadgroup").Inc()
				b.logger.Warn("XReadGroup error", zap.Error(err))
			}
			continue
		}

		for _, msg := range msgs {
			for _, entry := range msg.Messages {
				start := time.Now()

				data, _ := json.Marshal(entry.Values)
				if _, err := b.js.Publish(natsSubject, data); err != nil {
					bridgeErrorsTotal.WithLabelValues("redis_to_nats", "nats_publish").Inc()
					b.logger.Warn("NATS publish failed", zap.Error(err))
					continue
				}

				// Acknowledge processed message
				b.rdb.XAck(ctx, streamKey, group, entry.ID)

				eventsConsumedTotal.WithLabelValues(streamKey).Inc()
				eventsPublishedTotal.WithLabelValues(natsSubject).Inc()
				eventLatencyMs.Observe(float64(time.Since(start).Milliseconds()))
			}
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP server (health + metrics)
// ---------------------------------------------------------------------------

func startHTTPServer(cfg Config, nc *nats.Conn, rdb *redis.Client, logger *zap.Logger) {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"cosmicsec-broker"}`)
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		natsOK := nc.IsConnected()
		redisOK := rdb.Ping(r.Context()).Err() == nil

		if natsOK && redisOK {
			fmt.Fprintf(w, `{"ready":true,"nats":true,"redis":true}`)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"ready":false,"nats":%v,"redis":%v}`, natsOK, redisOK)
		}
	})

	mux.Handle("/metrics", promhttp.Handler())

	addr := ":" + cfg.HTTPPort
	logger.Info("HTTP server listening", zap.String("addr", addr))
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Fatal("HTTP server failed", zap.Error(err))
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	cfg := loadConfig()

	logger, _ := zap.NewProduction()
	defer logger.Sync() //nolint:errcheck

	logger.Info("CosmicSec Event Broker starting",
		zap.String("nats_url", cfg.NATSUrl),
		zap.String("redis_addr", cfg.RedisAddr),
		zap.String("http_port", cfg.HTTPPort),
	)

	registerMetrics()

	broker, err := newBroker(cfg, logger)
	if err != nil {
		logger.Fatal("broker initialisation failed", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start bridges in goroutines
	bridges := []struct {
		streamKey   string
		natsSubject string
		group       string
	}{
		{"cosmicsec:events", "cosmicsec.events.raw", "broker-events"},
		{"cosmicsec:ingest:raw", "cosmicsec.scans.ingest", "broker-ingest"},
		{"cosmicsec:findings:parsed", "cosmicsec.scans.findings", "broker-findings"},
		{"cosmicsec:alerts", "cosmicsec.alerts.new", "broker-alerts"},
	}

	for _, b := range bridges {
		go broker.BridgeRedisToNATS(ctx, b.streamKey, b.natsSubject, b.group)
	}

	// HTTP health / metrics server (non-blocking)
	go startHTTPServer(cfg, broker.nc, broker.rdb, logger)

	// Graceful shutdown on SIGINT / SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutdown signal received — stopping broker")
	cancel()
	broker.nc.Drain() //nolint:errcheck
	logger.Info("broker stopped cleanly")
}
