// Package config provides environment-based configuration for the CosmicSec broker.
package config

import (
	"fmt"
	"os"
)

// Config holds all runtime configuration for the broker.
type Config struct {
	// NATS connection string e.g. nats://localhost:4222
	NATSUrl string
	// Redis address e.g. localhost:6379
	RedisAddr string
	// Redis AUTH password (empty string = no auth)
	RedisPass string
	// TCP port for the HTTP management server
	HTTPPort string
	// Zap log level: debug, info, warn, error
	LogLevel string
	// Unique consumer name (used for Redis XREADGROUP consumer ID)
	ConsumerName string
	// Maximum number of events to read per Redis XREADGROUP call
	RedisReadCount int64
	// Milliseconds to block on Redis XREADGROUP when the stream is empty
	RedisBlockMs int64
}

// Load reads all config from environment variables, applying defaults where
// appropriate.  An error is returned only if a required variable is missing
// or invalid.
func Load() (*Config, error) {
	cfg := &Config{
		NATSUrl:        getenv("NATS_URL", "nats://localhost:4222"),
		RedisAddr:      getenv("REDIS_ADDR", "localhost:6379"),
		RedisPass:      getenv("REDIS_PASSWORD", ""),
		HTTPPort:       getenv("BROKER_HTTP_PORT", "8090"),
		LogLevel:       getenv("LOG_LEVEL", "info"),
		RedisReadCount: 100,
		RedisBlockMs:   2000,
	}
	cfg.ConsumerName = fmt.Sprintf("broker-%s", uniqueSuffix())
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// uniqueSuffix returns the first 8 chars of the hostname or a default.
func uniqueSuffix() string {
	h, err := os.Hostname()
	if err != nil || len(h) == 0 {
		return "unknown"
	}
	if len(h) > 8 {
		return h[:8]
	}
	return h
}
