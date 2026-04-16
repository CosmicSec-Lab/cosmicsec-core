// Package metrics provides Prometheus instrumentation for the CosmicSec broker.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus counters and histograms for the broker.
type Metrics struct {
	EventsConsumed  *prometheus.CounterVec
	EventsPublished *prometheus.CounterVec
	EventErrors     *prometheus.CounterVec
	ProcessDuration *prometheus.HistogramVec
}

// New registers and returns a new Metrics instance using promauto so metrics
// are automatically registered on the default Prometheus registry.
func New() *Metrics {
	return &Metrics{
		EventsConsumed: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "cosmicsec_broker_events_consumed_total",
			Help: "Total events consumed from Redis Streams, partitioned by stream name.",
		}, []string{"stream"}),

		EventsPublished: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "cosmicsec_broker_events_published_total",
			Help: "Total events published to NATS subjects, partitioned by subject.",
		}, []string{"subject"}),

		EventErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "cosmicsec_broker_event_errors_total",
			Help: "Total event processing errors, partitioned by stream/subject.",
		}, []string{"source"}),

		ProcessDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cosmicsec_broker_event_process_duration_seconds",
			Help:    "Time taken to process a single event end-to-end.",
			Buckets: prometheus.DefBuckets,
		}, []string{"stream"}),
	}
}
