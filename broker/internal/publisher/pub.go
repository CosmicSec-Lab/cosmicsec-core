// Package publisher wraps NATS JetStream message publishing with retry and
// metrics instrumentation.
package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cosmicsec/broker/internal/events"
	"github.com/cosmicsec/broker/internal/metrics"
	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// Publisher publishes events to NATS JetStream.
type Publisher struct {
	js      nats.JetStreamContext
	metrics *metrics.Metrics
	logger  *zap.Logger
}

// New creates a new Publisher backed by the given JetStream context.
func New(js nats.JetStreamContext, m *metrics.Metrics, log *zap.Logger) *Publisher {
	return &Publisher{js: js, metrics: m, logger: log}
}

// Publish serialises the payload as an Envelope and delivers it to NATS.
// It returns an error only after exhausting retries (3 attempts, 200ms back-off).
func (p *Publisher) Publish(ctx context.Context, subject string, payload any) error {
	env := events.Envelope{
		Subject:   subject,
		Timestamp: time.Now().UTC(),
		Payload:   payload,
	}

	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if _, err = p.js.Publish(subject, data); err == nil {
			p.metrics.EventsPublished.WithLabelValues(subject).Inc()
			p.logger.Debug("published event",
				zap.String("subject", subject),
				zap.Int("attempt", attempt),
			)
			return nil
		}

		lastErr = err
		p.logger.Warn("publish attempt failed",
			zap.String("subject", subject),
			zap.Int("attempt", attempt),
			zap.Error(err),
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond * time.Duration(attempt)):
		}
	}

	p.metrics.EventErrors.WithLabelValues(subject).Inc()
	return fmt.Errorf("publish to %q failed after %d attempts: %w", subject, maxAttempts, lastErr)
}
