// Package subscriber wraps NATS JetStream durable consumer setup.
package subscriber

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cosmicsec/broker/internal/metrics"
	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// Handler is an async message handler function signature.
type Handler func(ctx context.Context, subject string, data map[string]any) error

// Subscriber manages NATS JetStream durable subscriptions.
type Subscriber struct {
	js      nats.JetStreamContext
	metrics *metrics.Metrics
	logger  *zap.Logger
}

// New creates a new Subscriber.
func New(js nats.JetStreamContext, m *metrics.Metrics, log *zap.Logger) *Subscriber {
	return &Subscriber{js: js, metrics: m, logger: log}
}

// Subscribe creates a durable push-consumer on the given subject with
// the provided queue group.  Each received message is decoded from the
// Envelope JSON and forwarded to handler.
//
// Messages are acked on success; nack'd with no-wait on handler error
// so the broker can re-deliver immediately.
func (s *Subscriber) Subscribe(
	ctx context.Context,
	subject, durableName string,
	handler Handler,
) (nats.Subscription, error) {
	sub, err := s.js.QueueSubscribe(
		subject,
		durableName,
		func(msg *nats.Msg) {
			defer func() {
				if r := recover(); r != nil {
					s.logger.Error("panic in message handler",
						zap.String("subject", subject),
						zap.Any("panic", r),
					)
					_ = msg.NakWithDelay(0)
				}
			}()

			var envelope map[string]any
			if err := json.Unmarshal(msg.Data, &envelope); err != nil {
				s.logger.Error("failed to unmarshal envelope",
					zap.String("subject", subject),
					zap.Error(err),
				)
				_ = msg.Ack()
				return
			}

			payload, _ := envelope["payload"].(map[string]any)
			if payload == nil {
				payload = envelope
			}

			if err := handler(ctx, msg.Subject, payload); err != nil {
				s.logger.Warn("handler returned error — nacking",
					zap.String("subject", subject),
					zap.Error(err),
				)
				s.metrics.EventErrors.WithLabelValues(subject).Inc()
				_ = msg.NakWithDelay(0)
				return
			}

			_ = msg.Ack()
			s.metrics.EventsConsumed.WithLabelValues(subject).Inc()
		},
		nats.Durable(durableName),
		nats.AckExplicit(),
		nats.ManualAck(),
	)
	if err != nil {
		return nil, fmt.Errorf("QueueSubscribe %q (durable %q): %w", subject, durableName, err)
	}
	s.logger.Info("subscribed to NATS subject",
		zap.String("subject", subject),
		zap.String("durable", durableName),
	)
	return sub, nil
}
