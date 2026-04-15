module github.com/cosmicsec/broker

go 1.24

require (
	github.com/nats-io/nats.go v1.37.0
	github.com/redis/go-redis/v9 v9.7.0
	github.com/prometheus/client_golang v1.20.5
	go.opentelemetry.io/otel v1.32.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.32.0
	go.opentelemetry.io/otel/sdk v1.32.0
	go.uber.org/zap v1.27.0
	github.com/spf13/viper v1.19.0
	github.com/google/uuid v1.6.0
)
