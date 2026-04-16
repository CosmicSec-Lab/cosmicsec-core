// Package handlers provides event-specific business logic for the CosmicSec broker.
//
// Each handler receives a decoded event payload and dispatches it to the
// appropriate downstream consumers.  Handlers are intentionally stateless and
// side-effect-free apart from NATS publishes and structured log lines.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cosmicsec/broker/internal/events"
	"github.com/cosmicsec/broker/internal/publisher"
	"go.uber.org/zap"
)

// Dispatcher routes incoming events to the correct NATS fan-out subjects.
type Dispatcher struct {
	pub    *publisher.Publisher
	logger *zap.Logger
}

// New returns a configured Dispatcher.
func New(pub *publisher.Publisher, log *zap.Logger) *Dispatcher {
	return &Dispatcher{pub: pub, logger: log}
}

// ---------------------------------------------------------------------------
// Finding handlers
// ---------------------------------------------------------------------------

// OnFindingCreated fans out a finding.created event to:
//   - cosmicsec.finding.created   (all subscribers)
//   - cosmicsec.finding.critical  (critical findings only — triggers immediate alerts)
func (d *Dispatcher) OnFindingCreated(ctx context.Context, subject string, data map[string]any) error {
	finding := parseFinding(data)
	d.logger.Info("finding.created received",
		zap.String("finding_id", finding.FindingID),
		zap.String("severity", finding.Severity),
		zap.String("scan_id", finding.ScanID),
	)

	if err := d.pub.Publish(ctx, events.SubjectFindingCreated, finding); err != nil {
		return fmt.Errorf("publish finding.created: %w", err)
	}

	if finding.Severity == "critical" || finding.Severity == "high" {
		alert := events.AlertTriggered{
			AlertID:   fmt.Sprintf("alert-%s", finding.FindingID),
			FindingID: finding.FindingID,
			Severity:  finding.Severity,
			Title:     finding.Title,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
		if err := d.pub.Publish(ctx, events.SubjectAlertTriggered, alert); err != nil {
			d.logger.Warn("failed to publish alert", zap.Error(err))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scan lifecycle handlers
// ---------------------------------------------------------------------------

// OnScanCompleted forwards a scan.completed event and triggers report generation.
func (d *Dispatcher) OnScanCompleted(ctx context.Context, subject string, data map[string]any) error {
	d.logger.Info("scan.completed received",
		zap.String("scan_id", strVal(data, "scan_id")),
		zap.Any("findings_count", data["findings_count"]),
	)
	completed := events.ScanCompleted{
		ScanID:        strVal(data, "scan_id"),
		FindingsCount: intVal(data, "findings_count"),
		CriticalCount: intVal(data, "critical_count"),
		DurationSecs:  floatVal(data, "duration_secs"),
		Timestamp:     strVal(data, "timestamp"),
	}
	return d.pub.Publish(ctx, events.SubjectScanCompleted, completed)
}

// OnScanStarted forwards a scan.started event.
func (d *Dispatcher) OnScanStarted(ctx context.Context, subject string, data map[string]any) error {
	d.logger.Info("scan.started received", zap.String("scan_id", strVal(data, "scan_id")))
	started := events.ScanStarted{
		ScanID:    strVal(data, "scan_id"),
		Target:    strVal(data, "target"),
		UserID:    strVal(data, "user_id"),
		Timestamp: strVal(data, "timestamp"),
	}
	return d.pub.Publish(ctx, events.SubjectScanStarted, started)
}

// ---------------------------------------------------------------------------
// Agent lifecycle handlers
// ---------------------------------------------------------------------------

// OnAgentConnected forwards an agent.connected event.
func (d *Dispatcher) OnAgentConnected(ctx context.Context, subject string, data map[string]any) error {
	d.logger.Info("agent.connected received", zap.String("agent_id", strVal(data, "agent_id")))
	connected := events.AgentConnected{
		AgentID:   strVal(data, "agent_id"),
		IP:        strVal(data, "ip"),
		Timestamp: strVal(data, "timestamp"),
	}
	return d.pub.Publish(ctx, events.SubjectAgentConnected, connected)
}

// OnAgentDisconnected forwards an agent.disconnected event.
func (d *Dispatcher) OnAgentDisconnected(ctx context.Context, subject string, data map[string]any) error {
	d.logger.Info("agent.disconnected received", zap.String("agent_id", strVal(data, "agent_id")))
	disconnected := events.AgentDisconnected{
		AgentID:   strVal(data, "agent_id"),
		Reason:    strVal(data, "reason"),
		Timestamp: strVal(data, "timestamp"),
	}
	return d.pub.Publish(ctx, events.SubjectAgentDisconnected, disconnected)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseFinding(data map[string]any) events.FindingCreated {
	return events.FindingCreated{
		FindingID: strVal(data, "finding_id"),
		ScanID:    strVal(data, "scan_id"),
		Severity:  strVal(data, "severity"),
		Title:     strVal(data, "title"),
		Target:    strVal(data, "target"),
		Tool:      strVal(data, "tool"),
		Timestamp: strVal(data, "timestamp"),
	}
}

func strVal(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		b, _ := json.Marshal(v)
		return string(b)
	}
	return ""
}

func intVal(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		}
	}
	return 0
}

func floatVal(m map[string]any, key string) float64 {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return 0
}
