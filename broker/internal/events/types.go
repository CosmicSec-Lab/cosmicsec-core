// Package events defines the canonical event types exchanged between
// CosmicSec microservices via NATS JetStream and Redis Streams.
//
// All events are serialised as JSON.  The Envelope wrapper ensures every
// message carries a trace_id and timestamp even when the payload is
// delivered by a legacy service that does not set those fields.
package events

import "time"

// Subjects — well-known NATS subject strings.
const (
	SubjectScanStarted       = "cosmicsec.scan.started"
	SubjectScanCompleted     = "cosmicsec.scan.completed"
	SubjectScanFailed        = "cosmicsec.scan.failed"
	SubjectFindingCreated    = "cosmicsec.finding.created"
	SubjectFindingCritical   = "cosmicsec.finding.critical"
	SubjectAlertTriggered    = "cosmicsec.alert.triggered"
	SubjectAgentConnected    = "cosmicsec.agent.connected"
	SubjectAgentDisconnected = "cosmicsec.agent.disconnected"
	SubjectUserRegistered    = "cosmicsec.user.registered"
	SubjectUserLogin         = "cosmicsec.user.login"
)

// Envelope is the outermost JSON wrapper for every event.
type Envelope struct {
	Subject   string    `json:"subject"`
	TraceID   string    `json:"trace_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Payload   any       `json:"payload"`
}

// ---------------------------------------------------------------------------
// Scan lifecycle events
// ---------------------------------------------------------------------------

// ScanStarted is emitted by scan_service when a scan job begins.
type ScanStarted struct {
	ScanID    string   `json:"scan_id"`
	Target    string   `json:"target"`
	UserID    string   `json:"user_id"`
	Tools     []string `json:"tools"`
	Timestamp string   `json:"timestamp"`
}

// ScanCompleted is emitted when a scan job finishes successfully.
type ScanCompleted struct {
	ScanID         string  `json:"scan_id"`
	FindingsCount  int     `json:"findings_count"`
	CriticalCount  int     `json:"critical_count"`
	DurationSecs   float64 `json:"duration_secs"`
	Timestamp      string  `json:"timestamp"`
}

// ScanFailed is emitted when a scan job terminates with an error.
type ScanFailed struct {
	ScanID    string `json:"scan_id"`
	Reason    string `json:"reason"`
	Timestamp string `json:"timestamp"`
}

// ---------------------------------------------------------------------------
// Finding events
// ---------------------------------------------------------------------------

// FindingCreated is emitted for every finding produced by a scan.
type FindingCreated struct {
	FindingID string `json:"finding_id"`
	ScanID    string `json:"scan_id"`
	Severity  string `json:"severity"`   // critical|high|medium|low|info
	Title     string `json:"title"`
	Target    string `json:"target"`
	Tool      string `json:"tool"`
	Timestamp string `json:"timestamp"`
}

// ---------------------------------------------------------------------------
// Alert events
// ---------------------------------------------------------------------------

// AlertTriggered is emitted when a finding crosses a severity threshold.
type AlertTriggered struct {
	AlertID   string `json:"alert_id"`
	FindingID string `json:"finding_id"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Timestamp string `json:"timestamp"`
}

// ---------------------------------------------------------------------------
// Agent lifecycle events
// ---------------------------------------------------------------------------

// AgentConnected is emitted when a CLI agent establishes a relay connection.
type AgentConnected struct {
	AgentID   string   `json:"agent_id"`
	Tools     []string `json:"tools"`
	IP        string   `json:"ip"`
	Timestamp string   `json:"timestamp"`
}

// AgentDisconnected is emitted when an agent connection drops.
type AgentDisconnected struct {
	AgentID   string `json:"agent_id"`
	Reason    string `json:"reason"`
	Timestamp string `json:"timestamp"`
}

// ---------------------------------------------------------------------------
// Auth events
// ---------------------------------------------------------------------------

// UserRegistered is emitted after a successful account creation.
type UserRegistered struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Timestamp string `json:"timestamp"`
}

// UserLogin is emitted on every successful authentication.
type UserLogin struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
}
