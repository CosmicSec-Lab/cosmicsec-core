// Package tests provides integration tests for the CosmicSec event broker.
// These tests use a real NATS server started in-process using the nats-server package.
// Phase T.5 — Go event broker integration tests.
package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// getNATSURL returns the NATS URL to use in tests.
// Falls back to an in-process embedded server or the env variable.
func getNATSURL() string {
	if url := os.Getenv("NATS_URL"); url != "" {
		return url
	}
	return nats.DefaultURL // nats://localhost:4222
}

// connectOrSkip connects to NATS or skips the test if NATS is unavailable.
func connectOrSkip(t *testing.T) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(getNATSURL(),
		nats.Timeout(2*time.Second),
		nats.MaxReconnects(1),
	)
	if err != nil {
		t.Skipf("NATS unavailable (%s): %v — skipping integration test", getNATSURL(), err)
	}
	t.Cleanup(func() { nc.Drain() })
	return nc
}

// TestNATSConnect verifies basic connectivity.
func TestNATSConnect(t *testing.T) {
	nc := connectOrSkip(t)
	if !nc.IsConnected() {
		t.Fatal("expected connection to be active")
	}
	t.Logf("Connected to NATS: %s", nc.ConnectedUrl())
}

// TestPublishSubscribe tests basic pub/sub round-trip.
func TestPublishSubscribe(t *testing.T) {
	nc := connectOrSkip(t)

	received := make(chan []byte, 1)
	subject := fmt.Sprintf("test.pubsub.%d", time.Now().UnixNano())

	sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		received <- msg.Data
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	payload := []byte(`{"event":"test","value":42}`)
	if err := nc.Publish(subject, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case data := <-received:
		var m map[string]interface{}
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if m["event"] != "test" {
			t.Errorf("expected event=test, got %v", m["event"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for message")
	}
}

// TestScanStartedEvent tests publishing a scan.started event.
func TestScanStartedEvent(t *testing.T) {
	nc := connectOrSkip(t)

	subject := "scan.started"
	received := make(chan []byte, 1)

	sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		received <- msg.Data
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	event := map[string]interface{}{
		"scan_id":   "scan-test-001",
		"target":    "192.168.1.1",
		"user_id":   "user-test-001",
		"tools":     []string{"nmap", "nuclei"},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(event)

	if err := nc.Publish(subject, data); err != nil {
		t.Fatalf("publish scan.started: %v", err)
	}

	select {
	case msg := <-received:
		var e map[string]interface{}
		json.Unmarshal(msg, &e)
		if e["scan_id"] != "scan-test-001" {
			t.Errorf("expected scan_id=scan-test-001, got %v", e["scan_id"])
		}
		if e["target"] != "192.168.1.1" {
			t.Errorf("expected target=192.168.1.1, got %v", e["target"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for scan.started event")
	}
}

// TestFindingCreatedEvent tests publishing a finding.created event.
func TestFindingCreatedEvent(t *testing.T) {
	nc := connectOrSkip(t)

	subject := "finding.created"
	received := make(chan []byte, 1)

	sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		received <- msg.Data
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	event := map[string]interface{}{
		"finding_id": "finding-test-001",
		"scan_id":    "scan-test-001",
		"severity":   "critical",
		"title":      "CVE-2024-4577 PHP CGI",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(event)

	if err := nc.Publish(subject, data); err != nil {
		t.Fatalf("publish finding.created: %v", err)
	}

	select {
	case msg := <-received:
		var e map[string]interface{}
		json.Unmarshal(msg, &e)
		if e["severity"] != "critical" {
			t.Errorf("expected severity=critical, got %v", e["severity"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for finding.created")
	}
}

// TestAlertTriggeredEvent tests the alert.triggered subject.
func TestAlertTriggeredEvent(t *testing.T) {
	nc := connectOrSkip(t)

	subject := "alert.triggered"
	received := make(chan []byte, 1)

	sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		received <- msg.Data
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	event := map[string]interface{}{
		"alert_id":   "alert-001",
		"finding_id": "finding-test-001",
		"severity":   "critical",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(event)
	nc.Publish(subject, data)

	select {
	case msg := <-received:
		var e map[string]interface{}
		json.Unmarshal(msg, &e)
		if e["alert_id"] != "alert-001" {
			t.Errorf("expected alert_id=alert-001, got %v", e["alert_id"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

// TestMultipleSubscribers verifies fan-out to multiple subscribers.
func TestMultipleSubscribers(t *testing.T) {
	nc := connectOrSkip(t)

	subject := fmt.Sprintf("test.fanout.%d", time.Now().UnixNano())
	const N = 3
	channels := make([]chan struct{}, N)
	for i := range channels {
		channels[i] = make(chan struct{}, 1)
		i := i
		sub, _ := nc.Subscribe(subject, func(_ *nats.Msg) {
			channels[i] <- struct{}{}
		})
		defer sub.Unsubscribe()
	}

	nc.Publish(subject, []byte(`{"x":1}`))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	for i, ch := range channels {
		select {
		case <-ch:
		case <-ctx.Done():
			t.Errorf("subscriber %d did not receive message", i)
		}
	}
}

// TestMessageOrdering verifies messages arrive in publish order.
func TestMessageOrdering(t *testing.T) {
	nc := connectOrSkip(t)

	subject := fmt.Sprintf("test.ordering.%d", time.Now().UnixNano())
	const N = 10
	received := make(chan int, N)

	sub, _ := nc.Subscribe(subject, func(msg *nats.Msg) {
		var m map[string]interface{}
		json.Unmarshal(msg.Data, &m)
		if n, ok := m["n"].(float64); ok {
			received <- int(n)
		}
	})
	defer sub.Unsubscribe()

	for i := 0; i < N; i++ {
		data, _ := json.Marshal(map[string]int{"n": i})
		nc.Publish(subject, data)
	}
	nc.Flush()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got := make([]int, 0, N)
	for {
		select {
		case n := <-received:
			got = append(got, n)
			if len(got) == N {
				goto done
			}
		case <-ctx.Done():
			t.Fatalf("only received %d/%d messages", len(got), N)
		}
	}

done:
	for i, n := range got {
		if n != i {
			t.Errorf("position %d: expected %d, got %d", i, i, n)
		}
	}
}

// TestPublishEmptyPayload verifies broker handles empty payloads.
func TestPublishEmptyPayload(t *testing.T) {
	nc := connectOrSkip(t)
	subject := fmt.Sprintf("test.empty.%d", time.Now().UnixNano())
	received := make(chan struct{}, 1)

	sub, _ := nc.Subscribe(subject, func(_ *nats.Msg) { received <- struct{}{} })
	defer sub.Unsubscribe()

	if err := nc.Publish(subject, nil); err != nil {
		t.Fatalf("publish empty: %v", err)
	}

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout for empty payload")
	}
}

// TestRequestReply verifies NATS request/reply pattern.
func TestRequestReply(t *testing.T) {
	nc := connectOrSkip(t)
	subject := fmt.Sprintf("test.rpc.%d", time.Now().UnixNano())

	// Responder
	sub, _ := nc.Subscribe(subject, func(msg *nats.Msg) {
		reply := map[string]interface{}{"status": "ok", "echo": string(msg.Data)}
		data, _ := json.Marshal(reply)
		nc.Publish(msg.Reply, data)
	})
	defer sub.Unsubscribe()

	msg, err := nc.Request(subject, []byte(`"ping"`), 3*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var resp map[string]interface{}
	json.Unmarshal(msg.Data, &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
}
