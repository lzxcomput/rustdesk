package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConsumerCheckpointsAndDeduplicates(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "sessions-20260717-controller-42.jsonl")
	event := testEvent("event-1")
	record := signedRecord(t, event, zeroHash)
	line, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(line, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}

	var received []Record
	handler := HandlerFunc(func(_ context.Context, record Record) error {
		received = append(received, record)
		return nil
	})
	checkpoint := filepath.Join(directory, "checkpoint.json")
	consumer, err := NewConsumer(directory, checkpoint, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.Scan(); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Scan(); err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 {
		t.Fatalf("received %d events, want 1", len(received))
	}

	restarted, err := NewConsumer(directory, checkpoint, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Scan(); err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 {
		t.Fatalf("received %d events after restart, want 1", len(received))
	}
}

func TestConsumerWaitsForCompleteLine(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "sessions-20260717-controlled-7.jsonl")
	record := signedRecord(t, testEvent("event-2"), zeroHash)
	line, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, line, 0o640); err != nil {
		t.Fatal(err)
	}

	count := 0
	consumer, err := NewConsumer(directory, filepath.Join(directory, "checkpoint.json"), HandlerFunc(
		func(_ context.Context, _ Record) error {
			count++
			return nil
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.Scan(); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("received %d partial events, want 0", count)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{'\n'}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Scan(); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("received %d complete events, want 1", count)
	}
}

func testEvent(id string) Event {
	return Event{
		SchemaVersion:  1,
		EventID:        id,
		EventType:      "session_started",
		SessionID:      "019f7090-6928-7821-84e3-73809ce9f507",
		Role:           "controller",
		SessionType:    "remote_desktop",
		ConnectionMode: "direct",
		Local: Endpoint{
			IP:             "10.0.0.1",
			Hostname:       "controller",
			Username:       "alice",
			IdentityStatus: "complete",
		},
		Peer: Endpoint{
			IP:             "10.0.0.2",
			Hostname:       "controlled",
			Username:       "bob",
			IdentityStatus: "complete",
		},
		StartedAt:      "2026-07-17T10:23:41.582Z",
		ReconnectCount: 0,
	}
}

func signedRecord(t *testing.T, event Event, previous string) Record {
	t.Helper()
	payload, err := canonicalEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(previous))
	_, _ = hash.Write(payload)
	return Record{
		Event:      event,
		PrevHash:   previous,
		RecordHash: hex.EncodeToString(hash.Sum(nil)),
	}
}
