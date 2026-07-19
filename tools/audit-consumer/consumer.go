package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

const (
	zeroHash      = "0000000000000000000000000000000000000000000000000000000000000000"
	maxRecordSize = 1024 * 1024
)

var auditFilename = regexp.MustCompile(`^sessions-\d{8}-(controller|controlled)-\d+\.jsonl$`)

type Endpoint struct {
	IP             string `json:"ip"`
	Hostname       string `json:"hostname"`
	Username       string `json:"username"`
	IdentityStatus string `json:"identity_status"`
}

type Event struct {
	SchemaVersion  uint32   `json:"schema_version"`
	EventID        string   `json:"event_id"`
	EventType      string   `json:"event_type"`
	SessionID      string   `json:"session_id"`
	Role           string   `json:"role"`
	SessionType    string   `json:"session_type"`
	ConnectionMode string   `json:"connection_mode"`
	Local          Endpoint `json:"local"`
	Peer           Endpoint `json:"peer"`
	StartedAt      string   `json:"started_at"`
	EndedAt        *string  `json:"ended_at,omitempty"`
	DurationMS     *uint64  `json:"duration_ms,omitempty"`
	EndReason      *string  `json:"end_reason,omitempty"`
	EndInitiator   *string  `json:"end_initiator,omitempty"`
	ReconnectCount uint32   `json:"reconnect_count"`
}

type Record struct {
	Event
	PrevHash   string `json:"prev_hash"`
	RecordHash string `json:"record_hash"`
}

type Handler interface {
	Handle(context.Context, Record) error
}

type HandlerFunc func(context.Context, Record) error

func (f HandlerFunc) Handle(ctx context.Context, record Record) error {
	return f(ctx, record)
}

type JSONLineHandler struct {
	Writer io.Writer
	mu     sync.Mutex
}

func (h *JSONLineHandler) Handle(_ context.Context, record Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	encoder := json.NewEncoder(h.Writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(record)
}

type fileCheckpoint struct {
	Offset   int64  `json:"offset"`
	LastHash string `json:"last_hash"`
}

type checkpointState struct {
	Files map[string]fileCheckpoint `json:"files"`
	Seen  map[string]bool           `json:"seen_event_ids"`
}

type Consumer struct {
	directory      string
	checkpointPath string
	handler        Handler
	state          checkpointState
}

func NewConsumer(directory, checkpointPath string, handler Handler) (*Consumer, error) {
	if handler == nil {
		return nil, errors.New("handler is required")
	}
	consumer := &Consumer{
		directory:      directory,
		checkpointPath: checkpointPath,
		handler:        handler,
		state: checkpointState{
			Files: make(map[string]fileCheckpoint),
			Seen:  make(map[string]bool),
		},
	}
	if err := consumer.loadCheckpoint(); err != nil {
		return nil, err
	}
	return consumer, nil
}

func (c *Consumer) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("scan interval must be positive")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := c.scan(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (c *Consumer) Scan() error {
	return c.scan(context.Background())
}

func (c *Consumer) scan(ctx context.Context) error {
	paths, err := filepath.Glob(filepath.Join(c.directory, "sessions-*.jsonl"))
	if err != nil {
		return fmt.Errorf("glob audit files: %w", err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if !auditFilename.MatchString(filepath.Base(path)) {
			continue
		}
		if err := c.consumeFile(ctx, path); err != nil {
			return fmt.Errorf("consume %s: %w", path, err)
		}
	}
	return nil
}

func (c *Consumer) consumeFile(ctx context.Context, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	cp := c.state.Files[path]
	if cp.LastHash == "" {
		cp.LastHash = zeroHash
	}
	if info.Size() < cp.Offset {
		return fmt.Errorf("file was truncated from offset %d to size %d", cp.Offset, info.Size())
	}
	if _, err := file.Seek(cp.Offset, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			// RustDesk writes and syncs one complete newline-terminated record. Keep an
			// incomplete tail for the next scan instead of advancing the checkpoint.
			return nil
		}
		if err != nil {
			return err
		}
		if len(line) > maxRecordSize {
			return fmt.Errorf("record exceeds %d bytes", maxRecordSize)
		}
		line = bytes.TrimSuffix(line, []byte{'\n'})
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			cp.Offset++
			continue
		}
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			return fmt.Errorf("decode JSON at offset %d: %w", cp.Offset, err)
		}
		if err := validateRecord(record, cp.LastHash); err != nil {
			return fmt.Errorf("validate record at offset %d: %w", cp.Offset, err)
		}
		if !c.state.Seen[record.EventID] {
			if err := c.handler.Handle(ctx, record); err != nil {
				return fmt.Errorf("handle event %s: %w", record.EventID, err)
			}
			c.state.Seen[record.EventID] = true
		}
		cp.Offset += int64(len(line) + 1)
		cp.LastHash = record.RecordHash
		c.state.Files[path] = cp
		if err := c.saveCheckpoint(); err != nil {
			return err
		}
	}
}

func validateRecord(record Record, expectedPrevHash string) error {
	if record.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema_version %d", record.SchemaVersion)
	}
	if record.EventID == "" || record.SessionID == "" {
		return errors.New("event_id and session_id are required")
	}
	if record.PrevHash != expectedPrevHash {
		return fmt.Errorf("hash chain mismatch: got prev_hash %s, want %s", record.PrevHash, expectedPrevHash)
	}
	payload, err := canonicalEvent(record.Event)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(record.PrevHash))
	_, _ = hash.Write(payload)
	want := hex.EncodeToString(hash.Sum(nil))
	if record.RecordHash != want {
		return fmt.Errorf("record hash mismatch: got %s, want %s", record.RecordHash, want)
	}
	if _, err := time.Parse(time.RFC3339Nano, record.StartedAt); err != nil {
		return fmt.Errorf("invalid started_at: %w", err)
	}
	if record.EndedAt != nil {
		if _, err := time.Parse(time.RFC3339Nano, *record.EndedAt); err != nil {
			return fmt.Errorf("invalid ended_at: %w", err)
		}
	}
	return nil
}

func canonicalEvent(event Event) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(event); err != nil {
		return nil, fmt.Errorf("encode canonical event: %w", err)
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func (c *Consumer) loadCheckpoint() error {
	data, err := os.ReadFile(c.checkpointPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read checkpoint: %w", err)
	}
	if err := json.Unmarshal(data, &c.state); err != nil {
		return fmt.Errorf("decode checkpoint: %w", err)
	}
	if c.state.Files == nil {
		c.state.Files = make(map[string]fileCheckpoint)
	}
	if c.state.Seen == nil {
		c.state.Seen = make(map[string]bool)
	}
	return nil
}

func (c *Consumer) saveCheckpoint() error {
	if err := os.MkdirAll(filepath.Dir(c.checkpointPath), 0o750); err != nil {
		return fmt.Errorf("create checkpoint directory: %w", err)
	}
	data, err := json.Marshal(c.state)
	if err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	temporary := c.checkpointPath + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open temporary checkpoint: %w", err)
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close checkpoint: %w", closeErr)
	}
	if err := os.Remove(c.checkpointPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("replace checkpoint: %w", err)
	}
	if err := os.Rename(temporary, c.checkpointPath); err != nil {
		return fmt.Errorf("commit checkpoint: %w", err)
	}
	return nil
}
