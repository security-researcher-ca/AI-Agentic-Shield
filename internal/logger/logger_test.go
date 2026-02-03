package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLogger_Log(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test_audit.jsonl")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	event := AuditEvent{
		Timestamp:      "2026-02-02T12:00:00Z",
		Command:        "echo hello",
		Args:           []string{"echo", "hello"},
		Cwd:            "/tmp",
		Decision:       "ALLOW",
		TriggeredRules: []string{},
		Mode:           "policy-only",
	}

	if err := logger.Log(event); err != nil {
		t.Fatalf("failed to log event: %v", err)
	}

	logger.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	var parsed AuditEvent
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse log line as JSON: %v", err)
	}

	if parsed.Command != "echo hello" {
		t.Errorf("expected command 'echo hello', got '%s'", parsed.Command)
	}

	if parsed.Decision != "ALLOW" {
		t.Errorf("expected decision 'ALLOW', got '%s'", parsed.Decision)
	}
}

func TestAuditLogger_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "secure_audit.jsonl")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	logger.Close()

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("failed to stat log file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got %04o", perm)
	}
}
