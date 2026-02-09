package logger

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/gzhole/agentshield/internal/redact"
)

type AuditEvent struct {
	Timestamp      string   `json:"timestamp"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	Cwd            string   `json:"cwd"`
	Decision       string   `json:"decision"`
	Flagged        bool     `json:"flagged,omitempty"`
	TriggeredRules []string `json:"triggered_rules,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
	Mode           string   `json:"mode"`
	Source         string   `json:"source,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type AuditLogger struct {
	file *os.File
	mu   sync.Mutex
}

func New(path string) (*AuditLogger, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	return &AuditLogger{file: file}, nil
}

func (l *AuditLogger) Log(event AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Redact sensitive data before logging
	event.Command = redact.Redact(event.Command)
	event.Args = redact.RedactArgs(event.Args)
	if event.Error != "" {
		event.Error = redact.Redact(event.Error)
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	data = append(data, '\n')
	_, err = l.file.Write(data)
	return err
}

func (l *AuditLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
