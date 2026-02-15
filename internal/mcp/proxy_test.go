package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/gzhole/agentshield/internal/policy"
)

// nopWriteCloser wraps an io.Writer with a no-op Close method.
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func newNopWriteCloser(w io.Writer) io.WriteCloser {
	return nopWriteCloser{w}
}

// testProxyPolicy returns a policy for proxy tests.
func testProxyPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults:     MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{"execute_command", "run_shell"},
		Rules: []MCPRule{
			{
				ID: "block-etc-write",
				Match: MCPMatch{
					ToolName:         "write_file",
					ArgumentPatterns: map[string]string{"path": "/etc/**"},
				},
				Decision: policy.DecisionBlock,
				Reason:   "Write to /etc/ blocked.",
			},
		},
	}
}

func TestProxy_BlockedToolCall(t *testing.T) {
	evaluator := NewPolicyEvaluator(testProxyPolicy())

	// Client sends a tools/call for a blocked tool
	clientInput := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}` + "\n"

	var audited []AuditEntry
	var mu sync.Mutex

	proxy := NewProxy(ProxyConfig{
		Evaluator: evaluator,
		OnAudit: func(e AuditEntry) {
			mu.Lock()
			defer mu.Unlock()
			audited = append(audited, e)
		},
		Stderr: io.Discard,
	})

	clientReader := strings.NewReader(clientInput)
	clientWriter := &bytes.Buffer{}
	serverReader := strings.NewReader("") // server won't respond (blocked before forwarding)
	serverBuf := &bytes.Buffer{}
	serverWriter := newNopWriteCloser(serverBuf)

	proxy.RunWithIO(clientReader, clientWriter, serverReader, serverWriter)

	// Server should NOT have received the message
	if serverBuf.Len() > 0 {
		t.Errorf("expected no data forwarded to server, got: %s", serverBuf.String())
	}

	// Client should have received a JSON-RPC error
	output := strings.TrimSpace(clientWriter.String())
	if output == "" {
		t.Fatal("expected block response sent to client, got nothing")
	}

	var resp Message
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		t.Fatalf("failed to parse client response: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("expected error in response")
	}
	if resp.Error.Code != RPCInvalidRequest {
		t.Errorf("expected error code %d, got %d", RPCInvalidRequest, resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "AgentShield") {
		t.Errorf("expected AgentShield in error message, got: %s", resp.Error.Message)
	}

	// Audit should have been recorded
	mu.Lock()
	defer mu.Unlock()
	if len(audited) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(audited))
	}
	if audited[0].Decision != "BLOCK" {
		t.Errorf("expected BLOCK decision in audit, got %s", audited[0].Decision)
	}
	if audited[0].ToolName != "execute_command" {
		t.Errorf("expected tool name execute_command, got %s", audited[0].ToolName)
	}
}

func TestProxy_AllowedToolCall(t *testing.T) {
	evaluator := NewPolicyEvaluator(testProxyPolicy())

	clientInput := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"NYC"}}}` + "\n"

	// Mock server response
	serverResponse := `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Sunny, 72F"}],"isError":false}}` + "\n"

	var audited []AuditEntry
	var mu sync.Mutex

	proxy := NewProxy(ProxyConfig{
		Evaluator: evaluator,
		OnAudit: func(e AuditEntry) {
			mu.Lock()
			defer mu.Unlock()
			audited = append(audited, e)
		},
		Stderr: io.Discard,
	})

	clientReader := strings.NewReader(clientInput)
	clientWriter := &bytes.Buffer{}
	serverReader := strings.NewReader(serverResponse)
	serverBuf := &bytes.Buffer{}
	serverWriter := newNopWriteCloser(serverBuf)

	proxy.RunWithIO(clientReader, clientWriter, serverReader, serverWriter)

	// Server SHOULD have received the forwarded message
	forwarded := strings.TrimSpace(serverBuf.String())
	if forwarded == "" {
		t.Fatal("expected message forwarded to server")
	}

	// Client should have received the server's response
	clientOutput := strings.TrimSpace(clientWriter.String())
	if !strings.Contains(clientOutput, "Sunny, 72F") {
		t.Errorf("expected server response forwarded to client, got: %s", clientOutput)
	}

	// Audit should record AUDIT decision (default)
	mu.Lock()
	defer mu.Unlock()
	if len(audited) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(audited))
	}
	if audited[0].Decision != "AUDIT" {
		t.Errorf("expected AUDIT decision, got %s", audited[0].Decision)
	}
}

func TestProxy_NonToolCallPassthrough(t *testing.T) {
	evaluator := NewPolicyEvaluator(testProxyPolicy())

	// tools/list request should pass through without evaluation
	clientInput := `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}` + "\n"
	serverResponse := `{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"get_weather","description":"Get weather"}]}}` + "\n"

	proxy := NewProxy(ProxyConfig{
		Evaluator: evaluator,
		Stderr:    io.Discard,
	})

	clientReader := strings.NewReader(clientInput)
	clientWriter := &bytes.Buffer{}
	serverReader := strings.NewReader(serverResponse)
	serverBuf := &bytes.Buffer{}
	serverWriter := newNopWriteCloser(serverBuf)

	proxy.RunWithIO(clientReader, clientWriter, serverReader, serverWriter)

	// Server should have received the tools/list request
	forwarded := strings.TrimSpace(serverBuf.String())
	if !strings.Contains(forwarded, "tools/list") {
		t.Errorf("expected tools/list forwarded to server, got: %s", forwarded)
	}

	// Client should have received the response
	clientOutput := strings.TrimSpace(clientWriter.String())
	if !strings.Contains(clientOutput, "get_weather") {
		t.Errorf("expected tool list forwarded to client, got: %s", clientOutput)
	}
}

func TestProxy_BlockedByRule(t *testing.T) {
	evaluator := NewPolicyEvaluator(testProxyPolicy())

	// write_file to /etc/passwd should be blocked by rule
	clientInput := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"evil"}}}` + "\n"

	proxy := NewProxy(ProxyConfig{
		Evaluator: evaluator,
		Stderr:    io.Discard,
	})

	clientReader := strings.NewReader(clientInput)
	clientWriter := &bytes.Buffer{}
	serverReader := strings.NewReader("")
	serverBuf := &bytes.Buffer{}
	serverWriter := newNopWriteCloser(serverBuf)

	proxy.RunWithIO(clientReader, clientWriter, serverReader, serverWriter)

	// Server should NOT receive the blocked message
	if serverBuf.Len() > 0 {
		t.Errorf("expected no data to server, got: %s", serverBuf.String())
	}

	// Client gets error response
	output := strings.TrimSpace(clientWriter.String())
	var resp Message
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("expected error response")
	}
}

func TestProxy_MultipleMessages(t *testing.T) {
	evaluator := NewPolicyEvaluator(testProxyPolicy())

	// Send 3 messages: one blocked, one audited, one notification (passthrough)
	lines := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"cmd":"ls"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"LA"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	clientInput := strings.Join(lines, "\n") + "\n"

	serverResponse := `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Rainy"}]}}` + "\n"

	var audited []AuditEntry
	var mu sync.Mutex

	proxy := NewProxy(ProxyConfig{
		Evaluator: evaluator,
		OnAudit: func(e AuditEntry) {
			mu.Lock()
			defer mu.Unlock()
			audited = append(audited, e)
		},
		Stderr: io.Discard,
	})

	clientReader := strings.NewReader(clientInput)
	clientWriter := &bytes.Buffer{}
	serverReader := strings.NewReader(serverResponse)
	serverBuf := &bytes.Buffer{}
	serverWriter := newNopWriteCloser(serverBuf)

	proxy.RunWithIO(clientReader, clientWriter, serverReader, serverWriter)

	// Server should have received 2 messages (get_weather + notification), not execute_command
	serverOutput := serverBuf.String()
	if strings.Contains(serverOutput, "execute_command") {
		t.Error("execute_command should NOT have been forwarded to server")
	}
	if !strings.Contains(serverOutput, "get_weather") {
		t.Error("get_weather should have been forwarded to server")
	}
	if !strings.Contains(serverOutput, "notifications/initialized") {
		t.Error("notification should have been forwarded to server")
	}

	// Client should have: block response for execute_command + server response for get_weather
	clientOutput := clientWriter.String()
	if !strings.Contains(clientOutput, "AgentShield") {
		t.Error("expected block response with AgentShield in client output")
	}
	if !strings.Contains(clientOutput, "Rainy") {
		t.Error("expected server response forwarded to client")
	}

	// Should have 2 audit entries (2 tools/call messages)
	mu.Lock()
	defer mu.Unlock()
	if len(audited) != 2 {
		t.Errorf("expected 2 audit entries, got %d", len(audited))
	}
}

func TestProxy_MalformedJSON_FailOpen(t *testing.T) {
	evaluator := NewPolicyEvaluator(testProxyPolicy())

	clientInput := `{not valid json}` + "\n"

	proxy := NewProxy(ProxyConfig{
		Evaluator: evaluator,
		Stderr:    io.Discard,
	})

	clientReader := strings.NewReader(clientInput)
	clientWriter := &bytes.Buffer{}
	serverReader := strings.NewReader("")
	serverBuf := &bytes.Buffer{}
	serverWriter := newNopWriteCloser(serverBuf)

	proxy.RunWithIO(clientReader, clientWriter, serverReader, serverWriter)

	// Malformed JSON should be forwarded to server (fail open)
	if serverBuf.Len() == 0 {
		t.Error("expected malformed JSON to be forwarded to server (fail open)")
	}
}

func TestArgumentsToJSON(t *testing.T) {
	got := ArgumentsToJSON(map[string]interface{}{"key": "val"})
	if got != `{"key":"val"}` {
		t.Errorf("expected JSON, got %s", got)
	}

	got = ArgumentsToJSON(nil)
	if got != "{}" {
		t.Errorf("expected {}, got %s", got)
	}
}
