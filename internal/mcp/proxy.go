package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// AuditEntry records an MCP tool call decision for the audit log.
type AuditEntry struct {
	Timestamp      string                 `json:"timestamp"`
	ToolName       string                 `json:"tool_name"`
	Arguments      map[string]interface{} `json:"arguments,omitempty"`
	Decision       string                 `json:"decision"`
	Flagged        bool                   `json:"flagged,omitempty"`
	TriggeredRules []string               `json:"triggered_rules,omitempty"`
	Reasons        []string               `json:"reasons,omitempty"`
	Source         string                 `json:"source"`
}

// AuditFunc is a callback for logging audit entries.
// The proxy calls this for every tools/call it intercepts.
type AuditFunc func(entry AuditEntry)

// ProxyConfig holds configuration for the MCP stdio proxy.
type ProxyConfig struct {
	// ServerCmd is the command to launch the real MCP server (e.g., "npx", "-y", "@modelcontextprotocol/server-filesystem").
	ServerCmd []string

	// Evaluator is the MCP policy evaluator.
	Evaluator *PolicyEvaluator

	// OnAudit is called for every intercepted tools/call decision.
	OnAudit AuditFunc

	// Stderr is where proxy diagnostic messages go. Defaults to os.Stderr.
	Stderr io.Writer
}

// Proxy is a transparent MCP stdio proxy that intercepts tools/call requests.
type Proxy struct {
	cfg       ProxyConfig
	serverCmd *exec.Cmd
	stderr    io.Writer
}

// NewProxy creates a new MCP stdio proxy with the given configuration.
func NewProxy(cfg ProxyConfig) *Proxy {
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	return &Proxy{cfg: cfg, stderr: stderr}
}

// Run starts the proxy: spawns the child MCP server, bridges stdin/stdout,
// and intercepts tools/call requests for policy evaluation.
// Blocks until both the client (stdin) and server process finish.
func (p *Proxy) Run() error {
	if len(p.cfg.ServerCmd) == 0 {
		return fmt.Errorf("no server command specified")
	}

	// Spawn the real MCP server as a child process.
	p.serverCmd = exec.Command(p.cfg.ServerCmd[0], p.cfg.ServerCmd[1:]...)
	p.serverCmd.Stderr = p.stderr

	serverStdin, err := p.serverCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create server stdin pipe: %w", err)
	}
	serverStdout, err := p.serverCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create server stdout pipe: %w", err)
	}

	if err := p.serverCmd.Start(); err != nil {
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	var wg sync.WaitGroup

	// Client → Proxy → Server (intercept tools/call)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = serverStdin.Close() }()
		p.proxyClientToServer(os.Stdin, serverStdin, os.Stdout)
	}()

	// Server → Proxy → Client (pass through)
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.proxyServerToClient(serverStdout, os.Stdout)
	}()

	wg.Wait()

	// Wait for the server process to exit.
	if err := p.serverCmd.Wait(); err != nil {
		return fmt.Errorf("MCP server exited with error: %w", err)
	}

	return nil
}

// proxyClientToServer reads JSON-RPC messages from the client (IDE),
// evaluates tools/call requests, and either forwards or blocks them.
func (p *Proxy) proxyClientToServer(clientReader io.Reader, serverWriter io.Writer, clientWriter io.Writer) {
	scanner := bufio.NewScanner(clientReader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // up to 10MB per message

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		msg, kind, err := ParseMessage(line)
		if err != nil {
			// Can't parse — forward as-is (fail open)
			_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] warning: failed to parse message, forwarding: %v\n", err)
			writeLineToWriter(serverWriter, line)
			continue
		}

		if kind == KindToolCall {
			blocked, blockResp := p.evaluateToolCall(msg)
			if blocked {
				// Send JSON-RPC error back to client; don't forward to server
				writeLineToWriter(clientWriter, blockResp)
				continue
			}
		}

		if kind == KindResourceRead {
			blocked, blockResp := p.evaluateResourceRead(msg)
			if blocked {
				writeLineToWriter(clientWriter, blockResp)
				continue
			}
		}

		// Forward all non-blocked messages to the server
		writeLineToWriter(serverWriter, line)
	}
}

// proxyServerToClient reads messages from the MCP server, scans tools/list
// responses for poisoned tool descriptions, and forwards to the client.
func (p *Proxy) proxyServerToClient(serverReader io.Reader, clientWriter io.Writer) {
	scanner := bufio.NewScanner(serverReader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		// Try to detect tools/list responses and scan for poisoned descriptions
		if filtered := p.filterToolsListResponse(line); filtered != nil {
			writeLineToWriter(clientWriter, filtered)
			continue
		}

		writeLineToWriter(clientWriter, line)
	}
}

// filterToolsListResponse checks if a message is a tools/list response.
// If it is, scans each tool description for poisoning and removes poisoned tools.
// Returns the modified JSON bytes, or nil if the message is not a tools/list response.
func (p *Proxy) filterToolsListResponse(line []byte) []byte {
	var msg Message
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil
	}

	// Only process responses (has result, no method)
	if msg.Method != "" || msg.Result == nil {
		return nil
	}

	// Try to parse as ListToolsResult
	var listResult ListToolsResult
	if err := json.Unmarshal(msg.Result, &listResult); err != nil {
		return nil
	}

	// Must have a tools array to be a tools/list response
	if listResult.Tools == nil {
		return nil
	}

	// Scan each tool and filter out poisoned ones
	var clean []ToolDefinition
	removed := 0
	for _, tool := range listResult.Tools {
		scanResult := ScanToolDescription(tool)
		if scanResult.Poisoned {
			removed++
			_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] POISONED tool hidden: %s (%d signals)\n",
				tool.Name, len(scanResult.Findings))
			for _, f := range scanResult.Findings {
				_, _ = fmt.Fprintf(p.stderr, "  - [%s] %s\n", f.Signal, f.Detail)
			}

			// Audit the poisoned tool
			if p.cfg.OnAudit != nil {
				reasons := make([]string, 0, len(scanResult.Findings))
				for _, f := range scanResult.Findings {
					reasons = append(reasons, string(f.Signal)+": "+f.Detail)
				}
				p.cfg.OnAudit(AuditEntry{
					Timestamp:      time.Now().UTC().Format(time.RFC3339),
					ToolName:       tool.Name,
					Decision:       "BLOCK",
					Flagged:        true,
					TriggeredRules: []string{"tool-description-poisoning"},
					Reasons:        reasons,
					Source:         "mcp-proxy-description-scan",
				})
			}
			continue
		}
		clean = append(clean, tool)
	}

	if removed == 0 {
		return nil // no changes needed, use original bytes
	}

	_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] tools/list: %d/%d tools passed, %d hidden\n",
		len(clean), len(listResult.Tools), removed)

	// Rebuild the response with filtered tools
	listResult.Tools = clean
	newResult, err := json.Marshal(listResult)
	if err != nil {
		return nil
	}

	msg.Result = newResult
	out, err := json.Marshal(msg)
	if err != nil {
		return nil
	}
	return out
}

// evaluateResourceRead evaluates a resources/read message against the MCP policy.
// Returns (true, blockResponse) if blocked, or (false, nil) if allowed.
func (p *Proxy) evaluateResourceRead(msg *Message) (bool, []byte) {
	params, err := ExtractResourceRead(msg)
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] warning: failed to extract resource read: %v\n", err)
		return false, nil // fail open
	}

	result := p.cfg.Evaluator.EvaluateResourceRead(params.URI)

	// Log the audit entry
	if p.cfg.OnAudit != nil {
		p.cfg.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "resources/read",
			Arguments:      map[string]interface{}{"uri": params.URI},
			Decision:       string(result.Decision),
			Flagged:        result.Decision == "BLOCK" || result.Decision == "AUDIT",
			TriggeredRules: result.TriggeredRules,
			Reasons:        result.Reasons,
			Source:         "mcp-proxy",
		})
	}

	if result.Decision == "BLOCK" {
		reason := "Blocked by policy"
		if len(result.Reasons) > 0 {
			reason = result.Reasons[0]
		}
		_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] BLOCKED resource read: %s — %s\n", params.URI, reason)

		blockResp, err := NewBlockResponse(msg.ID, reason)
		if err != nil {
			_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] error creating block response: %v\n", err)
			return false, nil
		}
		return true, blockResp
	}

	if result.Decision == "AUDIT" {
		_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] AUDIT resource read: %s\n", params.URI)
	}

	return false, nil
}

// evaluateToolCall evaluates a tools/call message against the MCP policy
// and scans argument content for sensitive data exfiltration.
// Returns (true, blockResponse) if blocked, or (false, nil) if allowed.
func (p *Proxy) evaluateToolCall(msg *Message) (bool, []byte) {
	params, err := ExtractToolCall(msg)
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] warning: failed to extract tool call: %v\n", err)
		return false, nil // fail open
	}

	result := p.cfg.Evaluator.EvaluateToolCall(params.Name, params.Arguments)

	// If policy didn't block, scan argument content for secrets/exfiltration
	if result.Decision != "BLOCK" {
		contentResult := ScanToolCallContent(params.Name, params.Arguments)
		if contentResult.Blocked {
			result.Decision = "BLOCK"
			result.TriggeredRules = append(result.TriggeredRules, "argument-content-scan")
			for _, f := range contentResult.Findings {
				result.Reasons = append(result.Reasons, string(f.Signal)+": "+f.Detail+" (arg: "+f.ArgName+")")
			}
			_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] BLOCKED by content scan: %s (%d signals)\n",
				params.Name, len(contentResult.Findings))
			for _, f := range contentResult.Findings {
				_, _ = fmt.Fprintf(p.stderr, "  - [%s] %s (arg: %s)\n", f.Signal, f.Detail, f.ArgName)
			}
		}
	}

	// If still not blocked, check for config file write attempts
	if result.Decision != "BLOCK" {
		guardResult := CheckConfigGuard(params.Name, params.Arguments)
		if guardResult.Blocked {
			result.Decision = "BLOCK"
			result.TriggeredRules = append(result.TriggeredRules, "config-file-guard")
			for _, f := range guardResult.Findings {
				result.Reasons = append(result.Reasons, "["+f.Category+"] "+f.Reason+" (path: "+f.Path+")")
			}
			_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] BLOCKED by config guard: %s (%d findings)\n",
				params.Name, len(guardResult.Findings))
			for _, f := range guardResult.Findings {
				_, _ = fmt.Fprintf(p.stderr, "  - [%s] %s (path: %s)\n", f.Category, f.Reason, f.Path)
			}
		}
	}

	// Log the audit entry
	if p.cfg.OnAudit != nil {
		p.cfg.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       params.Name,
			Arguments:      params.Arguments,
			Decision:       string(result.Decision),
			Flagged:        result.Decision == "BLOCK" || result.Decision == "AUDIT",
			TriggeredRules: result.TriggeredRules,
			Reasons:        result.Reasons,
			Source:         "mcp-proxy",
		})
	}

	if result.Decision == "BLOCK" {
		reason := "Blocked by policy"
		if len(result.Reasons) > 0 {
			reason = result.Reasons[0]
		}
		_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] BLOCKED tool call: %s — %s\n", params.Name, reason)

		blockResp, err := NewBlockResponse(msg.ID, reason)
		if err != nil {
			_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] error creating block response: %v\n", err)
			return false, nil
		}
		return true, blockResp
	}

	if result.Decision == "AUDIT" {
		_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] AUDIT tool call: %s\n", params.Name)
	}

	return false, nil
}

// writeLineToWriter writes a line followed by a newline to the writer.
func writeLineToWriter(w io.Writer, data []byte) {
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n"))
}

// RunWithIO is like Run but accepts explicit reader/writer for testability.
// It does NOT spawn a child process — the caller provides the server I/O.
// serverWriter should be an io.WriteCloser so the proxy can signal the server
// that the client is done (by closing its stdin).
func (p *Proxy) RunWithIO(clientReader io.Reader, clientWriter io.Writer, serverReader io.Reader, serverWriter io.WriteCloser) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = serverWriter.Close() }() // signal server that client is done
		p.proxyClientToServer(clientReader, serverWriter, clientWriter)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		p.proxyServerToClient(serverReader, clientWriter)
	}()

	wg.Wait()
}

// ArgumentsToJSON serializes tool arguments to a JSON string for logging.
func ArgumentsToJSON(args map[string]interface{}) string {
	if args == nil {
		return "{}"
	}
	data, err := json.Marshal(args)
	if err != nil {
		return "{}"
	}
	return string(data)
}
