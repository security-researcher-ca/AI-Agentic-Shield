package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gzhole/agentshield/internal/config"
	"github.com/gzhole/agentshield/internal/mcp"
	"github.com/spf13/cobra"
)

var setupMCPCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Set up AgentShield MCP proxy for IDE MCP servers",
	Long: `Rewrites IDE MCP server configurations to route through AgentShield's
MCP proxy, so every MCP tool call is evaluated against policy before reaching
the server.

Supported config files:
  Cursor:        .cursor/mcp.json
  Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json

  agentshield setup mcp             # wrap all stdio MCP servers
  agentshield setup mcp --disable   # restore original configs`,
	RunE: setupMCPCommand,
}

var mcpDisableFlag bool

func init() {
	setupMCPCmd.Flags().BoolVar(&mcpDisableFlag, "disable", false, "Restore original MCP configs and remove proxy wrapping")
	setupCmd.AddCommand(setupMCPCmd)
}

// mcpConfigLocation describes a known IDE MCP config file.
type mcpConfigLocation struct {
	Name string
	Path string
}

func setupMCPCommand(cmd *cobra.Command, args []string) error {
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + MCP (Tool Call Mediation)")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	// Check if agentshield is in PATH
	binPath, err := exec.LookPath("agentshield")
	if err != nil {
		fmt.Println("⚠  agentshield not found in PATH. Install it first:")
		fmt.Println("   brew tap gzhole/tap && brew install agentshield")
		return nil
	}
	fmt.Printf("✅ agentshield found: %s\n", binPath)

	// Ensure default MCP policy exists
	if err := ensureDefaultMCPPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠  Could not create default MCP policy: %v\n", err)
	}

	// Find all MCP config files
	locations := findMCPConfigLocations()

	if len(locations) == 0 {
		fmt.Println()
		fmt.Println("ℹ  No MCP config files found.")
		fmt.Println("   Supported locations:")
		fmt.Println("     .cursor/mcp.json")
		fmt.Println("     ~/Library/Application Support/Claude/claude_desktop_config.json")
		fmt.Println()
		fmt.Println("   You can also use the proxy directly:")
		fmt.Println("   agentshield mcp-proxy -- <server-command> [args...]")
		return nil
	}

	for _, loc := range locations {
		fmt.Println()
		fmt.Printf("─── %s ───\n", loc.Name)
		fmt.Printf("  Config: %s\n", loc.Path)

		if mcpDisableFlag {
			if err := restoreMCPConfig(loc); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠  %v\n", err)
			}
		} else {
			if err := wrapMCPConfig(loc); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠  %v\n", err)
			}
		}
	}

	fmt.Println()
	if mcpDisableFlag {
		fmt.Println("Restart your IDE to apply changes.")
	} else {
		fmt.Println("How it works:")
		fmt.Println("  1. IDE sends MCP tool calls (tools/call) to the server")
		fmt.Println("  2. AgentShield proxy intercepts and evaluates each call")
		fmt.Println("  3. If BLOCK: tool call is rejected with a JSON-RPC error")
		fmt.Println("  4. If ALLOW/AUDIT: tool call is forwarded to the real server")
		fmt.Println("  5. All decisions are logged to ~/.agentshield/audit.jsonl")
		fmt.Println()
		fmt.Println("MCP policy: ~/.agentshield/mcp-policy.yaml")
		fmt.Println()
		fmt.Println("Restart your IDE to activate the proxy.")
		fmt.Println("To disable: agentshield setup mcp --disable")
	}
	fmt.Println()

	return nil
}

// findMCPConfigLocations returns paths to known IDE MCP config files that exist.
func findMCPConfigLocations() []mcpConfigLocation {
	home := os.Getenv("HOME")
	var found []mcpConfigLocation

	candidates := []mcpConfigLocation{
		{Name: "Cursor", Path: filepath.Join(home, ".cursor", "mcp.json")},
		{Name: "Claude Desktop", Path: filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")},
	}

	// Also check current directory for project-level .cursor/mcp.json
	if cwd, err := os.Getwd(); err == nil {
		projectCursor := filepath.Join(cwd, ".cursor", "mcp.json")
		if projectCursor != candidates[0].Path {
			candidates = append(candidates, mcpConfigLocation{
				Name: "Cursor (project)", Path: projectCursor,
			})
		}
	}

	for _, c := range candidates {
		if _, err := os.Stat(c.Path); err == nil {
			found = append(found, c)
		}
	}

	return found
}

// wrapMCPConfig reads an MCP config, wraps stdio server commands with agentshield mcp-proxy,
// and writes back the modified config. Creates a .agentshield-backup before modifying.
func wrapMCPConfig(loc mcpConfigLocation) error {
	data, err := os.ReadFile(loc.Path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", loc.Path, err)
	}

	// Check if already wrapped
	if strings.Contains(string(data), "agentshield") {
		fmt.Printf("  ✅ Already wrapped with AgentShield proxy\n")
		return nil
	}

	// Parse the config
	var configMap map[string]interface{}
	if err := json.Unmarshal(data, &configMap); err != nil {
		return fmt.Errorf("failed to parse %s: %w", loc.Path, err)
	}

	// Find the mcpServers object (Cursor uses "mcpServers", Claude uses "mcpServers")
	serversRaw, ok := configMap["mcpServers"]
	if !ok {
		fmt.Printf("  ℹ  No mcpServers found in config — nothing to wrap\n")
		return nil
	}

	servers, ok := serversRaw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("mcpServers is not an object")
	}

	// Create backup
	backupPath := loc.Path + ".agentshield-backup"
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	fmt.Printf("  📋 Backup: %s\n", backupPath)

	// Wrap each stdio server
	wrapped := 0
	skipped := 0
	for name, serverRaw := range servers {
		serverMap, ok := serverRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Wrap URL-based (Streamable HTTP transport) servers
		if urlRaw, hasURL := serverMap["url"]; hasURL {
			urlStr, ok := urlRaw.(string)
			if !ok || urlStr == "" {
				continue
			}
			// Already wrapped?
			if strings.Contains(urlStr, "agentshield") || strings.Contains(urlStr, "127.0.0.1:91") {
				fmt.Printf("  ✅ %s: HTTP already wrapped\n", name)
				wrapped++
				continue
			}
			// Assign a deterministic port per server: 9100 + index
			port := 9100 + wrapped + skipped
			localURL := fmt.Sprintf("http://127.0.0.1:%d", port)
			// Store original URL and port for unwrapping and proxy startup
			serverMap["url"] = localURL
			if serverMap["_agentshield"] == nil {
				serverMap["_agentshield"] = map[string]interface{}{}
			}
			meta, _ := serverMap["_agentshield"].(map[string]interface{})
			meta["original_url"] = urlStr
			meta["proxy_port"] = port
			serverMap["_agentshield"] = meta
			servers[name] = serverMap
			fmt.Printf("  ✅ %s: HTTP wrapped (%s → %s, proxy port %d)\n", name, urlStr, localURL, port)
			fmt.Printf("     Start proxy: agentshield mcp-http-proxy --upstream %s --port %d\n", urlStr, port)
			wrapped++
			continue
		}

		command, hasCmd := serverMap["command"].(string)
		if !hasCmd || command == "" {
			continue
		}

		// Build new command: agentshield mcp-proxy -- <original-command> <original-args...>
		newArgs := []string{"mcp-proxy", "--"}
		newArgs = append(newArgs, command)
		if existingArgs, ok := serverMap["args"].([]interface{}); ok {
			for _, a := range existingArgs {
				if s, ok := a.(string); ok {
					newArgs = append(newArgs, s)
				}
			}
		}

		serverMap["command"] = "agentshield"
		serverMap["args"] = newArgs
		servers[name] = serverMap
		fmt.Printf("  ✅ %s: wrapped (%s → agentshield mcp-proxy -- %s)\n", name, command, command)
		wrapped++
	}

	if wrapped == 0 {
		fmt.Printf("  ℹ  No stdio servers found to wrap\n")
		// Remove backup since we didn't modify
		_ = os.Remove(backupPath)
		return nil
	}

	// Write back
	configMap["mcpServers"] = servers
	out, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	out = append(out, '\n')

	if err := os.WriteFile(loc.Path, out, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", loc.Path, err)
	}

	fmt.Printf("  📝 Updated: %d server(s) wrapped", wrapped)
	if skipped > 0 {
		fmt.Printf(", %d skipped (HTTP)", skipped)
	}
	fmt.Println()

	return nil
}

// restoreMCPConfig restores the original MCP config from the .agentshield-backup file.
func restoreMCPConfig(loc mcpConfigLocation) error {
	backupPath := loc.Path + ".agentshield-backup"

	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		// No backup — try to unwrap in-place
		return unwrapMCPConfig(loc)
	}

	// Restore from backup
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	if err := os.WriteFile(loc.Path, data, 0644); err != nil {
		return fmt.Errorf("failed to restore config: %w", err)
	}

	_ = os.Remove(backupPath)
	fmt.Printf("  ✅ Restored from backup\n")
	return nil
}

// unwrapMCPConfig removes agentshield mcp-proxy wrapping from server commands in-place.
func unwrapMCPConfig(loc mcpConfigLocation) error {
	data, err := os.ReadFile(loc.Path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", loc.Path, err)
	}

	if !strings.Contains(string(data), "agentshield") {
		fmt.Printf("  ℹ  No AgentShield wrapping found — nothing to restore\n")
		return nil
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(data, &configMap); err != nil {
		return fmt.Errorf("failed to parse %s: %w", loc.Path, err)
	}

	serversRaw, ok := configMap["mcpServers"]
	if !ok {
		return nil
	}

	servers, ok := serversRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	unwrapped := 0
	for name, serverRaw := range servers {
		serverMap, ok := serverRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Unwrap HTTP servers: restore original URL from _agentshield metadata
		if meta, hasMeta := serverMap["_agentshield"].(map[string]interface{}); hasMeta {
			if origURL, ok := meta["original_url"].(string); ok && origURL != "" {
				serverMap["url"] = origURL
				delete(serverMap, "_agentshield")
				servers[name] = serverMap
				fmt.Printf("  ✅ %s: HTTP unwrapped (restored %s)\n", name, origURL)
				unwrapped++
				continue
			}
		}

		// Unwrap stdio servers
		command, _ := serverMap["command"].(string)
		if command != "agentshield" {
			continue
		}

		argsRaw, ok := serverMap["args"].([]interface{})
		if !ok || len(argsRaw) < 3 {
			continue
		}

		// Expected: ["mcp-proxy", "--", "original-command", "original-args..."]
		if fmt.Sprintf("%v", argsRaw[0]) != "mcp-proxy" || fmt.Sprintf("%v", argsRaw[1]) != "--" {
			continue
		}

		// Restore original command and args
		serverMap["command"] = fmt.Sprintf("%v", argsRaw[2])
		if len(argsRaw) > 3 {
			serverMap["args"] = argsRaw[3:]
		} else {
			delete(serverMap, "args")
		}

		servers[name] = serverMap
		fmt.Printf("  ✅ %s: unwrapped\n", name)
		unwrapped++
	}

	if unwrapped == 0 {
		fmt.Printf("  ℹ  No wrapped servers found\n")
		return nil
	}

	configMap["mcpServers"] = servers
	out, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	out = append(out, '\n')

	if err := os.WriteFile(loc.Path, out, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", loc.Path, err)
	}

	return nil
}

// ensureDefaultMCPPolicy creates ~/.agentshield/mcp-policy.yaml if it doesn't exist.
func ensureDefaultMCPPolicy() error {
	cfg, err := config.Load("", "", "")
	if err != nil {
		return err
	}

	policyPath := filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPolicyFile)
	if _, err := os.Stat(policyPath); err == nil {
		return nil // already exists
	}

	defaultPolicy := `# AgentShield MCP Policy
# Controls which MCP tool calls are allowed, audited, or blocked.
# Docs: https://github.com/gzhole/LLM-Agentic-Shield

defaults:
  decision: "AUDIT"        # ALLOW, AUDIT, or BLOCK

# Tools that are always blocked (exact name or glob)
blocked_tools:
  - "execute_command"
  - "run_shell"
  - "run_terminal_command"
  - "shell_exec"

# Fine-grained rules
rules:
  - id: block-write-sensitive-paths
    match:
      tool_name_any:
        - "write_file"
        - "create_file"
        - "edit_file"
      argument_patterns:
        path: "/etc/**"
    decision: "BLOCK"
    reason: "File write to system directories is blocked."

  - id: block-ssh-access
    match:
      tool_name_any:
        - "read_file"
        - "write_file"
        - "cat_file"
        - "create_file"
      argument_patterns:
        path: "**/.ssh/**"
    decision: "BLOCK"
    reason: "Access to SSH key directories is blocked."

  - id: block-credential-access
    match:
      tool_name_any:
        - "read_file"
        - "write_file"
        - "cat_file"
        - "create_file"
      argument_patterns:
        path: "**/.aws/**"
    decision: "BLOCK"
    reason: "Access to cloud credential directories is blocked."
`

	if err := os.WriteFile(policyPath, []byte(defaultPolicy), 0644); err != nil {
		return err
	}

	fmt.Printf("✅ Default MCP policy created: %s\n", policyPath)
	return nil
}
