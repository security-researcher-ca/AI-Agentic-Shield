# MCP Communication Mediation

AgentShield can intercept and evaluate [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) tool calls between AI agents and MCP servers, applying the same defense-in-depth philosophy used for shell commands.

## Architecture

```
┌──────────┐    JSON-RPC     ┌─────────────────────┐    JSON-RPC     ┌────────────┐
│  IDE /   │ ──────────────► │  AgentShield        │ ──────────────► │  MCP       │
│  Agent   │                 │  MCP Proxy          │                 │  Server    │
│          │ ◄────────────── │  (stdio bridge)     │ ◄────────────── │            │
└──────────┘   responses /   └─────────────────────┘   responses     └────────────┘
               block errors        │
                                   ▼
                            ┌──────────────┐
                            │  Audit Log   │
                            │ audit.jsonl  │
                            └──────────────┘
```

### How it works

1. **IDE sends** a `tools/call` JSON-RPC request to the MCP server.
2. **AgentShield intercepts** the request in its stdio proxy.
3. The **MCP Policy Engine** evaluates the tool name and arguments against:
   - A **blocked tools list** (always-blocked tool names)
   - **Fine-grained rules** with glob/regex tool name matching and argument pattern matching
4. **Decision:**
   - `BLOCK` → proxy returns a JSON-RPC error to the IDE; the request never reaches the server.
   - `AUDIT` → request is forwarded to the server; the decision is logged.
   - `ALLOW` → request is forwarded silently.
5. All other MCP messages (`tools/list`, `initialize`, notifications) pass through transparently.

### What is mediated

| Message type | Mediated? | Notes |
|---|---|---|
| `tools/call` | **Yes** | Tool name + arguments evaluated against policy |
| `tools/list` | No | Passes through (tool list not filtered) |
| `resources/read` | No | Deferred to future version |
| `initialize` | No | Passes through |
| Notifications | No | Passes through |

## Usage

### Direct proxy

Wrap any MCP server command:

```bash
agentshield mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem /path/to/allowed/dir
```

### IDE configuration

#### Cursor (`.cursor/mcp.json`)

Before:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path"]
    }
  }
}
```

After:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentshield",
      "args": ["mcp-proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path"]
    }
  }
}
```

#### Automatic setup

```bash
agentshield setup mcp            # wrap all detected MCP server configs
agentshield setup mcp --disable  # restore original configs
```

This scans known config locations (`.cursor/mcp.json`, Claude Desktop config) and wraps stdio server commands automatically.

## MCP Policy

The MCP policy is loaded from `~/.agentshield/mcp-policy.yaml`. A default is created on first run of `agentshield setup mcp`.

### Policy structure

```yaml
defaults:
  decision: "AUDIT"          # ALLOW, AUDIT, or BLOCK

# Tools always blocked (exact name or glob)
blocked_tools:
  - "execute_command"
  - "run_shell"
  - "run_terminal_command"

# Fine-grained rules
rules:
  - id: block-ssh-access
    match:
      tool_name_any:          # match any of these tool names
        - "read_file"
        - "write_file"
      argument_patterns:      # all patterns must match
        path: "**/.ssh/**"    # glob with ** for recursive match
    decision: "BLOCK"
    reason: "Access to SSH key directories is blocked."
```

### Match types

| Field | Type | Description |
|---|---|---|
| `tool_name` | Exact/glob | Single tool name pattern |
| `tool_name_regex` | Regex | Regex against tool name |
| `tool_name_any` | List | Match if any name in list matches |
| `argument_patterns` | Map | Glob patterns matched against argument values |

### Glob patterns

- `*` matches a single path component (e.g., `read_*` matches `read_file`)
- `**` matches zero or more path components:
  - `/etc/**` — anything under `/etc/`
  - `**/.ssh/**` — any path containing `.ssh` as a directory
  - `/home/*/.aws/**` — `.aws` under any user home

### Decision precedence

1. **Blocked tools list** — checked first, always wins
2. **Rules** — evaluated in order, most restrictive decision wins
3. **Default** — applied if no rule matches

## Files

| File | Purpose |
|---|---|
| `internal/mcp/types.go` | MCP JSON-RPC message types |
| `internal/mcp/parser.go` | JSON-RPC message parsing and classification |
| `internal/mcp/policy.go` | MCP policy engine with glob/regex matching |
| `internal/mcp/loader.go` | Policy YAML loading and defaults |
| `internal/mcp/proxy.go` | Stdio proxy (client ↔ server bridge) |
| `internal/cli/mcp_proxy.go` | `agentshield mcp-proxy` CLI command |
| `internal/cli/setup_mcp.go` | `agentshield setup mcp` IDE config rewriting |
| `internal/mcp/testdata/echo_server.go` | Test MCP server for integration tests |
| `internal/mcp/testdata/redteam_mcp_cases.yaml` | 24 red-team regression test cases |

## Design Decisions

1. **Block at `tools/call` only** — `tools/list` responses are not filtered. This avoids breaking server capability negotiation and keeps the proxy transparent.
2. **Fail open on parse errors** — If a message can't be parsed as JSON-RPC, it's forwarded to the server. This ensures the proxy doesn't break non-standard server implementations.
3. **stdio transport only** — HTTP/SSE transport is deferred. Most IDE MCP integrations use stdio.
4. **No server identity verification** — The proxy trusts the server it spawns. Server impersonation detection is deferred.
5. **Separate policy file** — MCP policy is in `mcp-policy.yaml`, not mixed with shell command policy. The threat models and rule shapes are different.

## Testing

```bash
# All MCP tests (unit + integration + red-team)
go test ./internal/mcp/ -v

# Red-team cases only
go test ./internal/mcp/ -run TestRedTeamMCP -v

# Generate red-team report
go test ./internal/mcp/ -run TestRedTeamMCPReport -v
```

Red-team results: **24/24 cases pass (100%)** covering blocked tools, credential access, system directory writes, safe operations, and evasion attempts.
