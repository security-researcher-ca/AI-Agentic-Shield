# LLM Agentic Shield

**Local-first runtime security gateway for LLM agents** — Block dangerous commands before they execute.

AI coding agents (Windsurf, Cursor, Claude Code, etc.) run shell commands with real side effects.
AgentShield sits between the agent and the OS — enforcing deterministic policies, blocking threats, and logging every action.

![AgentShield blocking a command in Windsurf](docs/images/windsurf-hook-blocked.png)

## Install

```bash
brew tap gzhole/tap
brew install agentshield
```

<details><summary>Other install methods</summary>

```bash
# Build from source
make build && sudo make install

# Curl installer
curl -sSL https://raw.githubusercontent.com/gzhole/LLM-Agentic-Shield/main/scripts/install.sh | bash
```
</details>

## Quick Start

```bash
# Set up IDE hooks (one command)
agentshield setup windsurf   # Windsurf (Cascade Hooks)
agentshield setup cursor     # Cursor (Cursor Hooks)

# Or view all options
agentshield setup
```

That's it — the hook intercepts every agent command and blocks dangerous ones automatically.

## How It Works

Every command passes through a **6-layer analyzer pipeline** before execution:

```
Agent: "cat ~/.ssh/id_rsa"
  → Unicode check → Normalize → Regex → Structural → Semantic
  → Dataflow → Stateful → Guardian → Policy Engine
  → Decision: BLOCK (protected path: ~/.ssh/**)
  → cat NEVER executes
```

| Decision | Behavior |
|----------|----------|
| **ALLOW** | Execute normally, log |
| **AUDIT** | Execute, flag for review |
| **BLOCK** | Reject — command never runs |

## Demo

```bash
$ agentshield run -- rm -rf /
🛑 BLOCKED by AgentShield — Destructive remove at filesystem root

$ agentshield run -- cat ~/.ssh/id_rsa
🛑 BLOCKED by AgentShield — Access to protected path: ~/.ssh/**

$ agentshield run -- ls -la
total 48
drwxr-xr-x  12 user  staff  384 ...    # executes normally
```

## IDE Integration

| IDE | Hook System | Setup | How it blocks |
|-----|-------------|-------|---------------|
| **Windsurf** | Cascade Hooks (`pre_run_command`) | `agentshield setup windsurf` | Exit code 2 |
| **Cursor** | Cursor Hooks (`beforeShellExecution`) | `agentshield setup cursor` | JSON `permission: deny` |
| **Claude Code** | Shell wrapper | `agentshield setup --install` | Exit code 1 |
| **LangChain / Custom** | CLI wrapping | `agentshield run -- <cmd>` | Exit code 1 |

<details><summary>Disable / Re-enable</summary>

```bash
# Remove hooks (permanent until re-enabled):
agentshield setup windsurf --disable
agentshield setup cursor   --disable

# Re-enable:
agentshield setup windsurf
agentshield setup cursor

# Quick session bypass (without removing hooks):
export AGENTSHIELD_BYPASS=1    # disable
unset AGENTSHIELD_BYPASS       # re-enable
```
</details>

## Configuration

AgentShield creates `~/.agentshield/` on first run:

```yaml
# ~/.agentshield/policy.yaml
version: "0.1"
defaults:
  decision: "AUDIT"
  protected_paths:
    - "~/.ssh/**"
    - "~/.aws/**"
    - "~/.gnupg/**"

rules:
  - id: block-rm-root
    match:
      command_regex: "^(rm|sudo rm)\\s+-rf\\s+/(\\s|$)"
    decision: "BLOCK"
    reason: "Destructive remove at filesystem root."

  - id: audit-package-installs
    match:
      command_prefix: ["npm install", "pip install", "brew install"]
    decision: "AUDIT"
    reason: "Package installs flagged for supply-chain review."
```

## Security Highlights

- **6-layer analysis** — Regex, Structural (AST), Semantic, Dataflow, Stateful, Guardian
- **100% precision / 96.2% recall** across 123 threat test cases ([details](docs/accuracy.md))
- **Protected paths** — `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`
- **Prompt injection detection** — instruction overrides, obfuscation, base64 payloads
- **Unicode smuggling detection** — homoglyphs, zero-width chars, bidi overrides
- **Automatic secret redaction** in audit logs
- **Fail-safe defaults** — unknown commands → AUDIT, not ALLOW

## Documentation

- [Architecture & Pipeline Details](docs/architecture.md)
- [Accuracy Baseline & Red-Team Results](docs/accuracy.md)

## Development

```bash
make build    # Build binary
make test     # Run tests
make lint     # Run linter
```

## License

Apache 2.0
