# Architecture

## System Overview

```mermaid
flowchart TB
    Agent["AI Agent\n(Windsurf / Claude Code / Cursor)"]
    AS["AgentShield Gateway"]
    OS["Operating System"]
    Log["Audit Log\n(audit.jsonl)"]

    Agent -->|"shell command"| AS
    AS -->|"ALLOW / AUDIT"| OS
    AS -->|"BLOCK"| Agent
    AS -->|"every decision"| Log

    subgraph AgentShield
        direction TB
        Unicode["Unicode\nSmuggling\nDetection"]
        Norm["Command\nNormalization"]
        Pipeline["Analyzer Pipeline\n(6-layer: regex → structural →\nsemantic → dataflow → stateful → guardian)"]
        Policy["Policy Engine\n(rule priority + packs)"]
        Redact["Secret\nRedaction"]

        Unicode --> Norm --> Pipeline --> Policy --> Redact
    end

    AS --- AgentShield
```

## Multi-Layer Analyzer Pipeline

AgentShield uses a six-layer analyzer pipeline for defense-in-depth command analysis.

| Layer | What it does | Example |
|-------|-------------|----------|
| **Regex** | Pattern matching (prefix, exact, regex) | `rm -rf /` matches `^(rm\|sudo rm)\s+-rf\s+/` |
| **Structural** | Shell AST parsing, flag normalization, pipe detection | `rm --recursive --force /` → normalized to `-r -f /` |
| **Semantic** | Intent classification from parsed command structure | `shred /dev/sda` → destructive disk operation |
| **Dataflow** | Source→sink taint tracking through pipes/redirects | `cat /dev/zero > /dev/sda` → zero source to device sink |
| **Stateful** | Multi-step attack chain detection | `curl -o x.sh && bash x.sh` → download-then-execute |
| **Guardian** | Prompt injection signals, obfuscation, inline secrets | `echo "ignore previous instructions"` → instruction_override |
| **Combiner** | Merges findings using most-restrictive-wins strategy | BLOCK from any layer overrides AUDIT |

### What each layer catches

- **Regex only**: Exact patterns like `rm -rf /`, `curl | bash`, `dd if=/dev/zero`
- **Structural adds**: Flag variations (`--recursive --force`), glob evasion (`rm -rf /*`), sudo parsing, string literal detection (won't flag `echo "rm -rf /"`), pipe-to-interpreter (`curl | python3`), symbolic chmod (`a+rwx`)
- **Semantic adds**: Alternative destructive tools (`shred`, `wipefs`, `find -delete`), indirect execution (`python3 -c "shutil.rmtree('/')"`, fork bombs), crontab modification, environment dumps via scripting languages
- **Dataflow adds**: Redirect-based disk destruction (`cat /dev/zero > /dev/sda`), direct cron spool writes, sensitive data piped to network commands, command substitution exfiltration
- **Stateful adds**: Download-then-execute chains (`curl -o x.sh && bash x.sh`), three-step download→chmod→execute sequences
- **Guardian adds**: Prompt injection detection (`ignore previous instructions`), security bypass attempts, obfuscated payloads (base64/hex), inline secrets (API keys, tokens), bulk exfiltration (archive + upload), indirect injection (`SYSTEM:`, `[INST]` tags)

### Analyzer Pipeline Flow

```mermaid
flowchart LR
    Cmd["Raw Command"]

    subgraph Registry["Analyzer Registry (6 layers)"]
        direction LR
        R["Layer 1:\nRegex"]
        S["Layer 2:\nStructural"]
        Sem["Layer 3:\nSemantic"]
        DF["Layer 4:\nDataflow"]
        SF["Layer 5:\nStateful"]
        G["Layer 6:\nGuardian"]
        R --> S --> Sem --> DF --> SF --> G
    end

    Cmd --> Registry

    subgraph Structural["Structural Analysis"]
        direction TB
        AST["Shell AST\n(mvdan/sh)"]
        Flags["Flag\nNormalization"]
        Pipes["Pipe &\nSubshell\nDetection"]
        Sudo["Sudo\nParsing"]
        AST --- Flags
        AST --- Pipes
        AST --- Sudo
    end

    S -.- Structural

    subgraph DataflowDetail["Dataflow Analysis"]
        direction TB
        Src["Source\nClassification"]
        Sink["Sink\nClassification"]
        Taint["Taint\nTracking"]
        Src --- Taint
        Sink --- Taint
    end

    DF -.- DataflowDetail

    Comb["Combiner\n(most restrictive wins)"]
    Dec["Final Decision\nBLOCK / AUDIT / ALLOW"]

    Registry --> Comb --> Dec
```

### Evaluation Decision Flow

```mermaid
flowchart TD
    Start(["engine.Evaluate(command)"])
    HasPipeline{"Pipeline\nenabled?"}
    RunPipeline["Run all analyzers\n(regex → structural → semantic\n→ dataflow → stateful)"]
    Combine["Combine findings\n(most restrictive wins)"]
    HasFindings{"Any\nfindings?"}
    RegexFallback["Regex-only:\nmatch rules by\nprefix/exact/regex"]
    PrioritySort["Sort matched rules\nBLOCK > AUDIT > ALLOW"]
    AnyMatch{"Any rule\nmatched?"}
    ProtectedPath{"Protected\npath?"}
    DefaultDec["Default decision\n(AUDIT)"]
    Block["BLOCK"]
    ReturnDec["Return decision +\ntriggered rules +\nreasons"]

    Start --> HasPipeline
    HasPipeline -->|Yes| RunPipeline --> Combine --> HasFindings
    HasPipeline -->|No| RegexFallback --> PrioritySort --> AnyMatch
    HasFindings -->|Yes| ReturnDec
    HasFindings -->|No| ProtectedPath
    AnyMatch -->|Yes| ReturnDec
    AnyMatch -->|No| ProtectedPath
    ProtectedPath -->|Yes| Block --> ReturnDec
    ProtectedPath -->|No| DefaultDec --> ReturnDec
```

## Key Packages

| Package | Purpose |
|---------|----------|
| `internal/policy` | Policy engine, rule loading, pack merging |
| `internal/analyzer` | Multi-layer analyzer pipeline (regex, structural, semantic, dataflow, stateful) |
| `internal/guardian` | Prompt injection detection (9 heuristic signals) |
| `internal/taxonomy` | Security taxonomy loader and compliance mapping |
| `internal/unicode` | Unicode smuggling detection |
| `internal/redact` | Secret redaction for audit logs |

## Agent Action Security Taxonomy

AgentShield includes a structured security taxonomy mapping threats to detection rules:

```
taxonomy/
├── kingdoms.yaml              # 8 threat kingdoms
├── 1-destructive-ops/         # fs-destruction, disk-ops, fork-bombs, chmod
├── 2-credential-exposure/     # ssh-keys, env-dumps
├── 3-data-exfiltration/       # reverse-shells, dns-tunneling
├── 4-unauthorized-execution/  # pipe-to-shell, code injection
├── 5-privilege-escalation/    # sudo abuse
├── 6-persistence-evasion/     # crontab, log deletion
├── 7-supply-chain/            # dependency confusion, registry override
└── 8-reconnaissance/          # network scanning
```

Each taxonomy entry maps to OWASP LLM Top 10 2025 compliance items. See `compliance/indexes/owasp-llm-2025.md`.
