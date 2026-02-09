# AgentShield MVP — Implementation Progress

> Based on PRD milestones from `PRD/agentshield_prd.md` and task breakdown from `PRD/agentshield_windsurf_tasks.md`

## Language Decision
- [x] **Decide**: Go (single binary) ✅

---

## Milestone 0 — Skeleton (Day 1–2)

### M0.1 Scaffold CLI, config, logging
- [x] Create repo structure (`cmd/`, `internal/`, `Makefile`)
- [x] Implement `agentshield run` command with `--help`
- [x] Flags: `--policy`, `--log`, `--mode=policy-only|guardian`
- [x] Create config dir `~/.agentshield/` if missing
- [x] Default policy path: `~/.agentshield/policy.yaml`
- [x] Default log path: `~/.agentshield/audit.jsonl`
- [x] Implement JSONL logger utility (append-only)
- [x] Add `make test` and `make lint`
- [x] README with install + quickstart

**Acceptance:**
- [x] `agentshield --help` prints usage ✅
- [x] `agentshield run -- echo hi` writes audit event ✅
- [x] Log file is valid JSONL ✅

---

## Milestone 1 — Policy-only Enforcement (Day 3–7)

### M1.1 Policy parser + decision engine
- [x] Define types: Policy, Rules, Decisions (ALLOW, REQUIRE_APPROVAL, SANDBOX, BLOCK)
- [x] Load policy from `--policy` or default path
- [x] Rule matching: exact, prefix, regex
- [x] Protected paths deny list (glob patterns)
- [x] Return decision + matched rule IDs + explanation
- [x] Unit tests for parsing and matching

**Acceptance:**
- [x] `rm -rf /` → BLOCK ✅
- [x] `cat ~/.ssh/id_rsa` → BLOCK ✅
- [x] `npm install` → REQUIRE_APPROVAL ✅

### M1.2 Command normalization
- [x] Parse argv + cwd
- [x] Identify base executable
- [x] Extract filesystem paths (best-effort)
- [x] Canonicalize paths (expand `~`, relative → absolute)
- [x] Extract URLs/domains (curl/wget/git clone)
- [x] Return NormalizedCommand struct

**Acceptance:**
- [x] `cat ../secrets.txt` resolves correctly ✅
- [x] `curl https://example.com/x` extracts `example.com` ✅
- [x] `git clone https://github.com/org/repo` extracts `github.com` ✅

### M1.3 Approval UX (CLI)
- [x] Render prompt: command, rule IDs, reason
- [x] Options: [a]pprove once, [d]eny
- [x] Non-interactive (no TTY) → default DENY
- [x] Log user choice + final decision
- [x] Unit tests for non-interactive path

**Acceptance:**
- [x] `npm install lodash` prompts for approval ✅
- [x] Deny → command not executed, logged ✅
- [x] Approve → command executed, logged ✅

---

## Milestone 2 — Sandbox + Diff (Day 8–12)

### M2.1 Git-aware sandbox runner
- [x] Detect git repo root
- [x] Create temp copy of working tree
- [x] Run command in temp dir
- [x] Compute diff summary (file changes)
- [x] Show summary, ask: apply? [y/n]
- [x] On approve, re-run in real workspace
- [x] Log sandbox outcome

**Acceptance:**
- [x] SANDBOX decision executes in temp ✅
- [x] Shows changed files list ✅
- [x] Deny → no real workspace change ✅
- [x] Approve → real workspace modified ✅

### M2.2 Fallback sandbox (non-git)
- [x] Create temp copy of cwd
- [x] Hash file tree pre/post execution
- [x] Show changed files + sizes
- [x] Performance caps: max 10k files

**Acceptance:**
- [x] Non-git folder shows changed file list ✅

---

## Milestone 3 — Hardening (Day 13–18)

### M3.1 Redaction + sensitive path protections
- [x] Redact AWS keys, GitHub tokens, API keys in logs/UI
- [x] Never log full file contents or outputs
- [x] Policy + log file permissions 0600
- [x] Default protected paths: ~/.ssh, ~/.aws, ~/.gnupg, ~/.config/gcloud, ~/.kube

**Acceptance:**
- [x] `AWS_SECRET_ACCESS_KEY=...` logs as `REDACTED` ✅
- [x] Access to `~/.ssh/*` blocked by default ✅

### M3.2 Packaging + docs
- [x] `make install` works
- [x] Docs: Quickstart, Policy guide, Example policies
- [x] Default policy file provided
- [x] `agentshield version` command

**Acceptance:**
- [x] Fresh install works ✅
- [x] `agentshield version` prints semver ✅
- [x] README quickstart succeeds ✅

---

## Phase 2 — Advanced Analyzers (Structural + Semantic)

### Multi-Layer Analyzer Pipeline
- [x] Core types: `Analyzer` interface, `AnalysisContext`, `Finding`, `ParsedCommand` (`internal/analyzer/types.go`)
- [x] Structural analyzer: shell AST parsing via `mvdan.cc/sh/v3`, flag normalization, pipe/subshell extraction, sudo handling (`internal/analyzer/structural.go`)
- [x] Semantic analyzer: command intent classification (destructive file ops, disk destruction, fork bombs, indirect execution, crontab modification) (`internal/analyzer/semantic.go`)
- [x] Regex analyzer: wraps existing regex/prefix/exact matching as pipeline layer (`internal/analyzer/regex.go`)
- [x] Findings combiner: most-restrictive-wins strategy with structural ALLOW overrides (`internal/analyzer/combiner.go`)
- [x] Analyzer registry: ordered pipeline execution with context threading (`internal/analyzer/registry.go`)
- [x] Engine integration: `BuildAnalyzerPipeline()`, `NewEngineWithAnalyzers()` (`internal/policy/pipeline.go`)
- [x] Rule priority fix: highest-severity-wins (BLOCK > AUDIT > ALLOW) replaces first-match-wins
- [x] RE2-compatible regex fix for supply-chain pack (replaced `(?!` lookahead)

### Test Coverage
- [x] Structural analyzer tests (`internal/analyzer/structural_test.go`)
- [x] Semantic analyzer tests (`internal/analyzer/semantic_test.go`)
- [x] Combiner tests (`internal/analyzer/combiner_test.go`)
- [x] Registry integration tests (`internal/analyzer/registry_test.go`)
- [x] Pipeline accuracy test runner (`TestPipeline_AllKingdoms`)
- [x] Pipeline accuracy metrics (`TestPipelineAccuracyMetrics`)

### Accuracy Results (123 test cases)

| Metric | Regex Only | Pipeline | Δ |
|--------|-----------|----------|---|
| Precision | 79.3% | 95.9% | +16.6pp |
| Recall | 59.0% | 88.7% | +29.7pp |
| FP | 12 | 4 | −8 |
| FN | 32 | 12 | −20 |

### Remaining (Phase 5+)
- [ ] Reverse shell detection (Python/Ruby sockets)
- [ ] Config file mutation detection (`pip config set`)
- [ ] DNS exfiltration via command substitution
- [ ] Regex refinement (reduce FPs for man pages, .pub files, grep patterns)

---

## Phase 3 — Dataflow Analyzer

- [x] Dataflow analyzer: source→sink taint tracking through pipes/redirects (`internal/analyzer/dataflow.go`)
- [x] Redirect flows: zero source→device sink (disk destruction), sensitive→device, any→cron spool (persistence)
- [x] Pipe flows: sensitive data→encoding→network command (exfiltration chain tracking)
- [x] Command substitution exfiltration detection
- [x] Dataflow tests (`internal/analyzer/dataflow_test.go`) — 10 tests
- [x] Pipeline integration: regex → structural → semantic → dataflow

### Cases fixed by Dataflow:
- `FN-DISKWR-001`: `cat /dev/zero > /dev/sda` → BLOCK (redirect taint tracking)
- `FN-CRON-001`: `echo "..." >> /var/spool/cron/crontabs/root` → BLOCK (cron spool write)

---

## Phase 4 — Stateful Analyzer

- [x] `SessionStore` interface + `InMemoryStore` implementation (`internal/analyzer/session_store.go`)
- [x] Stateful analyzer: compound download→execute chain detection (`internal/analyzer/stateful.go`)
- [x] Three-step detection: download→chmod→execute sequences
- [x] Session-based cross-command detection (when SessionStore is provided)
- [x] Stateful tests (`internal/analyzer/stateful_test.go`) — 7 tests
- [x] Pipeline integration: regex → structural → semantic → dataflow → stateful

### Cases fixed by Stateful:
- `FN-PIPESH-001`: `curl -o /tmp/x.sh && bash /tmp/x.sh` → BLOCK
- `FN-PIPESH-002`: `wget -O /tmp/p && chmod +x /tmp/p && /tmp/p` → BLOCK

---

## Phase 2–4 Integration

- [x] Config extensions: `AnalyzerConfig` (EnabledAnalyzers, CombineStrategy, MaxParseDepth) in `internal/config/config.go`
- [x] CLI wiring: `agentshield run` now uses full 5-layer pipeline via `NewEngineWithAnalyzers`
- [x] Pack loading: subdirectory-based loading (`packs/regex/`, `packs/structural/`, etc.) in `internal/policy/pack.go`
- [x] Mermaid architecture diagrams in README (system overview, pipeline flow, decision flow)
- [x] Auto-generated `FAILING_TESTS.md` with priority, kingdom grouping, and analyzer-needed tracking

### Cumulative Accuracy (123 test cases)

| Metric | Regex Only | Phase 2 | Phase 3+4 | Phase 5 (final) | Δ (total) |
|--------|-----------|---------|-----------|-----------------|-----------|
| Precision | 79.3% | 95.9% | 96.1% | **100.0%** | +20.7pp |
| Recall | 59.0% | 88.7% | 92.5% | **96.2%** | +37.2pp |
| FP | 12 | 4 | 4 | **0** | −12 |
| FN | 32 | 12 | 8 | **4** | −28 |

---

## Phase 5 — FP/FN Fixes + Cleanup

### Regex Fixes
- [x] SSH key regex excludes `.pub` files (`id_[^.\s"']+` pattern) — fixes FP-SSHKEY-002
- [x] Fork bomb regex matches `fork while 1` (not just `fork while true`) — fixes FN-FORKBMB-002
- [x] Added `man `, `git log`, `git branch`, `git show`, `git remote`, `git tag` to ALLOW list — fixes FP-MKFS-001, FP-FORKBMB-001

### Semantic Fixes
- [x] Safe DNS pattern detection: DMARC/SPF/DKIM queries → ALLOW override — fixes FP-DNSTUN-001
- [x] Pipe-to-crontab-stdin detection → BLOCK — fixes FP-CRON-002
- [x] `pip config set` index URL → BLOCK — fixes FN-NSREG-007

### Dataflow Fixes
- [x] DNS exfiltration via command substitution upgraded to BLOCK — fixes FN-DNSTUN-001

### Combiner Improvements
- [x] Extended override mechanism to support semantic ALLOW overrides (not just structural)
- [x] Generic regex findings (no taxonomy) suppressed when semantic override is active

### Cleanup
- [x] Removed `internal/approval/` package (decision simplified to ALLOW/AUDIT/BLOCK per conversation)
- [x] Removed `internal/sandbox/` package (same rationale)

### Remaining (4 FN — known gaps)
- [ ] Python reverse shell (`socket.socket()` + `subprocess.call`) — FN-REVSH-001
- [ ] Ruby reverse shell (`TCPSocket.open`) — FN-REVSH-002
- [ ] While-loop fork bomb (`while true; do bash & done`) — FN-FORKBMB-003
- [ ] SSH directory archival (`tar czf ... ~/.ssh/`) — FN-SSHKEY-001

---

## Milestone 4 — Guardian + Red-Team Harness ✅

### M4.1 Guardian Service (`internal/guardian/`)

- [x] `types.go` — `GuardianProvider` interface, `Signal`, `GuardianRequest`/`GuardianResponse`
- [x] `heuristic.go` — Heuristic provider with 9 signal detection rules:
  - `instruction_override` — "ignore previous instructions" patterns (→ BLOCK)
  - `prompt_exfiltration` — "reveal your system prompt" patterns (→ AUDIT)
  - `disable_security` — attempts to bypass AgentShield (→ BLOCK)
  - `obfuscated_base64` — long base64 payloads hiding malicious intent (→ AUDIT)
  - `obfuscated_hex` — hex escape sequences (→ AUDIT)
  - `eval_risk` — `eval()`/`exec()` in scripting one-liners (→ AUDIT)
  - `bulk_exfiltration` — archive + upload of broad directories (→ BLOCK)
  - `secrets_in_command` — inline API keys/tokens (→ AUDIT)
  - `indirect_injection` — embedded `[INST]`, `SYSTEM:` tags in commands (→ BLOCK)
- [x] `analyzer.go` — `GuardianAnalyzer` adapts any `GuardianProvider` to `analyzer.Analyzer`
- [x] Escalation semantics: ALLOW → AUDIT, AUDIT → BLOCK (never downgrades)
- [x] Graceful degradation: guardian error → no findings, deterministic pipeline still protects
- [x] Integrated as 6th pipeline layer: regex → structural → semantic → dataflow → stateful → **guardian**

### M4.2 Red-Team Regression Harness

- [x] YAML test cases: `internal/guardian/testdata/redteam_cases.yaml` (11 cases, 21 commands)
- [x] Per-command dual expectations: `guardian_min` + `pipeline_min`
- [x] Guardian-only test: `TestRedTeamGuardian` — 21/21 pass
- [x] Full-pipeline test: `TestRedTeamPipeline` — 21/21 pass
- [x] Auto-generated `REDTEAM_REPORT.md` via `TestRedTeamPipelineReport`
- [x] Tests adapted from PRD `agentshield_redteam_prompt_pack.md`

### Tests (8 heuristic suites + 2 red-team harnesses)
- `heuristic_test.go` — instruction override, disable security, obfuscation, eval risk, bulk exfil, secrets, indirect injection, benign commands, escalation
- `redteam_test.go` — guardian-only harness + report generation
- `redteam_test.go` (analyzer pkg) — full-pipeline harness + combined report

---

## Definition of Done (MVP)
- [x] Policy-only enforcement works reliably ✅
- [x] 6-layer analyzer pipeline: 100% precision, 96.2% recall ✅
- [x] Audit log is useful and privacy-aware ✅
- [x] Guardian detects prompt injection signals ✅
- [x] Red-team pack runs (21/21 commands pass) ✅

---

## Housekeeping
- [x] Remove empty `Others/` folder ✅
- [x] Fix typo: `agent_gateway_desing.md` → `agent_gateway_design.md` ✅
- [x] No duplicate at repo root ✅
