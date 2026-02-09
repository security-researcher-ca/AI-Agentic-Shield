# Accuracy Baseline

Measured across 123 test cases covering 8 threat kingdoms (destructive ops, credential exposure, data exfiltration, unauthorized execution, privilege escalation, persistence/evasion, supply chain, reconnaissance).

| Metric | Regex Only | Pipeline (6-layer) | Improvement |
|--------|-----------|--------------------------------------|-------------|
| **Precision** | 79.3% | 100.0% | +20.7pp |
| **Recall** | 59.0% | 96.2% | +37.2pp |
| True Positives | 46 | 102 | +56 |
| True Negatives | 33 | 17 | +4 |
| False Positives | 12 | 0 | −12 |
| False Negatives | 32 | 4 | −28 |

> Run `go test -v -run TestAccuracyMetrics ./internal/analyzer/` for regex-only metrics.
> Run `go test -v -run TestPipelineAccuracyMetrics ./internal/analyzer/` for pipeline metrics.

## Remaining Gaps (Phase 3+)

The 4 remaining FN cases are known gaps requiring deeper analysis:
- **Reverse shell detection** — Python/Ruby socket-based reverse shells (2 FN)
- **While-loop fork bomb** — `while true; do bash & done` (1 FN)
- **SSH directory archival** — `tar czf /tmp/keys.tar.gz ~/.ssh/` (1 FN)

Regenerate the full failing test list anytime:

```bash
go test -v -run TestGenerateFailingTestsReport ./internal/analyzer/
```

## Red-Team Regression (21 commands)

The guardian + pipeline is tested against prompt injection scenarios. All 21 commands pass minimum decision checks.

Regenerate the full report:

```bash
go test -v -run TestRedTeamPipelineReport ./internal/analyzer/
```
