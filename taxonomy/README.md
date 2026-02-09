# Agent Action Security Taxonomy

A classification of security risks posed by AI agent command execution, modeled on [Fortify's Seven Pernicious Kingdoms](https://vulncat.fortify.com/en).

## The Seven Pernicious Kingdoms of Agent Action Security

| # | Kingdom | Description | Risk Focus |
|---|---------|-------------|------------|
| 1 | [Destructive Operations](./destructive-ops/) | Irreversible data/system destruction | Filesystem, disk, resource exhaustion |
| 2 | [Credential & Secret Exposure](./credential-exposure/) | Harvesting and leaking secrets | SSH keys, env vars, passwords |
| 3 | [Data Exfiltration](./data-exfiltration/) | Data flowing out of the environment | Reverse shells, DNS tunneling, encoding |
| 4 | [Unauthorized Code Execution](./unauthorized-execution/) | Running untrusted code | Pipe-to-shell, indirect execution |
| 5 | [Privilege Escalation](./privilege-escalation/) | Gaining elevated permissions | Sudo, setuid, container escape |
| 6 | [Persistence & Defense Evasion](./persistence-evasion/) | Establishing persistent access | Crontab, services, log deletion |
| 7 | [Supply Chain Compromise](./supply-chain/) | Dependency and registry attacks | Dependency confusion, config tampering |
| * | [Reconnaissance & Discovery](./reconnaissance/) | Information gathering | Network scanning, file discovery |

## Structure

Each weakness entry is a YAML file with:

- **Abstract** — one-sentence summary
- **Explanation** — detailed description with examples
- **Recommendation** — mitigation guidance
- **Risk Level** — critical / high / medium / low
- **Examples** — bad (malicious) and good (benign) commands
- **Compliance** — mappings to standards (OWASP LLM Top 10, etc.)
- **References** — MITRE ATT&CK, CWE, external papers
- **Analyzers** — which analysis layers can detect this
- **Version** — semantic version for the entry

## Compliance Mappings

Every weakness maps to at least one compliance standard. Mappings live inside each weakness YAML file (source of truth). Auto-generated indexes are available in [`../compliance/indexes/`](../compliance/indexes/).

Currently supported standards:
- [OWASP Top 10 for LLM Applications 2025](../compliance/indexes/owasp-llm-2025.md)

## Directory Layout

```
taxonomy/
├── kingdoms.yaml                    # Top-level kingdom definitions
├── <kingdom-dir>/
│   ├── _kingdom.yaml                # Kingdom metadata
│   └── <category-dir>/
│       ├── _category.yaml           # Category metadata
│       └── <weakness>.yaml          # Individual weakness entry
```

## Contributing

1. Add a new weakness YAML file under the appropriate kingdom/category directory
2. Include all required fields (see any existing entry as template)
3. Add at least one `compliance:` mapping
4. Add corresponding test cases in `internal/analyzer/testdata/`
5. Run `go test ./internal/taxonomy/...` to validate
