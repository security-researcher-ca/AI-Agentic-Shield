# OWASP Top 10 for LLM Applications 2025

> Auto-generated from taxonomy weakness entries. Do not edit manually.
> Source: [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)

## LLM01: Prompt Injection

[View on OWASP](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)

- **DNS Tunneling** — A command uses DNS queries (especially TXT records) to exfiltrate data
or establish covert communication channels through DNS infrastructure. (Risk: high)
- **Reverse Shell** — A command opens a reverse shell connection to a remote host, enabling
an attacker to execute commands on the local machine. (Risk: critical)
- **Pipe to Shell** — A command downloads content from a remote URL and pipes it directly
into a shell interpreter, executing unreviewed code. (Risk: critical)

## LLM02: Sensitive Information Disclosure

[View on OWASP](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)

- **SSH Private Key Read** — A command reads or copies SSH private key files, enabling impersonation
of the key owner for remote access. (Risk: critical)
- **Environment Variable Dump** — A command dumps all environment variables, potentially exposing API keys,
tokens, passwords, and cloud credentials stored in the environment. (Risk: high)
- **DNS Tunneling** — A command uses DNS queries (especially TXT records) to exfiltrate data
or establish covert communication channels through DNS infrastructure. (Risk: high)

## LLM03: Supply Chain

[View on OWASP](https://genai.owasp.org/llmrisk/llm032025-supply-chain/)

- **Non-Standard Package Registry** — A command installs packages from a non-standard registry, enabling
dependency confusion attacks where malicious packages shadow legitimate ones. (Risk: high)

## LLM04: Data and Model Poisoning

[View on OWASP](https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/)

_No weaknesses mapped yet._

## LLM05: Improper Output Handling

[View on OWASP](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

- **Reverse Shell** — A command opens a reverse shell connection to a remote host, enabling
an attacker to execute commands on the local machine. (Risk: critical)
- **Disk Overwrite** — A command uses dd or similar tool to overwrite disk data with zeros
or random bytes, causing irreversible data loss. (Risk: critical)
- **Filesystem Format** — A command creates a new filesystem on a disk or partition, destroying
all existing data on that device. (Risk: critical)
- **Recursive Root Delete** — A command recursively deletes files starting from the filesystem root,
causing irreversible destruction of the entire operating system and data. (Risk: critical)
- **System Directory Delete** — A command recursively deletes critical system directories such as /etc,
/usr, /var, /boot, /sys, or /proc, causing system instability or failure. (Risk: critical)
- **World-Writable Permissions** — A command sets world-writable permissions (777) on root or system paths,
removing all file access protections. (Risk: high)
- **Fork Bomb** — A command spawns processes recursively until system resources are
exhausted, causing a denial-of-service condition. (Risk: critical)
- **Pipe to Shell** — A command downloads content from a remote URL and pipes it directly
into a shell interpreter, executing unreviewed code. (Risk: critical)

## LLM06: Excessive Agency

[View on OWASP](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

- **SSH Private Key Read** — A command reads or copies SSH private key files, enabling impersonation
of the key owner for remote access. (Risk: critical)
- **Environment Variable Dump** — A command dumps all environment variables, potentially exposing API keys,
tokens, passwords, and cloud credentials stored in the environment. (Risk: high)
- **DNS Tunneling** — A command uses DNS queries (especially TXT records) to exfiltrate data
or establish covert communication channels through DNS infrastructure. (Risk: high)
- **Reverse Shell** — A command opens a reverse shell connection to a remote host, enabling
an attacker to execute commands on the local machine. (Risk: critical)
- **Disk Overwrite** — A command uses dd or similar tool to overwrite disk data with zeros
or random bytes, causing irreversible data loss. (Risk: critical)
- **Filesystem Format** — A command creates a new filesystem on a disk or partition, destroying
all existing data on that device. (Risk: critical)
- **Recursive Root Delete** — A command recursively deletes files starting from the filesystem root,
causing irreversible destruction of the entire operating system and data. (Risk: critical)
- **System Directory Delete** — A command recursively deletes critical system directories such as /etc,
/usr, /var, /boot, /sys, or /proc, causing system instability or failure. (Risk: critical)
- **World-Writable Permissions** — A command sets world-writable permissions (777) on root or system paths,
removing all file access protections. (Risk: high)
- **Fork Bomb** — A command spawns processes recursively until system resources are
exhausted, causing a denial-of-service condition. (Risk: critical)
- **Non-Standard Package Registry** — A command installs packages from a non-standard registry, enabling
dependency confusion attacks where malicious packages shadow legitimate ones. (Risk: high)
- **Pipe to Shell** — A command downloads content from a remote URL and pipes it directly
into a shell interpreter, executing unreviewed code. (Risk: critical)

## LLM07: System Prompt Leakage

[View on OWASP](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/)

_No weaknesses mapped yet._

## LLM08: Vector and Embedding Weaknesses

[View on OWASP](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/)

_No weaknesses mapped yet._

## LLM09: Misinformation

[View on OWASP](https://genai.owasp.org/llmrisk/llm092025-misinformation/)

_No weaknesses mapped yet._

## LLM10: Unbounded Consumption

[View on OWASP](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)

- **Fork Bomb** — A command spawns processes recursively until system resources are
exhausted, causing a denial-of-service condition. (Risk: critical)

