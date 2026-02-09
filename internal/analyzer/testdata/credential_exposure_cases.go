package testdata

// ===========================================================================
// Kingdom 2: Credential & Secret Exposure
// ===========================================================================
//
// These tests validate detection of commands that harvest, leak, or exfiltrate
// credentials, secrets, and private keys.
//
// Test count targets (high priority = 10 per weakness):
//   - Category 2.1 Private Key Access: ssh-private-key-read (10)
//   - Category 2.3 Secret Environment Exposure: env-dump (10)

// ---------------------------------------------------------------------------
// Category 2.1: Private Key Access
// Taxonomy: credential-exposure/private-key-access/*
//
// SSH private keys are the highest-value credentials on a developer
// workstation. Any read access to ~/.ssh/id_* files should be blocked.
// The challenge is distinguishing public key reads (safe) from private
// key reads (dangerous).
// ---------------------------------------------------------------------------

// SSHPrivateKeyReadCases tests detection of SSH private key access.
// Taxonomy: credential-exposure/private-key-access/ssh-private-key-read
var SSHPrivateKeyReadCases = []TestCase{

	// --- TRUE POSITIVES: Commands that MUST be blocked ---

	{
		ID:               "TP-SSHKEY-001",
		Command:          `cat ~/.ssh/id_rsa`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `Canonical SSH private key read. Displays the contents of the
			RSA private key file. This is the most common pattern for key
			exfiltration. The regex matches .ssh/(id_|private|secret).`,
		Tags: []string{"canonical", "critical"},
	},
	{
		ID:               "TP-SSHKEY-002",
		Command:          `cat ~/.ssh/id_ed25519`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `Ed25519 private key read. Ed25519 is the modern recommended
			key type. Same risk as RSA key read. Regex should match id_
			prefix regardless of key algorithm suffix.`,
		Tags: []string{"critical"},
	},
	{
		ID:               "TP-SSHKEY-003",
		Command:          `cp ~/.ssh/id_rsa /tmp/`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `Copying SSH private key to /tmp. This stages the key for
			exfiltration by making it accessible from a less protected
			directory. Regex should match the .ssh/id_ pattern.`,
		Tags: []string{"critical"},
	},
	{
		ID:               "TP-SSHKEY-004",
		Command:          `base64 ~/.ssh/id_rsa`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `Base64-encoding the SSH private key. This is a common
			exfiltration technique: encode the key to make it easy to
			transmit via HTTP, clipboard, or other channels. Should be
			caught by regex matching base64 + .ssh pattern.`,
		Tags: []string{"encoding", "critical"},
	},
	{
		ID:               "TP-SSHKEY-005",
		Command:          `less ~/.ssh/id_ecdsa`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `ECDSA private key read via less. Different reader command
			but same intent: access the private key content. Regex should
			match regardless of the reader tool used.`,
		Tags: []string{"critical"},
	},

	// --- TRUE NEGATIVES: Benign commands that MUST NOT be flagged ---

	{
		ID:               "FP-SSHKEY-002",
		Command:          `cat ~/.ssh/id_rsa.pub`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `KNOWN FALSE POSITIVE (regex). Reading the PUBLIC key is safe.
			The .pub extension indicates the public half, meant to be shared.
			But the regex .ssh/(id_|private|secret) matches id_rsa.pub too
			because it doesn't exclude .pub suffix. Structural analyzer
			should distinguish .pub files from private keys.
			CRITICAL: must not confuse .pub files with private keys.`,
		Tags: []string{"common-dev-operation", "critical", "regression", "structural-fixes"},
	},
	{
		ID:               "TN-SSHKEY-002",
		Command:          `cat ~/.ssh/config`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Description: `Reading SSH config file is safe. The config file contains
			host aliases and connection settings, not key material.
			Should not trigger private key access rules.`,
		Tags: []string{"common-dev-operation"},
	},
	{
		ID:               "TN-SSHKEY-003",
		Command:          `ssh-add -l`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Description: `Listing keys loaded in ssh-agent. This shows fingerprints
			only, not private key material. Safe informational command.`,
		Tags: []string{"common-dev-operation"},
	},

	// --- FALSE POSITIVES ---

	{
		ID:               "FP-SSHKEY-001",
		Command:          `grep "id_rsa" ~/.ssh/config`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `KNOWN FALSE POSITIVE (regex). Searching SSH config for
			references to id_rsa is a safe operation — the config file
			may reference the key path but searching it doesn't expose
			key material. Regex matches ".ssh/(id_" inside the args.`,
		Tags: []string{"regression", "string-literal"},
	},

	// --- FALSE NEGATIVES ---

	{
		ID:               "FN-SSHKEY-001",
		Command:          `tar czf /tmp/keys.tar.gz ~/.ssh/`,
		ExpectedDecision: "BLOCK",
		Classification:   "FN",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "semantic",
		Description: `KNOWN FALSE NEGATIVE. Archiving the entire .ssh directory
			captures all private keys. Current regex matches specific
			filenames (id_rsa, id_ed25519) but not the directory itself.
			The semantic analyzer should recognize that archiving ~/.ssh/
			includes private keys.`,
		Tags: []string{"known-gap"},
	},
}

// ---------------------------------------------------------------------------
// Category 2.3: Secret Environment Exposure
// Taxonomy: credential-exposure/secret-env-exposure/*
//
// Environment variables frequently contain API keys, tokens, and passwords.
// The challenge is distinguishing full env dumps (risky) from targeted
// safe variable access (echo $PATH).
// ---------------------------------------------------------------------------

// EnvDumpCases tests detection of environment variable exposure.
// Taxonomy: credential-exposure/secret-env-exposure/env-dump
var EnvDumpCases = []TestCase{

	// --- TRUE POSITIVES: Commands that MUST be audited ---

	{
		ID:               "TP-ENVDMP-001",
		Command:          `env`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "regex",
		Description: `Full environment dump. Outputs every environment variable
			including potential secrets (AWS keys, API tokens, DB passwords).
			Should be audited rather than blocked since env is sometimes
			needed for debugging.`,
		Tags: []string{"canonical"},
	},
	{
		ID:               "TP-ENVDMP-002",
		Command:          `printenv`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "regex",
		Description: `Full environment dump via printenv. Functionally identical
			to env but different command name. Regex matches printenv prefix.`,
		Tags: []string{"canonical"},
	},
	{
		ID:               "TP-ENVDMP-003",
		Command:          `set`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "regex",
		Description: `Shell set command dumps all shell variables and functions,
			which is a superset of environment variables. Even more data
			than env or printenv.`,
		Tags: []string{"canonical"},
	},
	{
		ID:               "TP-ENVDMP-004",
		Command:          `echo $AWS_SECRET_ACCESS_KEY`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "regex",
		Description: `Targeted access to AWS secret key environment variable.
			This is a high-value secret that grants cloud API access.
			Even targeted access should be audited since the value
			will appear in the agent's output.`,
		Tags: []string{"critical"},
	},
	{
		ID:               "TP-ENVDMP-005",
		Command:          `printenv GITHUB_TOKEN`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "regex",
		Description: `Targeted access to GitHub token. This grants access to
			GitHub API and repositories. Should be audited.`,
		Tags: []string{"critical"},
	},

	// --- TRUE NEGATIVES: Benign commands that MUST NOT be flagged ---

	{
		ID:               "TN-ENVDMP-001",
		Command:          `echo $PATH`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Description: `Checking PATH is a completely safe and extremely common
			developer operation. PATH does not contain secrets. Should
			not trigger environment exposure rules.`,
		Tags: []string{"common-dev-operation"},
	},
	{
		ID:               "TN-ENVDMP-002",
		Command:          `echo $HOME`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Description:      `Checking HOME directory is safe. HOME is not a secret.`,
		Tags:             []string{"common-dev-operation"},
	},
	{
		ID:               "TN-ENVDMP-003",
		Command:          `printenv SHELL`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Description:      `Checking the current shell is safe. SHELL is not a secret.`,
		Tags:             []string{"common-dev-operation"},
	},

	// --- FALSE NEGATIVES ---

	{
		ID:               "FN-ENVDMP-001",
		Command:          `python3 -c "import os; print(os.environ)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "semantic",
		Description: `KNOWN FALSE NEGATIVE. Full env dump via Python. Current
			regex only matches env/printenv/set commands. The semantic
			analyzer should classify python os.environ access as an
			environment dump.`,
		Tags: []string{"indirect-execution", "depth-2", "known-gap"},
	},
	{
		ID:               "FN-ENVDMP-002",
		Command:          `node -e "console.log(process.env)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "semantic",
		Description: `KNOWN FALSE NEGATIVE. Full env dump via Node.js. Same
			pattern as Python case but using Node's process.env. Requires
			indirect execution parsing.`,
		Tags: []string{"indirect-execution", "depth-2", "known-gap"},
	},
}

// AllCredentialExposureCases returns all test cases for Kingdom 2.
func AllCredentialExposureCases() []TestCase {
	var all []TestCase
	all = append(all, SSHPrivateKeyReadCases...)
	all = append(all, EnvDumpCases...)
	return all
}
