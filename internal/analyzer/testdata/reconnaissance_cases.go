package testdata

// ===========================================================================
// Kingdom 8 (*): Reconnaissance & Discovery
// ===========================================================================
//
// These tests validate detection of commands that enumerate systems,
// discover sensitive files, or gather information for lateral movement.
//
// Test count targets (medium priority = 5 per weakness):
//   - Category 8.1 System Enumeration: network-scanning (5)

// NetworkScanningCases tests detection of network scanning/enumeration.
var NetworkScanningCases = []TestCase{

	// --- TRUE POSITIVES ---

	{
		ID:               "TP-NETSCAN-001",
		Command:          `nmap -sV 192.168.1.0/24`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "reconnaissance/system-enum/network-scanning",
		Analyzer:         "semantic",
		Description: `Network service version scan of a subnet. nmap scans all
			hosts on the network and identifies running services. This
			is a classic reconnaissance technique. Should be audited
			to flag potential lateral movement preparation.`,
		Tags: []string{"canonical"},
	},
	{
		ID:               "TP-NETSCAN-002",
		Command:          `netstat -tulpn`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "reconnaissance/system-enum/network-scanning",
		Analyzer:         "semantic",
		Description: `Listing all listening TCP/UDP ports. Reveals which services
			are running and on which ports. Useful for network mapping.
			Should be audited.`,
		Tags: []string{"canonical"},
	},

	// --- TRUE NEGATIVES ---

	{
		ID:               "TN-NETSCAN-001",
		Command:          `ping -c 3 google.com`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "reconnaissance/system-enum/network-scanning",
		Description: `Simple connectivity check via ping. This is a basic
			networking diagnostic tool used by every developer. Should
			not be flagged as reconnaissance.`,
		Tags: []string{"common-dev-operation"},
	},
	{
		ID:               "TN-NETSCAN-002",
		Command:          `curl -I https://api.example.com`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "reconnaissance/system-enum/network-scanning",
		Description: `HTTP HEAD request to check API availability. This is a
			standard developer operation for testing endpoints. Should
			be audited (network egress) but not flagged as scanning.`,
		Tags: []string{"common-dev-operation"},
	},

	// --- FALSE NEGATIVES ---

	{
		ID:               "FN-NETSCAN-001",
		Command:          `for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i; done`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "reconnaissance/system-enum/network-scanning",
		Analyzer:         "structural",
		Description: `KNOWN FALSE NEGATIVE. Ping sweep using a shell loop. This
			scans an entire subnet using only ping (no nmap needed).
			Current rules don't detect loop-based scanning. The structural
			analyzer should detect loop constructs with network commands.`,
		Tags: []string{"known-gap", "evasion"},
	},
}

// AllReconnaissanceCases returns all test cases for Kingdom 8.
func AllReconnaissanceCases() []TestCase {
	var all []TestCase
	all = append(all, NetworkScanningCases...)
	return all
}
