package analyzer

// Analyzer is the interface every analysis layer implements.
// Each analyzer receives the full AnalysisContext (original input + accumulated
// enrichments from prior layers) and returns zero or more Findings.
type Analyzer interface {
	// Name returns the analyzer's identifier (e.g., "regex", "structural", "semantic").
	Name() string

	// Analyze inspects the command and returns findings.
	// Analyzers may also enrich ctx (e.g., structural sets ctx.Parsed).
	Analyze(ctx *AnalysisContext) []Finding
}

// AnalysisContext carries the original input and accumulated enrichments
// through all analyzer layers. Every analyzer reads from and writes to this.
type AnalysisContext struct {
	RawCommand string
	Args       []string
	Cwd        string
	Paths      []string // filesystem paths extracted by normalizer
	Domains    []string // domains extracted by normalizer

	// Enrichments added by analyzers (downstream layers can read these)
	Parsed       *ParsedCommand  // set by structural analyzer
	Intents      []CommandIntent // set by semantic analyzer
	DataFlows    []DataFlow      // set by dataflow analyzer (Phase 3)
	SessionState *SessionState   // set by stateful analyzer (Phase 4)
}

// Finding is a single result from an analyzer.
type Finding struct {
	AnalyzerName string   // "regex", "structural", "semantic", etc.
	RuleID       string   // rule that produced this finding
	Decision     string   // "BLOCK", "AUDIT", "ALLOW"
	Confidence   float64  // 0.0–1.0, used by combiner for prioritization
	Reason       string   // human-readable explanation
	TaxonomyRef  string   // link to taxonomy entry
	Tags         []string // e.g., ["exfiltration", "credential-access"]
}

// ---------------------------------------------------------------------------
// ParsedCommand — produced by the structural analyzer
// ---------------------------------------------------------------------------

// ParsedCommand is the structural representation of a shell command.
// Produced by the structural analyzer for downstream layers to consume.
type ParsedCommand struct {
	// Segments are the pipeline-separated commands.
	// "curl ... | bash" → 2 segments.
	Segments []CommandSegment

	// Operators between segments: "|", "&&", "||", ";"
	Operators []string

	// Redirects at the top level (e.g., "> /dev/null")
	Redirects []Redirect

	// Subcommands found via indirect execution parsing (depth > 0).
	// E.g., for "bash -c 'rm -rf /'", the inner "rm -rf /" is a subcommand.
	Subcommands []*ParsedCommand
}

// CommandSegment is a single command within a pipeline.
type CommandSegment struct {
	Raw        string            // original text of this segment
	Executable string            // base command name (e.g., "rm", "curl")
	SubCommand string            // e.g., "install" for "npm install"
	Args       []string          // positional arguments
	Flags      map[string]string // normalized flags: key=flag name, value=flag value (or "")
	Redirects  []Redirect        // segment-level redirects
	IsShell    bool              // true if executable is a known shell interpreter
}

// Redirect represents a shell redirect operation.
type Redirect struct {
	Op   string // ">", ">>", "<", "2>"
	Path string // target path
}

// ---------------------------------------------------------------------------
// CommandIntent — produced by the semantic analyzer
// ---------------------------------------------------------------------------

// CommandIntent classifies a command's purpose using a security-relevant taxonomy.
type CommandIntent struct {
	Category   string  // e.g., "file-delete", "network-exfil", "code-execute"
	Risk       string  // "critical", "high", "medium", "low", "info"
	Confidence float64 // 0.0–1.0
	Segment    int     // which pipeline segment this applies to (-1 = whole command)
	Detail     string  // human-readable explanation
}

// ---------------------------------------------------------------------------
// DataFlow — produced by the dataflow analyzer (Phase 3 placeholder)
// ---------------------------------------------------------------------------

// DataFlow tracks data movement from source to sink through a command.
type DataFlow struct {
	Source    string // e.g., "/dev/zero", "~/.ssh/id_rsa", "env"
	Sink      string // e.g., "/dev/sda", "curl", "network"
	Transform string // e.g., "base64", "gzip", "pipe"
	Risk      string // "critical", "high", "medium", "low"
}

// ---------------------------------------------------------------------------
// SessionState — produced by the stateful analyzer (Phase 4 placeholder)
// ---------------------------------------------------------------------------

// SessionState tracks state across multiple commands in a session.
type SessionState struct {
	CommandCount  int
	RiskScore     float64
	AccessedPaths []string
}
