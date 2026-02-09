package policy

type Decision string

const (
	DecisionAllow Decision = "ALLOW"
	DecisionAudit Decision = "AUDIT"
	DecisionBlock Decision = "BLOCK"
)

type Policy struct {
	Version  string   `yaml:"version"`
	Defaults Defaults `yaml:"defaults"`
	Network  Network  `yaml:"network"`
	Rules    []Rule   `yaml:"rules"`
}

type Defaults struct {
	Decision       Decision `yaml:"decision"`
	NonInteractive Decision `yaml:"non_interactive"`
	LogRedaction   bool     `yaml:"log_redaction"`
	ProtectedPaths []string `yaml:"protected_paths"`
}

type Network struct {
	AllowDomains []string `yaml:"allow_domains"`
}

type Rule struct {
	ID         string   `yaml:"id"`
	Taxonomy   string   `yaml:"taxonomy,omitempty"`
	Match      Match    `yaml:"match"`
	Decision   Decision `yaml:"decision"`
	Confidence float64  `yaml:"confidence,omitempty"`
	Reason     string   `yaml:"reason"`
}

type Match struct {
	CommandExact  string           `yaml:"command_exact,omitempty"`
	CommandPrefix []string         `yaml:"command_prefix,omitempty"`
	CommandRegex  string           `yaml:"command_regex,omitempty"`
	Structural    *StructuralMatch `yaml:"structural,omitempty"`
}

// StructuralMatch defines a rule that matches against the parsed shell AST
// rather than raw command strings. This is more robust than regex because
// it handles flag reordering, sudo wrapping, and long-form flags.
type StructuralMatch struct {
	// Command identification
	Executable StringOrList `yaml:"executable,omitempty"` // exact match: "rm" or ["rm", "unlink"]
	SubCommand string       `yaml:"subcommand,omitempty"` // e.g., "install" for "npm install"

	// Flag predicates (short or long form, e.g., "r" matches both -r and --recursive)
	FlagsAll  []string `yaml:"flags_all,omitempty"`  // must have ALL of these
	FlagsAny  []string `yaml:"flags_any,omitempty"`  // must have at least ONE
	FlagsNone []string `yaml:"flags_none,omitempty"` // must NOT have any of these

	// Argument predicates (glob patterns on positional args)
	ArgsAny  []string `yaml:"args_any,omitempty"`  // any positional arg matches any glob
	ArgsNone []string `yaml:"args_none,omitempty"` // no positional arg matches any of these

	// Pipe analysis
	HasPipe  *bool    `yaml:"has_pipe,omitempty"`  // command contains a pipe operator
	PipeTo   []string `yaml:"pipe_to,omitempty"`   // RHS of pipe is one of these executables
	PipeFrom []string `yaml:"pipe_from,omitempty"` // LHS of pipe is one of these executables

	// Modifiers
	Negate bool `yaml:"negate,omitempty"` // invert match (for ALLOW overrides)
}

// StringOrList allows YAML fields to accept either a single string or a list.
// "rm" → ["rm"], ["rm", "unlink"] → ["rm", "unlink"]
type StringOrList []string

func (s *StringOrList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var single string
	if err := unmarshal(&single); err == nil {
		*s = []string{single}
		return nil
	}
	var list []string
	if err := unmarshal(&list); err != nil {
		return err
	}
	*s = list
	return nil
}

type EvalResult struct {
	Decision       Decision
	TriggeredRules []string
	Reasons        []string
	Explanation    string
}
