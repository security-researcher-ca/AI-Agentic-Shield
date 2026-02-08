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
	ID       string   `yaml:"id"`
	Match    Match    `yaml:"match"`
	Decision Decision `yaml:"decision"`
	Reason   string   `yaml:"reason"`
}

type Match struct {
	CommandExact  string   `yaml:"command_exact,omitempty"`
	CommandPrefix []string `yaml:"command_prefix,omitempty"`
	CommandRegex  string   `yaml:"command_regex,omitempty"`
}

type EvalResult struct {
	Decision       Decision
	TriggeredRules []string
	Reasons        []string
	Explanation    string
}
