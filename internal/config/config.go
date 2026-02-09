package config

import (
	"os"
	"path/filepath"
)

const (
	DefaultConfigDir  = ".agentshield"
	DefaultPolicyFile = "policy.yaml"
	DefaultLogFile    = "audit.jsonl"
)

type Config struct {
	PolicyPath string
	LogPath    string
	Mode       string
	ConfigDir  string
	Analyzer   AnalyzerConfig
}

// AnalyzerConfig controls the multi-layer analyzer pipeline.
type AnalyzerConfig struct {
	// EnabledAnalyzers lists which analyzers to run. Default: ["regex", "structural", "semantic"].
	EnabledAnalyzers []string
	// CombineStrategy controls how findings are merged. Default: "most_restrictive".
	CombineStrategy string
	// MaxParseDepth controls indirect execution parsing depth. Default: 2.
	MaxParseDepth int
}

// DefaultAnalyzerConfig returns the default analyzer configuration.
func DefaultAnalyzerConfig() AnalyzerConfig {
	return AnalyzerConfig{
		EnabledAnalyzers: []string{"regex", "structural", "semantic"},
		CombineStrategy:  "most_restrictive",
		MaxParseDepth:    2,
	}
}

func Load(policyPath, logPath, mode string) (*Config, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configDir := filepath.Join(homeDir, DefaultConfigDir)

	if err := ensureDir(configDir); err != nil {
		return nil, err
	}

	cfg := &Config{
		ConfigDir: configDir,
		Mode:      mode,
		Analyzer:  DefaultAnalyzerConfig(),
	}

	if policyPath != "" {
		cfg.PolicyPath = policyPath
	} else {
		cfg.PolicyPath = filepath.Join(configDir, DefaultPolicyFile)
	}

	if logPath != "" {
		cfg.LogPath = logPath
	} else {
		cfg.LogPath = filepath.Join(configDir, DefaultLogFile)
	}

	return cfg, nil
}

func ensureDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0700)
	}
	return nil
}
