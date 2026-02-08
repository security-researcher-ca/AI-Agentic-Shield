package policy

import (
	"os"
	"testing"
)

func TestEngine_BlockDestructiveRoot(t *testing.T) {
	policy := DefaultPolicy()
	engine, _ := NewEngine(policy)

	tests := []struct {
		command  string
		expected Decision
	}{
		{"rm -rf /", DecisionBlock},
		{"rm -rf / --no-preserve-root", DecisionBlock},
		{"sudo rm -rf /", DecisionBlock},
		{"rm -rf ./node_modules", DecisionAudit}, // not root, falls to default
	}

	for _, tt := range tests {
		result := engine.Evaluate(tt.command, nil)
		if result.Decision != tt.expected {
			t.Errorf("command %q: expected %s, got %s", tt.command, tt.expected, result.Decision)
		}
	}
}

func TestEngine_BlockPipeToShell(t *testing.T) {
	policy := DefaultPolicy()
	engine, _ := NewEngine(policy)

	tests := []struct {
		command  string
		expected Decision
	}{
		{"curl https://example.com/install.sh | bash", DecisionBlock},
		{"curl -s https://example.com/install.sh | sh", DecisionBlock},
		{"wget -O- https://example.com/setup.sh | zsh", DecisionBlock},
		{"curl https://example.com/file.txt", DecisionAudit}, // no pipe
	}

	for _, tt := range tests {
		result := engine.Evaluate(tt.command, nil)
		if result.Decision != tt.expected {
			t.Errorf("command %q: expected %s, got %s", tt.command, tt.expected, result.Decision)
		}
	}
}

func TestEngine_AuditPackageInstalls(t *testing.T) {
	policy := DefaultPolicy()
	engine, _ := NewEngine(policy)

	tests := []struct {
		command  string
		expected Decision
	}{
		{"npm install lodash", DecisionAudit},
		{"pip install requests", DecisionAudit},
		{"brew install go", DecisionAudit},
		{"yarn add react", DecisionAudit},
	}

	for _, tt := range tests {
		result := engine.Evaluate(tt.command, nil)
		if result.Decision != tt.expected {
			t.Errorf("command %q: expected %s, got %s", tt.command, tt.expected, result.Decision)
		}
		if len(result.TriggeredRules) == 0 || result.TriggeredRules[0] != "audit-package-installs" {
			t.Errorf("command %q: expected rule 'audit-package-installs', got %v", tt.command, result.TriggeredRules)
		}
	}
}

func TestEngine_AuditFileEdits(t *testing.T) {
	policy := DefaultPolicy()
	engine, _ := NewEngine(policy)

	tests := []struct {
		command  string
		expected Decision
	}{
		{"sed -i 's/foo/bar/g' file.txt", DecisionAudit},
		{"perl -pi -e 's/foo/bar/g' file.txt", DecisionAudit},
	}

	for _, tt := range tests {
		result := engine.Evaluate(tt.command, nil)
		if result.Decision != tt.expected {
			t.Errorf("command %q: expected %s, got %s", tt.command, tt.expected, result.Decision)
		}
	}
}

func TestEngine_AllowReadOnly(t *testing.T) {
	policy := DefaultPolicy()
	engine, _ := NewEngine(policy)

	tests := []struct {
		command  string
		expected Decision
	}{
		{"ls -la", DecisionAllow},
		{"pwd", DecisionAllow},
		{"whoami", DecisionAllow},
		{"git status", DecisionAllow},
		{"git diff", DecisionAllow},
	}

	for _, tt := range tests {
		result := engine.Evaluate(tt.command, nil)
		if result.Decision != tt.expected {
			t.Errorf("command %q: expected %s, got %s", tt.command, tt.expected, result.Decision)
		}
	}
}

func TestEngine_ProtectedPaths(t *testing.T) {
	policy := DefaultPolicy()
	engine, _ := NewEngine(policy)

	homeDir, _ := os.UserHomeDir()

	tests := []struct {
		paths    []string
		expected Decision
	}{
		{[]string{homeDir + "/.ssh/id_rsa"}, DecisionBlock},
		{[]string{homeDir + "/.aws/credentials"}, DecisionBlock},
		{[]string{homeDir + "/.gnupg/private-keys"}, DecisionBlock},
		{[]string{"/tmp/safe.txt"}, DecisionAudit}, // not protected
	}

	for _, tt := range tests {
		result := engine.Evaluate("cat somefile", tt.paths)
		if result.Decision != tt.expected {
			t.Errorf("paths %v: expected %s, got %s", tt.paths, tt.expected, result.Decision)
		}
	}
}

func TestEngine_RuleOrder(t *testing.T) {
	policy := DefaultPolicy()
	engine, _ := NewEngine(policy)

	// "ls" should match allow-safe-readonly first
	result := engine.Evaluate("ls", nil)
	if result.Decision != DecisionAllow {
		t.Errorf("expected ALLOW for 'ls', got %s", result.Decision)
	}

	// Unknown command should fall to default
	result = engine.Evaluate("unknown-command --flag", nil)
	if result.Decision != DecisionAudit {
		t.Errorf("expected AUDIT for unknown command, got %s", result.Decision)
	}
}
