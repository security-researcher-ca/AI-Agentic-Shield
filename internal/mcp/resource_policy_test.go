package mcp

import (
	"os"
	"testing"

	"github.com/gzhole/agentshield/internal/policy"
)

func testResourcePolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		BlockedResources: []string{
			"secret://*",
		},
		ResourceRules: []ResourceRule{
			{
				ID:       "block-postgres",
				Match:    ResourceMatch{Scheme: "postgres"},
				Decision: policy.DecisionBlock,
				Reason:   "Direct database access is blocked.",
			},
			{
				ID:       "block-ssh-file",
				Match:    ResourceMatch{URIRegex: `.ssh`},
				Decision: policy.DecisionBlock,
				Reason:   "SSH key resources are blocked.",
			},
		},
	}
}

func TestResourcePolicy_DefaultAudit(t *testing.T) {
	evaluator := NewPolicyEvaluator(testResourcePolicy())
	result := evaluator.EvaluateResourceRead("https://api.example.com/data")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for unmatched URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_BlockedResourcePattern(t *testing.T) {
	evaluator := NewPolicyEvaluator(testResourcePolicy())
	result := evaluator.EvaluateResourceRead("secret://api-key-123")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for secret:// URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_BlockByScheme(t *testing.T) {
	evaluator := NewPolicyEvaluator(testResourcePolicy())
	result := evaluator.EvaluateResourceRead("postgres://user:pass@prod-db:5432/mydb")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for postgres:// URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_BlockByRegex(t *testing.T) {
	evaluator := NewPolicyEvaluator(testResourcePolicy())
	result := evaluator.EvaluateResourceRead("file:///home/user/.ssh/id_rsa")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for SSH key URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_ConfigGuardOnFileURI(t *testing.T) {
	home := os.Getenv("HOME")
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	})

	// file:// URI pointing to AgentShield config should be blocked by config guard
	result := evaluator.EvaluateResourceRead("file://" + home + "/.agentshield/policy.yaml")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for file:// to AgentShield config, got %s", result.Decision)
	}
}

func TestResourcePolicy_AllowSafeURI(t *testing.T) {
	evaluator := NewPolicyEvaluator(testResourcePolicy())
	result := evaluator.EvaluateResourceRead("https://docs.example.com/readme")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for safe URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_NilPolicy(t *testing.T) {
	evaluator := NewPolicyEvaluator(nil)
	result := evaluator.EvaluateResourceRead("https://example.com/data")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT default, got %s", result.Decision)
	}
}
