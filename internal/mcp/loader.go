package mcp

import (
	"os"

	"github.com/gzhole/agentshield/internal/policy"
	"gopkg.in/yaml.v3"
)

// DefaultMCPPolicyFile is the filename for MCP-specific policy within ~/.agentshield/.
const DefaultMCPPolicyFile = "mcp-policy.yaml"

// LoadMCPPolicy reads an MCP policy from the given YAML file path.
// If the file doesn't exist, returns a sensible default policy.
func LoadMCPPolicy(path string) (*MCPPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultMCPPolicy(), nil
		}
		return nil, err
	}

	var p MCPPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	if p.Defaults.Decision == "" {
		p.Defaults.Decision = policy.DecisionAudit
	}

	return &p, nil
}

// DefaultMCPPolicy returns a reasonable default MCP security policy.
// Blocks known-dangerous tool patterns and audits everything else.
func DefaultMCPPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{
			"execute_command",
			"run_shell",
			"run_terminal_command",
			"shell_exec",
		},
		Rules: []MCPRule{
			{
				ID: "block-write-sensitive-paths",
				Match: MCPMatch{
					ToolNameAny:      []string{"write_file", "create_file", "edit_file"},
					ArgumentPatterns: map[string]string{"path": "/etc/**"},
				},
				Decision: policy.DecisionBlock,
				Reason:   "File write to system directories is blocked.",
			},
			{
				ID: "block-ssh-access",
				Match: MCPMatch{
					ToolNameAny: []string{"read_file", "write_file", "cat_file", "create_file"},
					ArgumentPatterns: map[string]string{
						"path": "**/.ssh/**",
					},
				},
				Decision: policy.DecisionBlock,
				Reason:   "Access to SSH key directories is blocked.",
			},
			{
				ID: "block-credential-access",
				Match: MCPMatch{
					ToolNameAny: []string{"read_file", "write_file", "cat_file", "create_file"},
					ArgumentPatterns: map[string]string{
						"path": "**/.aws/**",
					},
				},
				Decision: policy.DecisionBlock,
				Reason:   "Access to cloud credential directories is blocked.",
			},
		},
	}
}
