package mcp

import (
	"os"
	"testing"
)

func TestConfigGuard_BlockAgentShieldConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.agentshield/policy.yaml",
		"content": "defaults:\n  decision: ALLOW\n",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to AgentShield policy")
	}
	assertConfigCategory(t, result, "agentshield-config")
}

func TestConfigGuard_BlockMCPPolicyWrite(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("edit_file", map[string]interface{}{
		"path": home + "/.agentshield/mcp-policy.yaml",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to MCP policy")
	}
	assertConfigCategory(t, result, "agentshield-config")
}

func TestConfigGuard_BlockCursorMCPConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.cursor/mcp.json",
		"content": `{"mcpServers":{"evil":{"command":"evil-server"}}}`,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to Cursor MCP config")
	}
	assertConfigCategory(t, result, "ide-mcp-config")
}

func TestConfigGuard_BlockWindsurfHooks(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("create_file", map[string]interface{}{
		"path":    home + "/.codeium/windsurf/hooks.json",
		"content": "{}",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to Windsurf hooks")
	}
	assertConfigCategory(t, result, "ide-hooks")
}

func TestConfigGuard_BlockBashrc(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.bashrc",
		"content": "alias rm='rm -rf /'\n",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .bashrc")
	}
	assertConfigCategory(t, result, "shell-config")
}

func TestConfigGuard_BlockZshrc(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("edit_file", map[string]interface{}{
		"path": home + "/.zshrc",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .zshrc")
	}
	assertConfigCategory(t, result, "shell-config")
}

func TestConfigGuard_BlockNpmrc(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.npmrc",
		"content": "registry=https://evil.com/npm/\n",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .npmrc")
	}
	assertConfigCategory(t, result, "package-config")
}

func TestConfigGuard_BlockGitConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.gitconfig",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .gitconfig")
	}
	assertConfigCategory(t, result, "git-config")
}

func TestConfigGuard_BlockSSHConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("edit_file", map[string]interface{}{
		"path": home + "/.ssh/config",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to SSH config")
	}
	assertConfigCategory(t, result, "ssh-config")
}

func TestConfigGuard_BlockKubeConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.kube/config",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to kubeconfig")
	}
	assertConfigCategory(t, result, "kube-config")
}

func TestConfigGuard_BlockDockerConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.docker/config.json",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to Docker config")
	}
	assertConfigCategory(t, result, "docker-config")
}

func TestConfigGuard_BlockTildePath(t *testing.T) {
	// Tools might pass paths with ~ instead of expanded home
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": "~/.agentshield/policy.yaml",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — tilde path to AgentShield config")
	}
}

func TestConfigGuard_BlockPipConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.config/pip/pip.conf",
		"content": "[global]\nindex-url = https://evil.com/simple/\n",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to pip config")
	}
	assertConfigCategory(t, result, "package-config")
}

func TestConfigGuard_AllowProjectFiles(t *testing.T) {
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    "/Users/dev/myproject/src/main.go",
		"content": "package main\n",
	})
	if result.Blocked {
		t.Errorf("expected allowed — project file write, got: %v", result.Findings)
	}
}

func TestConfigGuard_AllowTmpFiles(t *testing.T) {
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    "/tmp/test.txt",
		"content": "hello",
	})
	if result.Blocked {
		t.Errorf("expected allowed — tmp file write, got: %v", result.Findings)
	}
}

func TestConfigGuard_AllowNonPathArguments(t *testing.T) {
	result := CheckConfigGuard("get_weather", map[string]interface{}{
		"location": "New York",
		"units":    "celsius",
	})
	if result.Blocked {
		t.Errorf("expected allowed — no paths in arguments, got: %v", result.Findings)
	}
}

func TestConfigGuard_EmptyArguments(t *testing.T) {
	result := CheckConfigGuard("noop", map[string]interface{}{})
	if result.Blocked {
		t.Error("expected allowed — empty arguments")
	}
}

func TestConfigGuard_NilArguments(t *testing.T) {
	result := CheckConfigGuard("noop", nil)
	if result.Blocked {
		t.Error("expected allowed — nil arguments")
	}
}

func TestConfigGuard_NestedPathArgument(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("complex_tool", map[string]interface{}{
		"config": map[string]interface{}{
			"target": home + "/.bashrc",
		},
	})
	if !result.Blocked {
		t.Fatal("expected blocked — nested path to .bashrc")
	}
	assertConfigCategory(t, result, "shell-config")
}

func TestConfigGuard_AgentShieldSubdir(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.agentshield/packs/evil.yaml",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to AgentShield packs directory")
	}
	assertConfigCategory(t, result, "agentshield-config")
}

func assertConfigCategory(t *testing.T, result ConfigGuardResult, category string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.Category == category {
			return
		}
	}
	var found []string
	for _, f := range result.Findings {
		found = append(found, f.Category+": "+f.Reason)
	}
	t.Errorf("expected category %s, got: %v", category, found)
}
