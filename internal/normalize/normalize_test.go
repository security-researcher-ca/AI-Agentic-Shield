package normalize

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalize_RelativePathExpansion(t *testing.T) {
	cwd := "/home/user/project"
	args := []string{"cat", "../secrets.txt"}

	nc := Normalize(args, cwd)

	expected := "/home/user/secrets.txt"
	if len(nc.Paths) != 1 || nc.Paths[0] != expected {
		t.Errorf("expected path %q, got %v", expected, nc.Paths)
	}
}

func TestNormalize_TildeExpansion(t *testing.T) {
	homeDir, _ := os.UserHomeDir()
	cwd := "/tmp"
	args := []string{"cat", "~/.ssh/id_rsa"}

	nc := Normalize(args, cwd)

	expected := filepath.Join(homeDir, ".ssh/id_rsa")
	if len(nc.Paths) != 1 || nc.Paths[0] != expected {
		t.Errorf("expected path %q, got %v", expected, nc.Paths)
	}
}

func TestNormalize_CurlDomainExtraction(t *testing.T) {
	cwd := "/tmp"
	args := []string{"curl", "https://example.com/file.txt"}

	nc := Normalize(args, cwd)

	if len(nc.Domains) != 1 || nc.Domains[0] != "example.com" {
		t.Errorf("expected domain 'example.com', got %v", nc.Domains)
	}
}

func TestNormalize_WgetDomainExtraction(t *testing.T) {
	cwd := "/tmp"
	args := []string{"wget", "-O", "file.sh", "https://malicious.site/install.sh"}

	nc := Normalize(args, cwd)

	if len(nc.Domains) != 1 || nc.Domains[0] != "malicious.site" {
		t.Errorf("expected domain 'malicious.site', got %v", nc.Domains)
	}
}

func TestNormalize_GitCloneHTTPS(t *testing.T) {
	cwd := "/tmp"
	args := []string{"git", "clone", "https://github.com/org/repo.git"}

	nc := Normalize(args, cwd)

	if len(nc.Domains) != 1 || nc.Domains[0] != "github.com" {
		t.Errorf("expected domain 'github.com', got %v", nc.Domains)
	}
}

func TestNormalize_GitCloneSSH(t *testing.T) {
	cwd := "/tmp"
	args := []string{"git", "clone", "git@github.com:org/repo.git"}

	nc := Normalize(args, cwd)

	if len(nc.Domains) != 1 || nc.Domains[0] != "github.com" {
		t.Errorf("expected domain 'github.com', got %v", nc.Domains)
	}
}

func TestNormalize_Executable(t *testing.T) {
	cwd := "/tmp"

	tests := []struct {
		args     []string
		expected string
	}{
		{[]string{"ls", "-la"}, "ls"},
		{[]string{"/usr/bin/cat", "file.txt"}, "cat"},
		{[]string{"./script.sh"}, "script.sh"},
	}

	for _, tt := range tests {
		nc := Normalize(tt.args, cwd)
		if nc.Executable != tt.expected {
			t.Errorf("args %v: expected executable %q, got %q", tt.args, tt.expected, nc.Executable)
		}
	}
}

func TestNormalize_IgnoresFlags(t *testing.T) {
	cwd := "/tmp"
	args := []string{"rm", "-rf", "--verbose", "./target"}

	nc := Normalize(args, cwd)

	if len(nc.Paths) != 1 {
		t.Errorf("expected 1 path, got %d: %v", len(nc.Paths), nc.Paths)
	}
}
