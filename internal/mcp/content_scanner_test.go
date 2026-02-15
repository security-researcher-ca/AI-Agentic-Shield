package mcp

import (
	"strings"
	"testing"
)

func TestContentScan_CleanArguments(t *testing.T) {
	result := ScanToolCallContent("get_weather", map[string]interface{}{
		"location": "New York City",
		"units":    "celsius",
	})
	if result.Blocked {
		t.Errorf("expected clean args, got blocked with findings: %v", result.Findings)
	}
}

func TestContentScan_SSHPrivateKey(t *testing.T) {
	result := ScanToolCallContent("send_message", map[string]interface{}{
		"to":      "user@example.com",
		"subject": "Hello",
		"body":    "Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — SSH private key in argument")
	}
	assertContentSignal(t, result, SignalPrivateKey)
}

func TestContentScan_AWSAccessKey(t *testing.T) {
	result := ScanToolCallContent("add", map[string]interface{}{
		"a":        1,
		"b":        2,
		"sidenote": "AKIAIOSFODNN7EXAMPLE",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — AWS access key in sidenote")
	}
	assertContentSignal(t, result, SignalAWSCredential)
}

func TestContentScan_AWSSecretAssignment(t *testing.T) {
	result := ScanToolCallContent("calculator", map[string]interface{}{
		"context": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — AWS secret in argument")
	}
	assertContentSignal(t, result, SignalAWSCredential)
}

func TestContentScan_GitHubToken(t *testing.T) {
	result := ScanToolCallContent("search", map[string]interface{}{
		"query":   "test",
		"context": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — GitHub token")
	}
	assertContentSignal(t, result, SignalGitHubToken)
}

func TestContentScan_BearerToken(t *testing.T) {
	result := ScanToolCallContent("fetch", map[string]interface{}{
		"url":     "https://api.example.com/data",
		"headers": "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — bearer token")
	}
	assertContentSignal(t, result, SignalBearerToken)
}

func TestContentScan_BasicAuthURL(t *testing.T) {
	result := ScanToolCallContent("fetch", map[string]interface{}{
		"url": "https://admin:s3cret_p4ss@internal-api.company.com/data",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — basic auth in URL")
	}
	assertContentSignal(t, result, SignalBasicAuth)
}

func TestContentScan_StripeKey(t *testing.T) {
	result := ScanToolCallContent("payment", map[string]interface{}{
		"key": "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — Stripe secret key")
	}
	assertContentSignal(t, result, SignalStripeKey)
}

func TestContentScan_GenericAPIKey(t *testing.T) {
	result := ScanToolCallContent("config", map[string]interface{}{
		"data": "api_key=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — generic API key")
	}
	assertContentSignal(t, result, SignalGenericSecret)
}

func TestContentScan_EnvFileContent(t *testing.T) {
	envContent := `DATABASE_URL=postgres://user:pass@host:5432/db
API_KEY=sk-1234567890abcdef
SECRET_KEY=mysupersecretvalue
REDIS_URL=redis://localhost:6379`

	result := ScanToolCallContent("write_file", map[string]interface{}{
		"path":    "/tmp/test.env",
		"content": envContent,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — .env file content with secrets")
	}
	assertContentSignal(t, result, SignalEnvFileContent)
}

func TestContentScan_LargeBase64Blob(t *testing.T) {
	// Generate a large base64-looking string (simulating exfiltrated file content)
	blob := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 5)

	result := ScanToolCallContent("add", map[string]interface{}{
		"a":        1,
		"b":        2,
		"sidenote": blob,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — large base64 blob in sidenote")
	}
	assertContentSignal(t, result, SignalBase64Blob)
}

func TestContentScan_NestedArguments(t *testing.T) {
	result := ScanToolCallContent("complex_tool", map[string]interface{}{
		"config": map[string]interface{}{
			"auth": "-----BEGIN OPENSSH PRIVATE KEY-----\nbase64data\n-----END OPENSSH PRIVATE KEY-----",
		},
	})
	if !result.Blocked {
		t.Fatal("expected blocked — private key in nested argument")
	}
	assertContentSignal(t, result, SignalPrivateKey)
}

func TestContentScan_WhatsAppExfiltration(t *testing.T) {
	// Real-world attack pattern: WhatsApp MCP exfiltration
	// The agent reads SSH keys and passes them as a "sidenote" parameter
	result := ScanToolCallContent("add", map[string]interface{}{
		"a":        42,
		"b":        13,
		"sidenote": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoRBh2vHKSl0tkjyPFOExrr\nnG5ka15mMNHMdF+E0k0XavSmGvh97PmYbvfJNY5tCl8JjF8T7LMbGMXQ\n-----END RSA PRIVATE KEY-----",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — WhatsApp-style SSH key exfiltration via sidenote")
	}
	assertContentSignal(t, result, SignalPrivateKey)
}

func TestContentScan_SlackToken(t *testing.T) {
	result := ScanToolCallContent("notify", map[string]interface{}{
		"token": "xoxb-" + "1234567890123-" + "1234567890123-" + "ABCdefGHIjklMNOpqrSTUvwx",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — Slack token")
	}
	assertContentSignal(t, result, SignalSlackToken)
}

func TestContentScan_SafeBase64(t *testing.T) {
	// Short base64 should NOT trigger (could be a legitimate small payload)
	result := ScanToolCallContent("encode", map[string]interface{}{
		"data": "SGVsbG8gV29ybGQ=", // "Hello World"
	})
	if result.Blocked {
		t.Errorf("short base64 should not trigger, got: %v", result.Findings)
	}
}

func TestContentScan_NormalTextNotBlocked(t *testing.T) {
	result := ScanToolCallContent("write_file", map[string]interface{}{
		"path":    "/tmp/readme.md",
		"content": "# My Project\n\nThis is a normal README file with regular text content.\nIt has multiple lines but no secrets.\n\n## Installation\n\nnpm install my-package",
	})
	if result.Blocked {
		t.Errorf("normal text should not be blocked, got: %v", result.Findings)
	}
}

func TestContentScan_EmptyArguments(t *testing.T) {
	result := ScanToolCallContent("noop", map[string]interface{}{})
	if result.Blocked {
		t.Error("empty arguments should not be blocked")
	}
}

func TestContentScan_NilArguments(t *testing.T) {
	result := ScanToolCallContent("noop", nil)
	if result.Blocked {
		t.Error("nil arguments should not be blocked")
	}
}

func assertContentSignal(t *testing.T, result ContentScanResult, signal ContentSignal) {
	t.Helper()
	for _, f := range result.Findings {
		if f.Signal == signal {
			return
		}
	}
	var found []string
	for _, f := range result.Findings {
		found = append(found, string(f.Signal)+": "+f.Detail)
	}
	t.Errorf("expected signal %s, got: %v", signal, found)
}
