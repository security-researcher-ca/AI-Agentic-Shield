package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	unicheck "github.com/gzhole/agentshield/internal/unicode"
)

type Engine struct {
	policy  *Policy
	homeDir string
}

func NewEngine(p *Policy) (*Engine, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = ""
	}
	return &Engine{policy: p, homeDir: homeDir}, nil
}

func (e *Engine) Evaluate(command string, paths []string) EvalResult {
	result := EvalResult{
		Decision:       e.policy.Defaults.Decision,
		TriggeredRules: []string{},
		Reasons:        []string{},
	}

	// Built-in: Unicode smuggling detection (runs before all rules)
	uniScan := unicheck.Scan(command)
	if !uniScan.Clean {
		hasBlockLevel := false
		for _, threat := range uniScan.Threats {
			result.TriggeredRules = append(result.TriggeredRules, "unicode-"+threat.Category)
			result.Reasons = append(result.Reasons, threat.Description)
			if threat.Severity == "block" {
				hasBlockLevel = true
			}
		}
		if hasBlockLevel {
			result.Decision = DecisionBlock
		} else {
			result.Decision = DecisionAudit
		}
		result.Explanation = buildExplanation(result)
		return result
	}

	if blocked, rule := e.checkProtectedPaths(paths); blocked {
		result.Decision = DecisionBlock
		result.TriggeredRules = append(result.TriggeredRules, "protected-path")
		result.Reasons = append(result.Reasons, fmt.Sprintf("Access to protected path denied: %s", rule))
		result.Explanation = buildExplanation(result)
		return result
	}

	for _, rule := range e.policy.Rules {
		if e.matchRule(command, rule) {
			result.Decision = rule.Decision
			result.TriggeredRules = append(result.TriggeredRules, rule.ID)
			result.Reasons = append(result.Reasons, rule.Reason)
			result.Explanation = buildExplanation(result)
			return result
		}
	}

	result.Explanation = buildExplanation(result)
	return result
}

func (e *Engine) matchRule(command string, rule Rule) bool {
	if rule.Match.CommandExact != "" {
		if command == rule.Match.CommandExact {
			return true
		}
	}

	for _, prefix := range rule.Match.CommandPrefix {
		if strings.HasPrefix(command, prefix) {
			return true
		}
	}

	if rule.Match.CommandRegex != "" {
		re, err := regexp.Compile(rule.Match.CommandRegex)
		if err == nil && re.MatchString(command) {
			return true
		}
	}

	return false
}

func (e *Engine) checkProtectedPaths(paths []string) (bool, string) {
	for _, path := range paths {
		expandedPath := e.expandPath(path)
		for _, pattern := range e.policy.Defaults.ProtectedPaths {
			expandedPattern := e.expandPath(pattern)
			if matchGlob(expandedPath, expandedPattern) {
				return true, pattern
			}
		}
	}
	return false, ""
}

func (e *Engine) expandPath(path string) string {
	if strings.HasPrefix(path, "~/") && e.homeDir != "" {
		return filepath.Join(e.homeDir, path[2:])
	}
	if strings.HasPrefix(path, "~") && e.homeDir != "" {
		return e.homeDir
	}
	return path
}

func matchGlob(path, pattern string) bool {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(path, prefix+"/") {
			return false
		}
		remainder := strings.TrimPrefix(path, prefix+"/")
		return !strings.Contains(remainder, "/")
	}

	matched, _ := filepath.Match(pattern, path)
	return matched
}

func buildExplanation(result EvalResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Decision: %s\n", result.Decision))

	if len(result.TriggeredRules) > 0 {
		sb.WriteString(fmt.Sprintf("Triggered rules: %s\n", strings.Join(result.TriggeredRules, ", ")))
	}

	if len(result.Reasons) > 0 {
		sb.WriteString("Reasons:\n")
		for _, reason := range result.Reasons {
			sb.WriteString(fmt.Sprintf("  - %s\n", reason))
		}
	}

	return sb.String()
}
