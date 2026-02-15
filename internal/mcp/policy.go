package mcp

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gzhole/agentshield/internal/policy"
)

// MCPPolicy defines MCP-specific security policy loaded from YAML.
type MCPPolicy struct {
	Defaults         MCPDefaults    `yaml:"defaults"`
	BlockedTools     []string       `yaml:"blocked_tools,omitempty"`
	BlockedResources []string       `yaml:"blocked_resources,omitempty"`
	Rules            []MCPRule      `yaml:"rules,omitempty"`
	ResourceRules    []ResourceRule `yaml:"resource_rules,omitempty"`
}

// MCPDefaults defines the default decision for MCP tool calls.
type MCPDefaults struct {
	Decision policy.Decision `yaml:"decision"`
}

// MCPRule defines a single MCP policy rule.
type MCPRule struct {
	ID       string          `yaml:"id"`
	Match    MCPMatch        `yaml:"match"`
	Decision policy.Decision `yaml:"decision"`
	Reason   string          `yaml:"reason"`
}

// ResourceRule defines a rule for resources/read requests.
type ResourceRule struct {
	ID       string          `yaml:"id"`
	Match    ResourceMatch   `yaml:"match"`
	Decision policy.Decision `yaml:"decision"`
	Reason   string          `yaml:"reason"`
}

// ResourceMatch defines conditions for a resource rule.
type ResourceMatch struct {
	URIPattern string `yaml:"uri_pattern,omitempty"` // glob pattern on URI
	URIRegex   string `yaml:"uri_regex,omitempty"`   // regex on URI
	Scheme     string `yaml:"scheme,omitempty"`      // exact scheme match (file, postgres, etc.)
}

// MCPMatch defines the conditions for an MCP rule to trigger.
type MCPMatch struct {
	ToolName         string            `yaml:"tool_name,omitempty"`         // exact tool name
	ToolNameRegex    string            `yaml:"tool_name_regex,omitempty"`   // regex on tool name
	ToolNameAny      []string          `yaml:"tool_name_any,omitempty"`     // any of these tool names
	ArgumentPatterns map[string]string `yaml:"argument_patterns,omitempty"` // key=arg name, value=glob pattern on arg value
}

// MCPEvalResult holds the outcome of evaluating an MCP tool call.
type MCPEvalResult struct {
	Decision       policy.Decision
	TriggeredRules []string
	Reasons        []string
}

// PolicyEvaluator evaluates MCP tool calls against an MCPPolicy.
type PolicyEvaluator struct {
	policy *MCPPolicy
}

// NewPolicyEvaluator creates a new evaluator from the given MCP policy.
func NewPolicyEvaluator(p *MCPPolicy) *PolicyEvaluator {
	if p == nil {
		p = &MCPPolicy{
			Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		}
	}
	if p.Defaults.Decision == "" {
		p.Defaults.Decision = policy.DecisionAudit
	}
	return &PolicyEvaluator{policy: p}
}

// EvaluateToolCall checks a tool call against the MCP policy.
// Returns the most restrictive matching decision.
func (e *PolicyEvaluator) EvaluateToolCall(toolName string, arguments map[string]interface{}) MCPEvalResult {
	result := MCPEvalResult{
		Decision:       e.policy.Defaults.Decision,
		TriggeredRules: []string{},
		Reasons:        []string{},
	}

	// Check blocked tools list first (highest priority)
	for _, blocked := range e.policy.BlockedTools {
		if matchToolName(toolName, blocked) {
			return MCPEvalResult{
				Decision:       policy.DecisionBlock,
				TriggeredRules: []string{"blocked-tool:" + blocked},
				Reasons:        []string{fmt.Sprintf("Tool %q is in the blocked tools list", toolName)},
			}
		}
	}

	// Evaluate rules — collect all matches, pick highest severity
	for _, rule := range e.policy.Rules {
		if e.matchRule(toolName, arguments, rule) {
			if decisionSeverity(rule.Decision) > decisionSeverity(result.Decision) {
				result.Decision = rule.Decision
				result.TriggeredRules = []string{rule.ID}
				result.Reasons = []string{rule.Reason}
			} else if decisionSeverity(rule.Decision) == decisionSeverity(result.Decision) {
				result.TriggeredRules = append(result.TriggeredRules, rule.ID)
				result.Reasons = append(result.Reasons, rule.Reason)
			}
		}
	}

	return result
}

func (e *PolicyEvaluator) matchRule(toolName string, arguments map[string]interface{}, rule MCPRule) bool {
	m := rule.Match

	// Tool name matching (if any name matcher is specified, at least one must match)
	nameMatched := false
	nameSpecified := false

	if m.ToolName != "" {
		nameSpecified = true
		if matchToolName(toolName, m.ToolName) {
			nameMatched = true
		}
	}

	if m.ToolNameRegex != "" {
		nameSpecified = true
		re, err := regexp.Compile(m.ToolNameRegex)
		if err == nil && re.MatchString(toolName) {
			nameMatched = true
		}
	}

	if len(m.ToolNameAny) > 0 {
		nameSpecified = true
		for _, name := range m.ToolNameAny {
			if matchToolName(toolName, name) {
				nameMatched = true
				break
			}
		}
	}

	if nameSpecified && !nameMatched {
		return false
	}

	// Argument pattern matching (all specified patterns must match)
	if len(m.ArgumentPatterns) > 0 {
		for argName, pattern := range m.ArgumentPatterns {
			argVal, ok := arguments[argName]
			if !ok {
				return false
			}
			valStr := fmt.Sprintf("%v", argVal)
			if !matchGlob(valStr, pattern) {
				return false
			}
		}
	}

	// If we had name matchers and they matched (or no name matchers were specified)
	// AND all argument patterns matched, the rule matches.
	return nameSpecified || len(m.ArgumentPatterns) > 0
}

// matchToolName checks if a tool name matches a pattern.
// Supports exact match and simple glob (* suffix).
func matchToolName(name, pattern string) bool {
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, name)
		return matched
	}
	return name == pattern
}

// matchGlob matches a value against a glob pattern.
// Supports ** for recursive path matching and * for single-level.
//
// Common patterns:
//
//	/etc/**          — matches anything under /etc/
//	**/.ssh/**       — matches any path containing a .ssh directory
//	/home/*/.aws/**  — matches .aws under any user in /home
func matchGlob(value, pattern string) bool {
	if !strings.Contains(pattern, "**") {
		matched, _ := filepath.Match(pattern, value)
		return matched
	}

	// Split both into path components and use recursive matching.
	vParts := splitPath(value)
	pParts := splitPathPattern(pattern)

	return globMatch(vParts, pParts)
}

// globMatch recursively matches value parts against pattern parts.
// "**" in pattern parts matches zero or more path components.
func globMatch(value, pattern []string) bool {
	vi, pi := 0, 0
	for pi < len(pattern) {
		if pattern[pi] == "**" {
			pi++
			// ** at end of pattern matches everything remaining
			if pi >= len(pattern) {
				return true
			}
			// Try matching the rest of the pattern at every position in value
			for vi <= len(value) {
				if globMatch(value[vi:], pattern[pi:]) {
					return true
				}
				vi++
			}
			return false
		}

		if vi >= len(value) {
			return false
		}

		matched, _ := filepath.Match(pattern[pi], value[vi])
		if !matched {
			return false
		}
		vi++
		pi++
	}

	return vi == len(value)
}

// splitPath splits a file path into its directory components.
func splitPath(p string) []string {
	p = filepath.Clean(p)
	if p == "/" || p == "." {
		return nil
	}
	var parts []string
	for {
		dir, file := filepath.Split(p)
		if file != "" {
			parts = append([]string{file}, parts...)
		}
		dir = filepath.Clean(dir)
		if dir == p { // no more progress (reached root or .)
			break
		}
		p = dir
	}
	return parts
}

// splitPathPattern splits a glob pattern into components, preserving "**".
func splitPathPattern(pattern string) []string {
	pattern = strings.TrimPrefix(pattern, "/")
	if pattern == "" {
		return nil
	}
	return strings.Split(pattern, "/")
}

// EvaluateResourceRead checks a resources/read URI against the MCP policy.
func (e *PolicyEvaluator) EvaluateResourceRead(uri string) MCPEvalResult {
	result := MCPEvalResult{
		Decision:       e.policy.Defaults.Decision,
		TriggeredRules: []string{},
		Reasons:        []string{},
	}

	// Check blocked resources list
	for _, blocked := range e.policy.BlockedResources {
		if matchResourceURI(uri, blocked) {
			return MCPEvalResult{
				Decision:       policy.DecisionBlock,
				TriggeredRules: []string{"blocked-resource:" + blocked},
				Reasons:        []string{fmt.Sprintf("Resource URI %q matches blocked pattern %q", uri, blocked)},
			}
		}
	}

	// Evaluate resource rules
	for _, rule := range e.policy.ResourceRules {
		if matchResourceRule(uri, rule) {
			if decisionSeverity(rule.Decision) > decisionSeverity(result.Decision) {
				result.Decision = rule.Decision
				result.TriggeredRules = []string{rule.ID}
				result.Reasons = []string{rule.Reason}
			} else if decisionSeverity(rule.Decision) == decisionSeverity(result.Decision) {
				result.TriggeredRules = append(result.TriggeredRules, rule.ID)
				result.Reasons = append(result.Reasons, rule.Reason)
			}
		}
	}

	// Check config guard on file:// URIs
	if strings.HasPrefix(uri, "file://") {
		path := strings.TrimPrefix(uri, "file://")
		// Use config guard to check if the resource path is protected
		guardResult := CheckConfigGuard("resources/read", map[string]interface{}{"path": path})
		if guardResult.Blocked {
			result.Decision = policy.DecisionBlock
			result.TriggeredRules = append(result.TriggeredRules, "config-file-guard")
			for _, f := range guardResult.Findings {
				result.Reasons = append(result.Reasons, "["+f.Category+"] "+f.Reason)
			}
		}
	}

	return result
}

// matchResourceURI checks if a URI matches a blocked resource pattern.
func matchResourceURI(uri, pattern string) bool {
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, uri)
		if matched {
			return true
		}
		// Also try glob matching on the path portion
		if strings.Contains(pattern, "**") {
			vParts := splitPath(uri)
			pParts := splitPathPattern(pattern)
			return globMatch(vParts, pParts)
		}
		return false
	}
	return uri == pattern
}

// matchResourceRule checks if a URI matches a resource rule.
func matchResourceRule(uri string, rule ResourceRule) bool {
	m := rule.Match
	matched := false
	specified := false

	if m.URIPattern != "" {
		specified = true
		if matchResourceURI(uri, m.URIPattern) {
			matched = true
		}
	}

	if m.URIRegex != "" {
		specified = true
		re, err := regexp.Compile(m.URIRegex)
		if err == nil && re.MatchString(uri) {
			matched = true
		}
	}

	if m.Scheme != "" {
		specified = true
		if strings.HasPrefix(uri, m.Scheme+"://") {
			matched = true
		}
	}

	if !specified {
		return false
	}
	return matched
}

func decisionSeverity(d policy.Decision) int {
	switch d {
	case policy.DecisionBlock:
		return 3
	case policy.DecisionAudit:
		return 2
	case policy.DecisionAllow:
		return 1
	default:
		return 0
	}
}
