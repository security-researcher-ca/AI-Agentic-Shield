package policy

import (
	"github.com/gzhole/agentshield/internal/analyzer"
	"github.com/gzhole/agentshield/internal/guardian"
)

// BuildAnalyzerPipeline creates a full analyzer registry from the engine's policy rules.
// The pipeline runs: regex → structural → semantic, combined with most_restrictive strategy.
// This is the standard pipeline for production use.
func BuildAnalyzerPipeline(pol *Policy, maxParseDepth int) *analyzer.Registry {
	if maxParseDepth <= 0 {
		maxParseDepth = 2
	}

	// Convert policy rules to analyzer-side types.
	// Rules with regex/prefix/exact go to the RegexAnalyzer.
	// Rules with structural match go to the StructuralAnalyzer.
	var regexRules []analyzer.RegexRule
	var structuralRules []analyzer.StructuralRule

	for _, r := range pol.Rules {
		// Regex/prefix/exact match → RegexAnalyzer
		if r.Match.CommandExact != "" || len(r.Match.CommandPrefix) > 0 || r.Match.CommandRegex != "" {
			regexRules = append(regexRules, analyzer.RegexRule{
				ID:         r.ID,
				Decision:   string(r.Decision),
				Confidence: r.Confidence,
				Reason:     r.Reason,
				Taxonomy:   r.Taxonomy,
				Exact:      r.Match.CommandExact,
				Prefixes:   r.Match.CommandPrefix,
				Regex:      r.Match.CommandRegex,
			})
		}

		// Structural match → StructuralAnalyzer (user-defined YAML rules)
		if r.Match.Structural != nil {
			structuralRules = append(structuralRules, convertStructuralRule(r))
		}
	}

	regex := analyzer.NewRegexAnalyzer(regexRules)
	structural := analyzer.NewStructuralAnalyzer(maxParseDepth)
	structural.SetUserRules(structuralRules)
	semantic := analyzer.NewSemanticAnalyzer()
	dataflow := analyzer.NewDataflowAnalyzer()
	stateful := analyzer.NewStatefulAnalyzer(nil) // nil = compound-command-only mode
	guard := guardian.NewGuardianAnalyzer(guardian.NewHeuristicProvider())

	return analyzer.NewRegistry(
		[]analyzer.Analyzer{regex, structural, semantic, dataflow, stateful, guard},
		analyzer.NewCombiner(analyzer.StrategyMostRestrictive),
	)
}

// convertStructuralRule converts a policy.Rule with a StructuralMatch into
// an analyzer.StructuralRule (crossing the package boundary without import cycles).
func convertStructuralRule(r Rule) analyzer.StructuralRule {
	sm := r.Match.Structural
	return analyzer.StructuralRule{
		ID:         r.ID,
		Decision:   string(r.Decision),
		Confidence: r.Confidence,
		Reason:     r.Reason,
		Taxonomy:   r.Taxonomy,
		Executable: []string(sm.Executable),
		SubCommand: sm.SubCommand,
		FlagsAll:   sm.FlagsAll,
		FlagsAny:   sm.FlagsAny,
		FlagsNone:  sm.FlagsNone,
		ArgsAny:    sm.ArgsAny,
		ArgsNone:   sm.ArgsNone,
		HasPipe:    sm.HasPipe,
		PipeTo:     sm.PipeTo,
		PipeFrom:   sm.PipeFrom,
		Negate:     sm.Negate,
	}
}

// NewEngineWithAnalyzers creates an engine with the full analyzer pipeline enabled.
func NewEngineWithAnalyzers(p *Policy, maxParseDepth int) (*Engine, error) {
	engine, err := NewEngine(p)
	if err != nil {
		return nil, err
	}
	engine.SetRegistry(BuildAnalyzerPipeline(p, maxParseDepth))
	return engine, nil
}
