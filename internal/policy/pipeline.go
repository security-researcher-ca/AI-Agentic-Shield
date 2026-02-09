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

	// Convert policy rules to analyzer.RegexRule
	regexRules := make([]analyzer.RegexRule, 0, len(pol.Rules))
	for _, r := range pol.Rules {
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

	regex := analyzer.NewRegexAnalyzer(regexRules)
	structural := analyzer.NewStructuralAnalyzer(maxParseDepth)
	semantic := analyzer.NewSemanticAnalyzer()
	dataflow := analyzer.NewDataflowAnalyzer()
	stateful := analyzer.NewStatefulAnalyzer(nil) // nil = compound-command-only mode
	guard := guardian.NewGuardianAnalyzer(guardian.NewHeuristicProvider())

	return analyzer.NewRegistry(
		[]analyzer.Analyzer{regex, structural, semantic, dataflow, stateful, guard},
		analyzer.NewCombiner(analyzer.StrategyMostRestrictive),
	)
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
