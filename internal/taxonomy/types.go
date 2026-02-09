package taxonomy

// TaxonomyEntry represents a single weakness in the Agent Action Security Taxonomy.
// Each entry belongs to a Kingdom and Category, and contains documentation
// (Abstract, Explanation, Recommendation) plus compliance mappings to
// industry standards like OWASP LLM Top 10.
type TaxonomyEntry struct {
	ID             string              `yaml:"id"`
	Version        string              `yaml:"version"`
	Kingdom        string              `yaml:"kingdom"`
	KingdomID      int                 `yaml:"kingdom_id"`
	Category       string              `yaml:"category"`
	CategoryID     string              `yaml:"category_id"`
	Name           string              `yaml:"name"`
	RiskLevel      string              `yaml:"risk_level"` // "critical", "high", "medium", "low"
	Abstract       string              `yaml:"abstract"`
	Explanation    string              `yaml:"explanation"`
	Recommendation string              `yaml:"recommendation"`
	Examples       TaxonomyExamples    `yaml:"examples"`
	Compliance     map[string][]string `yaml:"compliance"`   // standard-id → item IDs
	References     TaxonomyRefs        `yaml:"references"`
	Analyzers      []string            `yaml:"analyzers"`
	RelatedRules   []string            `yaml:"related_rules"`
}

// TaxonomyExamples holds example commands that illustrate the weakness.
type TaxonomyExamples struct {
	Bad  []string `yaml:"bad"`
	Good []string `yaml:"good"`
}

// TaxonomyRefs holds external references for a taxonomy entry.
type TaxonomyRefs struct {
	MitreAttack []string      `yaml:"mitre_attack"`
	CWE         []string      `yaml:"cwe"`
	External    []ExternalRef `yaml:"external"`
}

// ExternalRef is a link to an external resource (paper, standard, etc.).
type ExternalRef struct {
	Title string `yaml:"title"`
	URL   string `yaml:"url"`
}

// KingdomDef defines a top-level kingdom in the taxonomy.
type KingdomDef struct {
	ID          int    `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// CategoryDef defines a category within a kingdom.
type CategoryDef struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	KingdomID   int    `yaml:"kingdom_id"`
	Description string `yaml:"description"`
}

// Kingdoms is the top-level YAML structure for kingdoms.yaml.
type Kingdoms struct {
	Kingdoms []KingdomDef `yaml:"kingdoms"`
}
