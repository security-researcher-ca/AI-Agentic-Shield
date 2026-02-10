package taxonomy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ComplianceStandard defines a regulatory/industry standard (e.g., OWASP LLM Top 10).
type ComplianceStandard struct {
	ID      string         `yaml:"id"`
	Name    string         `yaml:"name"`
	Version string         `yaml:"version"`
	URL     string         `yaml:"url"`
	Items   []StandardItem `yaml:"items"`
}

// StandardItem is a single item within a compliance standard.
type StandardItem struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// ComplianceIndex maps standard items to the weakness IDs that reference them.
// This is the auto-generated reverse index used for markdown generation.
type ComplianceIndex struct {
	StandardID string
	Standard   ComplianceStandard
	Mappings   map[string][]string // item ID → []weakness ID
}

// LoadStandards loads all compliance standard definitions from a directory.
// Files prefixed with underscore are treated as drafts and skipped.
func LoadStandards(dir string) (map[string]ComplianceStandard, error) {
	standards := make(map[string]ComplianceStandard)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return standards, nil
		}
		return nil, fmt.Errorf("reading standards directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		// Underscore prefix = draft/disabled
		baseName := strings.TrimSuffix(name, filepath.Ext(name))
		if strings.HasPrefix(baseName, "_") {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading standard %s: %w", name, err)
		}

		var std ComplianceStandard
		if err := yaml.Unmarshal(data, &std); err != nil {
			return nil, fmt.Errorf("parsing standard %s: %w", name, err)
		}
		standards[std.ID] = std
	}

	return standards, nil
}

// ValidItemIDs returns a set of valid item IDs for a standard.
func ValidItemIDs(std ComplianceStandard) map[string]bool {
	ids := make(map[string]bool, len(std.Items))
	for _, item := range std.Items {
		ids[item.ID] = true
	}
	return ids
}

// BuildComplianceIndex creates a reverse index from standard items to weakness IDs
// for a given standard, scanning all taxonomy entries.
func BuildComplianceIndex(std ComplianceStandard, entries []TaxonomyEntry) ComplianceIndex {
	idx := ComplianceIndex{
		StandardID: std.ID,
		Standard:   std,
		Mappings:   make(map[string][]string),
	}

	for _, entry := range entries {
		items, ok := entry.Compliance[std.ID]
		if !ok {
			continue
		}
		for _, itemID := range items {
			idx.Mappings[itemID] = append(idx.Mappings[itemID], entry.ID)
		}
	}

	return idx
}

// GenerateIndexMarkdown produces a GitHub-browsable markdown file for a compliance index.
func GenerateIndexMarkdown(idx ComplianceIndex, entries map[string]TaxonomyEntry) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s\n\n", idx.Standard.Name))
	sb.WriteString("> Auto-generated from taxonomy weakness entries. Do not edit manually.\n")
	sb.WriteString(fmt.Sprintf("> Source: [%s](%s)\n\n", idx.Standard.Name, idx.Standard.URL))

	// Sort items by ID for stable output
	sortedItems := make([]StandardItem, len(idx.Standard.Items))
	copy(sortedItems, idx.Standard.Items)
	sort.Slice(sortedItems, func(i, j int) bool {
		return sortedItems[i].ID < sortedItems[j].ID
	})

	for _, item := range sortedItems {
		sb.WriteString(fmt.Sprintf("## %s: %s\n\n", item.ID, item.Name))
		if item.URL != "" {
			sb.WriteString(fmt.Sprintf("[View on OWASP](%s)\n\n", item.URL))
		}

		weaknesses, ok := idx.Mappings[item.ID]
		if !ok || len(weaknesses) == 0 {
			sb.WriteString("_No weaknesses mapped yet._\n\n")
			continue
		}

		sort.Strings(weaknesses)
		for _, wID := range weaknesses {
			entry, found := entries[wID]
			if found {
				sb.WriteString(fmt.Sprintf("- **%s** — %s (Risk: %s)\n",
					entry.Name, strings.TrimSpace(entry.Abstract), entry.RiskLevel))
			} else {
				sb.WriteString(fmt.Sprintf("- `%s` _(entry not found)_\n", wID))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
