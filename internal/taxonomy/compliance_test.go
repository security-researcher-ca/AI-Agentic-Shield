package taxonomy

import (
	"os"
	"testing"
)

// TestComplianceMappings validates that every compliance mapping in taxonomy
// weakness YAML files references a valid standard and valid item ID.
// This is the key validation test that replaces Fortify's manual CSV approach.
func TestComplianceMappings(t *testing.T) {
	standardsDir := "../../compliance/standards"
	taxonomyDir := "../../taxonomy"

	if _, err := os.Stat(standardsDir); os.IsNotExist(err) {
		t.Skip("compliance/standards directory not found")
	}
	if _, err := os.Stat(taxonomyDir); os.IsNotExist(err) {
		t.Skip("taxonomy directory not found")
	}

	// Load all standards
	standards, err := LoadStandards(standardsDir)
	if err != nil {
		t.Fatalf("LoadStandards failed: %v", err)
	}
	t.Logf("Loaded %d compliance standards", len(standards))

	// Load all taxonomy entries
	cat, err := LoadCatalog(taxonomyDir)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}
	t.Logf("Loaded %d taxonomy entries", len(cat.Entries))

	// Validate every compliance mapping
	totalMappings := 0
	for _, entry := range cat.Entries {
		for stdID, items := range entry.Compliance {
			std, ok := standards[stdID]
			if !ok {
				t.Errorf("[%s] references unknown standard %q — "+
					"add it to compliance/standards/ or fix the mapping",
					entry.ID, stdID)
				continue
			}

			validItems := ValidItemIDs(std)
			for _, item := range items {
				if !validItems[item] {
					t.Errorf("[%s] references unknown item %q in standard %q — "+
						"valid items: %v",
						entry.ID, item, stdID, validItemList(std))
				}
				totalMappings++
			}
		}
	}

	t.Logf("Validated %d compliance mappings across %d entries", totalMappings, len(cat.Entries))
}

// TestComplianceStandardsLoad validates that standard definition files parse correctly.
func TestComplianceStandardsLoad(t *testing.T) {
	standardsDir := "../../compliance/standards"
	if _, err := os.Stat(standardsDir); os.IsNotExist(err) {
		t.Skip("compliance/standards directory not found")
	}

	standards, err := LoadStandards(standardsDir)
	if err != nil {
		t.Fatalf("LoadStandards failed: %v", err)
	}

	for id, std := range standards {
		if std.ID == "" {
			t.Errorf("standard loaded with key %q but empty ID field", id)
		}
		if std.Name == "" {
			t.Errorf("[%s] missing name", std.ID)
		}
		if len(std.Items) == 0 {
			t.Errorf("[%s] has no items", std.ID)
		}

		// Verify item IDs are unique within the standard
		seen := map[string]bool{}
		for _, item := range std.Items {
			if seen[item.ID] {
				t.Errorf("[%s] duplicate item ID: %s", std.ID, item.ID)
			}
			seen[item.ID] = true
		}

		t.Logf("Standard %q: %d items", std.ID, len(std.Items))
	}
}

// TestComplianceIndexGeneration validates that index generation works and
// produces non-empty output for standards with mappings.
func TestComplianceIndexGeneration(t *testing.T) {
	standardsDir := "../../compliance/standards"
	taxonomyDir := "../../taxonomy"

	if _, err := os.Stat(standardsDir); os.IsNotExist(err) {
		t.Skip("compliance/standards directory not found")
	}
	if _, err := os.Stat(taxonomyDir); os.IsNotExist(err) {
		t.Skip("taxonomy directory not found")
	}

	standards, err := LoadStandards(standardsDir)
	if err != nil {
		t.Fatalf("LoadStandards failed: %v", err)
	}

	cat, err := LoadCatalog(taxonomyDir)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	for _, std := range standards {
		idx := BuildComplianceIndex(std, cat.Entries)

		md := GenerateIndexMarkdown(idx, cat.ByID)
		if md == "" {
			t.Errorf("[%s] generated empty index markdown", std.ID)
		}

		// Count total mappings
		totalMappings := 0
		for _, weaknesses := range idx.Mappings {
			totalMappings += len(weaknesses)
		}
		t.Logf("Standard %q: %d items with mappings, %d total weakness mappings",
			std.ID, len(idx.Mappings), totalMappings)
	}
}

// TestAllEntriesHaveCompliance verifies that every taxonomy entry has at least
// one compliance mapping. This ensures no weakness is "orphaned" from standards.
func TestAllEntriesHaveCompliance(t *testing.T) {
	taxonomyDir := "../../taxonomy"
	if _, err := os.Stat(taxonomyDir); os.IsNotExist(err) {
		t.Skip("taxonomy directory not found")
	}

	cat, err := LoadCatalog(taxonomyDir)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	for _, entry := range cat.Entries {
		if len(entry.Compliance) == 0 {
			t.Errorf("[%s] has no compliance mappings — every weakness should map "+
				"to at least one standard", entry.ID)
		}
	}
}

// validItemList returns a list of valid item IDs for error messages.
func validItemList(std ComplianceStandard) []string {
	ids := make([]string, len(std.Items))
	for i, item := range std.Items {
		ids[i] = item.ID
	}
	return ids
}
