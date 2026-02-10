package taxonomy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCatalog_FullTaxonomy(t *testing.T) {
	// Load the actual taxonomy from the project root
	taxonomyDir := "../../taxonomy"
	if _, err := os.Stat(taxonomyDir); os.IsNotExist(err) {
		t.Skip("taxonomy directory not found — run from project root")
	}

	cat, err := LoadCatalog(taxonomyDir)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	// Verify kingdoms were loaded
	if len(cat.Kingdoms) == 0 {
		t.Error("expected at least one kingdom")
	}
	t.Logf("Loaded %d kingdoms", len(cat.Kingdoms))

	// Verify entries were loaded
	if len(cat.Entries) == 0 {
		t.Error("expected at least one taxonomy entry")
	}
	t.Logf("Loaded %d taxonomy entries", len(cat.Entries))

	// Verify ByID index
	for _, entry := range cat.Entries {
		if _, ok := cat.ByID[entry.ID]; !ok {
			t.Errorf("entry %q not found in ByID index", entry.ID)
		}
	}

	// Verify all entries have required fields
	for _, entry := range cat.Entries {
		if entry.ID == "" {
			t.Error("entry with empty ID")
		}
		if entry.Version == "" {
			t.Errorf("[%s] missing version", entry.ID)
		}
		if entry.Kingdom == "" {
			t.Errorf("[%s] missing kingdom", entry.ID)
		}
		if entry.Category == "" {
			t.Errorf("[%s] missing category", entry.ID)
		}
		if entry.Name == "" {
			t.Errorf("[%s] missing name", entry.ID)
		}
		if entry.RiskLevel == "" {
			t.Errorf("[%s] missing risk_level", entry.ID)
		}
		if entry.Abstract == "" {
			t.Errorf("[%s] missing abstract", entry.ID)
		}
		if entry.Explanation == "" {
			t.Errorf("[%s] missing explanation", entry.ID)
		}
		if entry.Recommendation == "" {
			t.Errorf("[%s] missing recommendation", entry.ID)
		}
	}
}

func TestLoadCatalog_KingdomIDs(t *testing.T) {
	taxonomyDir := "../../taxonomy"
	if _, err := os.Stat(taxonomyDir); os.IsNotExist(err) {
		t.Skip("taxonomy directory not found")
	}

	cat, err := LoadCatalog(taxonomyDir)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	// Verify each entry's kingdom_id maps to a known kingdom
	kingdomIDs := map[int]string{}
	for _, k := range cat.Kingdoms {
		kingdomIDs[k.ID] = k.Name
	}

	for _, entry := range cat.Entries {
		if _, ok := kingdomIDs[entry.KingdomID]; !ok {
			t.Errorf("[%s] kingdom_id %d not found in kingdoms.yaml",
				entry.ID, entry.KingdomID)
		}
	}
}

func TestLoadCatalog_RiskLevelsAreValid(t *testing.T) {
	taxonomyDir := "../../taxonomy"
	if _, err := os.Stat(taxonomyDir); os.IsNotExist(err) {
		t.Skip("taxonomy directory not found")
	}

	cat, err := LoadCatalog(taxonomyDir)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	validLevels := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}

	for _, entry := range cat.Entries {
		if !validLevels[entry.RiskLevel] {
			t.Errorf("[%s] invalid risk_level %q — must be critical/high/medium/low",
				entry.ID, entry.RiskLevel)
		}
	}
}

func TestLoadCatalog_IDsAreUnique(t *testing.T) {
	taxonomyDir := "../../taxonomy"
	if _, err := os.Stat(taxonomyDir); os.IsNotExist(err) {
		t.Skip("taxonomy directory not found")
	}

	cat, err := LoadCatalog(taxonomyDir)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	seen := map[string]bool{}
	for _, entry := range cat.Entries {
		if seen[entry.ID] {
			t.Errorf("duplicate taxonomy entry ID: %s", entry.ID)
		}
		seen[entry.ID] = true
	}
	t.Logf("Verified %d taxonomy entry IDs are unique", len(cat.Entries))
}

func TestLoadCatalog_ExamplesPresent(t *testing.T) {
	taxonomyDir := "../../taxonomy"
	if _, err := os.Stat(taxonomyDir); os.IsNotExist(err) {
		t.Skip("taxonomy directory not found")
	}

	cat, err := LoadCatalog(taxonomyDir)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	for _, entry := range cat.Entries {
		if len(entry.Examples.Bad) == 0 {
			t.Errorf("[%s] missing bad examples", entry.ID)
		}
		if len(entry.Examples.Good) == 0 {
			t.Errorf("[%s] missing good examples", entry.ID)
		}
	}
}

func TestLoadCatalog_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	// Create minimal kingdoms.yaml
	kingdomsYAML := `kingdoms:
  - id: 1
    name: "Test Kingdom"
    description: "Test"
`
	if err := os.WriteFile(filepath.Join(dir, "kingdoms.yaml"), []byte(kingdomsYAML), 0644); err != nil {
		t.Fatalf("Failed to write kingdoms.yaml: %v", err)
	}

	cat, err := LoadCatalog(dir)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	if len(cat.Kingdoms) != 1 {
		t.Errorf("expected 1 kingdom, got %d", len(cat.Kingdoms))
	}
	if len(cat.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(cat.Entries))
	}
}

func TestLoadCatalog_WithEntries(t *testing.T) {
	dir := t.TempDir()

	kingdomsYAML := `kingdoms:
  - id: 1
    name: "Test Kingdom"
    description: "Test"
`
	if err := os.WriteFile(filepath.Join(dir, "kingdoms.yaml"), []byte(kingdomsYAML), 0644); err != nil {
		t.Fatalf("Failed to write kingdoms.yaml: %v", err)
	}

	// Create kingdom dir, category dir, and entry
	catDir := filepath.Join(dir, "test-kingdom", "test-category")
	if err := os.MkdirAll(catDir, 0755); err != nil {
		t.Fatalf("Failed to create category directory: %v", err)
	}

	entryYAML := `id: "test-kingdom/test-category/test-weakness"
version: "1.0.0"
kingdom: "Test Kingdom"
kingdom_id: 1
category: "Test Category"
category_id: "1.1"
name: "Test Weakness"
risk_level: "high"
abstract: "A test weakness."
explanation: "Detailed explanation."
recommendation: "Fix it."
examples:
  bad: ["bad command"]
  good: ["good command"]
compliance:
  owasp-llm-2025: ["LLM06"]
references:
  mitre_attack: ["T1234"]
  cwe: ["CWE-123"]
analyzers: ["regex"]
related_rules: ["test-rule"]
`
	if err := os.WriteFile(filepath.Join(catDir, "test-weakness.yaml"), []byte(entryYAML), 0644); err != nil {
		t.Fatalf("Failed to write entry file: %v", err)
	}

	cat, err := LoadCatalog(dir)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	if len(cat.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(cat.Entries))
	}

	entry := cat.Entries[0]
	if entry.ID != "test-kingdom/test-category/test-weakness" {
		t.Errorf("wrong entry ID: %s", entry.ID)
	}
	if entry.Version != "1.0.0" {
		t.Errorf("wrong version: %s", entry.Version)
	}
	if entry.RiskLevel != "high" {
		t.Errorf("wrong risk_level: %s", entry.RiskLevel)
	}

	// Verify compliance mapping
	items, ok := entry.Compliance["owasp-llm-2025"]
	if !ok {
		t.Error("missing owasp-llm-2025 compliance mapping")
	}
	if len(items) != 1 || items[0] != "LLM06" {
		t.Errorf("wrong compliance items: %v", items)
	}

	// Verify ByID index
	if _, ok := cat.ByID[entry.ID]; !ok {
		t.Error("entry not in ByID index")
	}

	// Verify ByKingdom index
	if entries, ok := cat.ByKingdom[1]; !ok || len(entries) != 1 {
		t.Errorf("ByKingdom[1] expected 1 entry, got %d", len(entries))
	}
}
