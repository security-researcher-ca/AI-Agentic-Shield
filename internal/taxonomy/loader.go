package taxonomy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Catalog holds all loaded taxonomy data: kingdoms, categories, and entries.
type Catalog struct {
	Kingdoms   []KingdomDef
	Categories []CategoryDef
	Entries    []TaxonomyEntry
	ByID       map[string]TaxonomyEntry   // weakness ID → entry
	ByKingdom  map[int][]TaxonomyEntry    // kingdom ID → entries
	ByCategory map[string][]TaxonomyEntry // category ID → entries
}

// LoadCatalog loads the full taxonomy from a root directory.
// Expected structure:
//
//	taxonomy/
//	  kingdoms.yaml
//	  <kingdom-dir>/
//	    _kingdom.yaml
//	    <category-dir>/
//	      _category.yaml
//	      <weakness>.yaml
func LoadCatalog(taxonomyDir string) (*Catalog, error) {
	cat := &Catalog{
		ByID:       make(map[string]TaxonomyEntry),
		ByKingdom:  make(map[int][]TaxonomyEntry),
		ByCategory: make(map[string][]TaxonomyEntry),
	}

	// Load kingdoms.yaml
	kingdomsPath := filepath.Join(taxonomyDir, "kingdoms.yaml")
	if err := cat.loadKingdoms(kingdomsPath); err != nil {
		return nil, fmt.Errorf("loading kingdoms: %w", err)
	}

	// Walk kingdom directories
	topEntries, err := os.ReadDir(taxonomyDir)
	if err != nil {
		return nil, fmt.Errorf("reading taxonomy dir: %w", err)
	}

	for _, topEntry := range topEntries {
		if !topEntry.IsDir() {
			continue
		}
		kingdomDir := filepath.Join(taxonomyDir, topEntry.Name())

		// Load _kingdom.yaml if present
		kingdomMeta := filepath.Join(kingdomDir, "_kingdom.yaml")
		if _, err := os.Stat(kingdomMeta); err == nil {
			// Kingdom metadata is informational; kingdoms.yaml is authoritative
			_ = err // silence unused variable warning
		}

		// Walk category directories
		catEntries, err := os.ReadDir(kingdomDir)
		if err != nil {
			continue
		}

		for _, catEntry := range catEntries {
			if !catEntry.IsDir() {
				continue
			}
			categoryDir := filepath.Join(kingdomDir, catEntry.Name())

			// Load _category.yaml if present
			catMeta := filepath.Join(categoryDir, "_category.yaml")
			if data, err := os.ReadFile(catMeta); err == nil {
				var cdef CategoryDef
				if err := yaml.Unmarshal(data, &cdef); err == nil {
					cat.Categories = append(cat.Categories, cdef)
				}
			}

			// Load weakness entries
			weaknessFiles, err := os.ReadDir(categoryDir)
			if err != nil {
				continue
			}

			for _, wf := range weaknessFiles {
				if wf.IsDir() {
					continue
				}
				name := wf.Name()
				if strings.HasPrefix(name, "_") {
					continue
				}
				if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
					continue
				}

				path := filepath.Join(categoryDir, name)
				entry, err := loadEntry(path)
				if err != nil {
					return nil, fmt.Errorf("loading entry %s: %w", path, err)
				}

				cat.Entries = append(cat.Entries, entry)
				cat.ByID[entry.ID] = entry
				cat.ByKingdom[entry.KingdomID] = append(cat.ByKingdom[entry.KingdomID], entry)
				cat.ByCategory[entry.CategoryID] = append(cat.ByCategory[entry.CategoryID], entry)
			}
		}
	}

	return cat, nil
}

func (c *Catalog) loadKingdoms(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var k Kingdoms
	if err := yaml.Unmarshal(data, &k); err != nil {
		return err
	}
	c.Kingdoms = k.Kingdoms
	return nil
}

func loadEntry(path string) (TaxonomyEntry, error) {
	var entry TaxonomyEntry
	data, err := os.ReadFile(path)
	if err != nil {
		return entry, err
	}
	if err := yaml.Unmarshal(data, &entry); err != nil {
		return entry, err
	}
	return entry, nil
}
