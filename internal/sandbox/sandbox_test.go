package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunner_DetectsChanges(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(tmpDir)
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	defer runner.Cleanup()

	result := runner.Run([]string{"sh", "-c", "echo 'modified content' > test.txt"})

	if result.Error != nil {
		t.Fatalf("sandbox run failed: %v", result.Error)
	}

	if len(result.ChangedFiles) != 1 {
		t.Errorf("expected 1 changed file, got %d", len(result.ChangedFiles))
	}

	if len(result.ChangedFiles) > 0 && result.ChangedFiles[0].Action != "modified" {
		t.Errorf("expected action 'modified', got '%s'", result.ChangedFiles[0].Action)
	}
}

func TestRunner_DetectsNewFiles(t *testing.T) {
	tmpDir := t.TempDir()

	runner, err := NewRunner(tmpDir)
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	defer runner.Cleanup()

	result := runner.Run([]string{"sh", "-c", "echo 'new file' > newfile.txt"})

	if result.Error != nil {
		t.Fatalf("sandbox run failed: %v", result.Error)
	}

	foundNew := false
	for _, c := range result.ChangedFiles {
		if c.Path == "newfile.txt" && c.Action == "added" {
			foundNew = true
			break
		}
	}

	if !foundNew {
		t.Errorf("expected to find new file 'newfile.txt', got: %v", result.ChangedFiles)
	}
}

func TestRunner_DetectsDeletedFiles(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "todelete.txt")
	if err := os.WriteFile(testFile, []byte("to be deleted"), 0644); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(tmpDir)
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	defer runner.Cleanup()

	result := runner.Run([]string{"rm", "todelete.txt"})

	if result.Error != nil {
		t.Fatalf("sandbox run failed: %v", result.Error)
	}

	foundDeleted := false
	for _, c := range result.ChangedFiles {
		if c.Path == "todelete.txt" && c.Action == "deleted" {
			foundDeleted = true
			break
		}
	}

	if !foundDeleted {
		t.Errorf("expected to find deleted file 'todelete.txt', got: %v", result.ChangedFiles)
	}
}

func TestRunner_NoChangesInRealWorkspace(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "original.txt")
	originalContent := []byte("original content")
	if err := os.WriteFile(testFile, originalContent, 0644); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRunner(tmpDir)
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}
	defer runner.Cleanup()

	_ = runner.Run([]string{"sh", "-c", "echo 'modified' > original.txt"})

	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed to read original file: %v", err)
	}

	if string(content) != string(originalContent) {
		t.Errorf("sandbox modified real workspace! expected %q, got %q", originalContent, content)
	}
}

func TestRunner_Cleanup(t *testing.T) {
	tmpDir := t.TempDir()

	runner, err := NewRunner(tmpDir)
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}

	sandboxDir := runner.tempDir
	runner.Cleanup()

	if _, err := os.Stat(sandboxDir); !os.IsNotExist(err) {
		t.Errorf("sandbox temp dir should be removed after cleanup")
	}
}
