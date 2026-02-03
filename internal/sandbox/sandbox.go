package sandbox

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Result struct {
	Success      bool
	ChangedFiles []FileChange
	DiffSummary  string
	Error        error
}

type FileChange struct {
	Path      string
	Action    string // "added", "modified", "deleted"
	SizeDelta int64
}

type Runner struct {
	workDir string
	tempDir string
	isGit   bool
}

func NewRunner(workDir string) (*Runner, error) {
	isGit := isGitRepo(workDir)

	tempDir, err := os.MkdirTemp("", "agentshield-sandbox-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	return &Runner{
		workDir: workDir,
		tempDir: tempDir,
		isGit:   isGit,
	}, nil
}

func (r *Runner) Cleanup() {
	if r.tempDir != "" {
		os.RemoveAll(r.tempDir)
	}
}

func (r *Runner) Run(args []string) Result {
	if err := r.copyWorkspace(); err != nil {
		return Result{Error: fmt.Errorf("failed to copy workspace: %w", err)}
	}

	beforeState, err := r.captureState()
	if err != nil {
		return Result{Error: fmt.Errorf("failed to capture before state: %w", err)}
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = r.tempDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmdErr := cmd.Run()

	afterState, err := r.captureState()
	if err != nil {
		return Result{Error: fmt.Errorf("failed to capture after state: %w", err)}
	}

	changes := r.computeChanges(beforeState, afterState)
	diffSummary := r.buildDiffSummary(changes)

	return Result{
		Success:      cmdErr == nil,
		ChangedFiles: changes,
		DiffSummary:  diffSummary,
		Error:        cmdErr,
	}
}

func (r *Runner) Apply(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = r.workDir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) copyWorkspace() error {
	return copyDir(r.workDir, r.tempDir)
}

type fileState struct {
	size    int64
	modTime int64
	exists  bool
}

func (r *Runner) captureState() (map[string]fileState, error) {
	state := make(map[string]fileState)
	maxFiles := 10000
	count := 0

	err := filepath.Walk(r.tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if count >= maxFiles {
			return filepath.SkipAll
		}

		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, _ := filepath.Rel(r.tempDir, path)
		state[relPath] = fileState{
			size:    info.Size(),
			modTime: info.ModTime().UnixNano(),
			exists:  true,
		}
		count++
		return nil
	})

	return state, err
}

func (r *Runner) computeChanges(before, after map[string]fileState) []FileChange {
	changes := []FileChange{}

	for path, afterInfo := range after {
		beforeInfo, existed := before[path]
		if !existed {
			changes = append(changes, FileChange{
				Path:      path,
				Action:    "added",
				SizeDelta: afterInfo.size,
			})
		} else if afterInfo.modTime != beforeInfo.modTime || afterInfo.size != beforeInfo.size {
			changes = append(changes, FileChange{
				Path:      path,
				Action:    "modified",
				SizeDelta: afterInfo.size - beforeInfo.size,
			})
		}
	}

	for path := range before {
		if _, exists := after[path]; !exists {
			changes = append(changes, FileChange{
				Path:      path,
				Action:    "deleted",
				SizeDelta: -before[path].size,
			})
		}
	}

	return changes
}

func (r *Runner) buildDiffSummary(changes []FileChange) string {
	if len(changes) == 0 {
		return "No files changed."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d file(s) changed:\n", len(changes)))

	added, modified, deleted := 0, 0, 0
	for _, c := range changes {
		switch c.Action {
		case "added":
			added++
			sb.WriteString(fmt.Sprintf("  + %s (new, %d bytes)\n", c.Path, c.SizeDelta))
		case "modified":
			modified++
			sb.WriteString(fmt.Sprintf("  ~ %s (%+d bytes)\n", c.Path, c.SizeDelta))
		case "deleted":
			deleted++
			sb.WriteString(fmt.Sprintf("  - %s (removed)\n", c.Path))
		}
	}

	sb.WriteString(fmt.Sprintf("\nSummary: %d added, %d modified, %d deleted\n", added, modified, deleted))
	return sb.String()
}

func isGitRepo(dir string) bool {
	gitDir := filepath.Join(dir, ".git")
	info, err := os.Stat(gitDir)
	return err == nil && info.IsDir()
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		if relPath == "." {
			return nil
		}

		if info.Name() == ".git" && info.IsDir() {
			return filepath.SkipDir
		}

		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		return copyFile(path, dstPath, info.Mode())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}
