package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gzhole/agentshield/internal/config"
	"github.com/spf13/cobra"
)

var setupWindsurfCmd = &cobra.Command{
	Use:   "windsurf",
	Short: "Set up AgentShield for Windsurf IDE",
	Long: `Install Cascade Hooks so every command Windsurf's AI agent runs is
evaluated by AgentShield before execution.

  agentshield setup windsurf`,
	RunE: setupWindsurfCommand,
}

var setupCursorCmd = &cobra.Command{
	Use:   "cursor",
	Short: "Set up AgentShield for Cursor IDE",
	Long: `Show instructions to configure Cursor's terminal profile to use
AgentShield's wrapper shell.

  agentshield setup cursor`,
	RunE: setupCursorCommand,
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up AgentShield for your environment",
	Long: `Set up AgentShield integration with IDE agents and install default policy packs.

IDE-specific setup:
  agentshield setup windsurf    # install Cascade Hooks (recommended)
  agentshield setup cursor      # show terminal profile config

General setup:
  agentshield setup --install   # install wrapper + policy packs
  agentshield setup             # show all integration instructions`,
	RunE: setupCommand,
}

var installFlag bool

func init() {
	setupCmd.Flags().BoolVar(&installFlag, "install", false, "Install wrapper script and default policy packs")
	setupCmd.AddCommand(setupWindsurfCmd)
	setupCmd.AddCommand(setupCursorCmd)
	rootCmd.AddCommand(setupCmd)
}

func setupCommand(cmd *cobra.Command, args []string) error {
	if installFlag {
		return runSetupInstall()
	}
	printSetupInstructions()
	return nil
}

func runSetupInstall() error {
	cfg, err := config.Load("", "", "")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Ensure config directory exists
	if err := os.MkdirAll(cfg.ConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	// Ensure packs directory exists
	packsDir := filepath.Join(cfg.ConfigDir, "packs")
	if err := os.MkdirAll(packsDir, 0755); err != nil {
		return fmt.Errorf("failed to create packs dir: %w", err)
	}

	// Find wrapper script source
	wrapperSrc := findWrapperSource()
	if wrapperSrc == "" {
		fmt.Fprintln(os.Stderr, "⚠  Could not find agentshield-wrapper.sh source.")
		fmt.Fprintln(os.Stderr, "   The wrapper will need to be installed manually.")
	} else {
		// Install wrapper to share directory
		shareDir := getShareDir()
		if err := os.MkdirAll(shareDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Could not create %s: %v\n", shareDir, err)
			fmt.Fprintln(os.Stderr, "   Try: sudo agentshield setup --install")
		} else {
			wrapperDst := filepath.Join(shareDir, "agentshield-wrapper.sh")
			data, err := os.ReadFile(wrapperSrc)
			if err != nil {
				return fmt.Errorf("failed to read wrapper source: %w", err)
			}
			if err := os.WriteFile(wrapperDst, data, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "⚠  Could not write to %s: %v\n", wrapperDst, err)
				fmt.Fprintln(os.Stderr, "   Try: sudo agentshield setup --install")
			} else {
				fmt.Printf("✅ Wrapper installed: %s\n", wrapperDst)
			}
		}
	}

	// Copy bundled packs if packs dir is empty
	packsSrc := findPacksSource()
	if packsSrc != "" {
		installed := installPacks(packsSrc, packsDir)
		if installed > 0 {
			fmt.Printf("✅ %d policy packs installed to %s\n", installed, packsDir)
		} else {
			fmt.Printf("✅ Policy packs already present in %s\n", packsDir)
		}
	}

	fmt.Println()
	printSetupInstructions()
	return nil
}

// ─── Windsurf Setup ─────────────────────────────────────────────────────────

func setupWindsurfCommand(cmd *cobra.Command, args []string) error {
	hooksPath := filepath.Join(os.Getenv("HOME"), ".codeium", "windsurf", "hooks.json")
	hooksDir := filepath.Dir(hooksPath)

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + Windsurf (Cascade Hooks)")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	// Check if agentshield is in PATH
	binPath, err := exec.LookPath("agentshield")
	if err != nil {
		fmt.Println("⚠  agentshield not found in PATH. Install it first:")
		fmt.Println("   brew tap gzhole/tap && brew install agentshield")
		return nil
	}
	fmt.Printf("✅ agentshield found: %s\n", binPath)

	// Check for existing hooks.json
	if _, err := os.Stat(hooksPath); err == nil {
		// Read existing hooks
		data, err := os.ReadFile(hooksPath)
		if err == nil && strings.Contains(string(data), "agentshield hook") {
			fmt.Printf("✅ Cascade Hook already configured: %s\n", hooksPath)
			fmt.Println()
			fmt.Println("AgentShield is active. Test it by asking Cascade to run:")
			fmt.Println("  rm -rf /")
			fmt.Println("  cat ~/.ssh/id_ed25519")
			fmt.Println()
			printStatus()
			return nil
		}
		// Hooks file exists but doesn't have our hook — show manual instructions
		fmt.Printf("⚠  Existing hooks.json found: %s\n", hooksPath)
		fmt.Println("   Add this to the \"hooks\" object manually:")
		fmt.Println()
		fmt.Println(`   "pre_run_command": [`)
		fmt.Println(`     {`)
		fmt.Println(`       "command": "agentshield hook",`)
		fmt.Println(`       "show_output": true`)
		fmt.Println(`     }`)
		fmt.Println(`   ]`)
		fmt.Println()
		return nil
	}

	// Create hooks.json
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", hooksDir, err)
	}

	hooksContent := `{
  "hooks": {
    "pre_run_command": [
      {
        "command": "agentshield hook",
        "show_output": true
      }
    ]
  }
}
`
	if err := os.WriteFile(hooksPath, []byte(hooksContent), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", hooksPath, err)
	}

	fmt.Printf("✅ Cascade Hook installed: %s\n", hooksPath)
	fmt.Println()
	fmt.Println("How it works:")
	fmt.Println("  1. Cascade (Windsurf's AI) tries to run a command")
	fmt.Println("  2. The pre_run_command hook calls `agentshield hook`")
	fmt.Println("  3. AgentShield evaluates the command against your policy")
	fmt.Println("  4. If BLOCK: Cascade is prevented from running the command")
	fmt.Println("  5. If ALLOW/AUDIT: the command runs normally")
	fmt.Println()
	fmt.Println("Restart Windsurf to activate the hook, then test by asking")
	fmt.Println("Cascade to run: rm -rf /")
	fmt.Println()
	printStatus()
	return nil
}

// ─── Cursor Setup ───────────────────────────────────────────────────────────

func setupCursorCommand(cmd *cobra.Command, args []string) error {
	hooksPath := filepath.Join(os.Getenv("HOME"), ".cursor", "hooks.json")
	hooksDir := filepath.Dir(hooksPath)

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + Cursor (Hooks)")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	// Check if agentshield is in PATH
	binPath, err := exec.LookPath("agentshield")
	if err != nil {
		fmt.Println("⚠  agentshield not found in PATH. Install it first:")
		fmt.Println("   brew tap gzhole/tap && brew install agentshield")
		return nil
	}
	fmt.Printf("✅ agentshield found: %s\n", binPath)

	// Check for existing hooks.json
	if _, err := os.Stat(hooksPath); err == nil {
		data, err := os.ReadFile(hooksPath)
		if err == nil && strings.Contains(string(data), "agentshield hook") {
			fmt.Printf("✅ Cursor Hook already configured: %s\n", hooksPath)
			fmt.Println()
			fmt.Println("AgentShield is active. Test by asking Agent to run:")
			fmt.Println("  rm -rf /")
			fmt.Println("  cat ~/.ssh/id_ed25519")
			fmt.Println()
			printStatus()
			return nil
		}
		fmt.Printf("⚠  Existing hooks.json found: %s\n", hooksPath)
		fmt.Println("   Add this to the \"hooks\" object manually:")
		fmt.Println()
		fmt.Println(`   "beforeShellExecution": [`)
		fmt.Println(`     {`)
		fmt.Println(`       "command": "agentshield hook",`)
		fmt.Println(`       "show_output": true`)
		fmt.Println(`     }`)
		fmt.Println(`   ]`)
		fmt.Println()
		return nil
	}

	// Create hooks.json
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", hooksDir, err)
	}

	hooksContent := `{
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "agentshield hook",
        "show_output": true
      }
    ]
  }
}
`
	if err := os.WriteFile(hooksPath, []byte(hooksContent), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", hooksPath, err)
	}

	fmt.Printf("✅ Cursor Hook installed: %s\n", hooksPath)
	fmt.Println()
	fmt.Println("How it works:")
	fmt.Println("  1. Cursor's Agent tries to run a command")
	fmt.Println("  2. The beforeShellExecution hook calls `agentshield hook`")
	fmt.Println("  3. AgentShield evaluates the command against your policy")
	fmt.Println("  4. If BLOCK: Agent is prevented from running the command")
	fmt.Println("  5. If ALLOW/AUDIT: the command runs normally")
	fmt.Println()
	fmt.Println("Restart Cursor to activate the hook, then test by asking")
	fmt.Println("Agent to run: rm -rf /")
	fmt.Println()
	printStatus()
	return nil
}

// ─── Generic Setup Instructions ─────────────────────────────────────────────

func printSetupInstructions() {
	wrapperPath := filepath.Join(getShareDir(), "agentshield-wrapper.sh")

	wrapperExists := false
	if _, err := os.Stat(wrapperPath); err == nil {
		wrapperExists = true
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield Setup Guide")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	if !wrapperExists {
		fmt.Println("⚠  Wrapper not installed. Run: agentshield setup --install")
		fmt.Println()
	}

	fmt.Println("─── Windsurf (Recommended) ───────────────────────────")
	fmt.Println()
	fmt.Println("  Uses native Cascade Hooks — no shell changes needed.")
	fmt.Println("  One command to install:")
	fmt.Println()
	fmt.Println("    agentshield setup windsurf")
	fmt.Println()

	fmt.Println("─── Cursor ───────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Uses native Cursor Hooks (beforeShellExecution).")
	fmt.Println("  One command to install:")
	fmt.Println()
	fmt.Println("    agentshield setup cursor")
	fmt.Println()

	fmt.Println("─── Claude Code ───────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Set the shell override in Claude Code settings:")
	fmt.Println()
	fmt.Printf("    \"shell\": \"%s\"\n", wrapperPath)
	fmt.Println()

	fmt.Println("─── Direct CLI Usage ─────────────────────────────────")
	fmt.Println()
	fmt.Println("  agentshield run -- <command>         # evaluate & run")
	fmt.Println("  agentshield run --shell -- \"cmd\"     # shell string mode")
	fmt.Println("  agentshield hook                     # Windsurf hook handler")
	fmt.Println("  agentshield log                      # view audit trail")
	fmt.Println("  agentshield log --summary            # audit summary")
	fmt.Println("  agentshield pack list                # show policy packs")
	fmt.Println()

	fmt.Println("─── Bypass Mode ──────────────────────────────────────")
	fmt.Println()
	fmt.Println("  export AGENTSHIELD_BYPASS=1    # temporarily disable")
	fmt.Println("  unset AGENTSHIELD_BYPASS       # re-enable")
	fmt.Println()

	fmt.Println("─── Current Status ───────────────────────────────────")
	fmt.Println()
	printStatus()
}

func printStatus() {
	cfg, _ := config.Load("", "", "")

	// Check binary
	binPath, err := exec.LookPath("agentshield")
	if err != nil {
		fmt.Println("  Binary:  ⚠  not found in PATH")
	} else {
		fmt.Printf("  Binary:  ✅ %s\n", binPath)
	}

	// Check wrapper
	wrapperPath := filepath.Join(getShareDir(), "agentshield-wrapper.sh")
	if _, err := os.Stat(wrapperPath); err == nil {
		fmt.Printf("  Wrapper: ✅ %s\n", wrapperPath)
	} else {
		fmt.Println("  Wrapper: ⚠  not installed")
	}

	// Check packs
	if cfg != nil {
		packsDir := filepath.Join(cfg.ConfigDir, "packs")
		entries, err := os.ReadDir(packsDir)
		if err == nil {
			count := 0
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") && !strings.HasPrefix(e.Name(), "_") {
					count++
				}
			}
			fmt.Printf("  Packs:   ✅ %d enabled in %s\n", count, packsDir)
		} else {
			fmt.Printf("  Packs:   ⚠  %s not found\n", packsDir)
		}

		// Check policy
		if _, err := os.Stat(cfg.PolicyPath); err == nil {
			fmt.Printf("  Policy:  ✅ %s\n", cfg.PolicyPath)
		} else {
			fmt.Println("  Policy:  ℹ  using built-in defaults")
		}
	}

	fmt.Println()
}

// getShareDir returns the platform-appropriate share directory for AgentShield.
func getShareDir() string {
	// Check if installed via Homebrew
	brewPrefix := os.Getenv("HOMEBREW_PREFIX")
	if brewPrefix == "" {
		if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" {
			brewPrefix = "/opt/homebrew"
		} else {
			brewPrefix = "/usr/local"
		}
	}
	return filepath.Join(brewPrefix, "share", "agentshield")
}

// findWrapperSource looks for the wrapper script in known locations.
func findWrapperSource() string {
	candidates := []string{
		filepath.Join(getShareDir(), "agentshield-wrapper.sh"),
	}

	// Check relative to binary
	if binPath, err := exec.LookPath("agentshield"); err == nil {
		binDir := filepath.Dir(binPath)
		candidates = append(candidates,
			filepath.Join(binDir, "..", "share", "agentshield", "agentshield-wrapper.sh"),
			filepath.Join(binDir, "..", "scripts", "agentshield-wrapper.sh"),
		)
	}

	// Check current working directory (for dev)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "scripts", "agentshield-wrapper.sh"))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// findPacksSource looks for bundled policy packs in known locations.
func findPacksSource() string {
	candidates := []string{
		filepath.Join(getShareDir(), "packs"),
	}

	if binPath, err := exec.LookPath("agentshield"); err == nil {
		binDir := filepath.Dir(binPath)
		candidates = append(candidates,
			filepath.Join(binDir, "..", "share", "agentshield", "packs"),
			filepath.Join(binDir, "..", "packs"),
		)
	}

	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "packs"))
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}

// installPacks copies pack files from src to dst, skipping files that already exist.
func installPacks(srcDir, dstDir string) int {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return 0
	}

	installed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		dstPath := filepath.Join(dstDir, e.Name())
		if _, err := os.Stat(dstPath); err == nil {
			continue // already exists
		}
		data, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
		if err != nil {
			continue
		}
		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Failed to install pack %s: %v\n", e.Name(), err)
			continue
		}
		installed++
	}
	return installed
}
