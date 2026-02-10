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
	Long: `Install or remove Cascade Hooks so every command Windsurf's AI agent
runs is evaluated by AgentShield before execution.

  agentshield setup windsurf             # enable hooks
  agentshield setup windsurf --disable   # disable hooks`,
	RunE: setupWindsurfCommand,
}

var setupCursorCmd = &cobra.Command{
	Use:   "cursor",
	Short: "Set up AgentShield for Cursor IDE",
	Long: `Install or remove Cursor Hooks so every command Cursor's AI agent
runs is evaluated by AgentShield before execution.

  agentshield setup cursor             # enable hooks
  agentshield setup cursor --disable   # disable hooks`,
	RunE: setupCursorCommand,
}

var setupOpenClawCmd = &cobra.Command{
	Use:   "openclaw",
	Short: "Set up AgentShield for OpenClaw gateway",
	Long: `Install an OpenClaw hook that routes every agent exec call through
AgentShield's 6-layer security pipeline.

  agentshield setup openclaw             # install hook
  agentshield setup openclaw --disable   # remove hook`,
	RunE: setupOpenClawCommand,
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up AgentShield for your environment",
	Long: `Set up AgentShield integration with IDE agents and install default policy packs.

IDE-specific setup:
  agentshield setup windsurf              # install Cascade Hooks
  agentshield setup windsurf --disable    # remove Cascade Hooks
  agentshield setup cursor                # install Cursor Hooks
  agentshield setup cursor --disable      # remove Cursor Hooks
  agentshield setup openclaw              # install OpenClaw Hook
  agentshield setup openclaw --disable    # remove OpenClaw Hook

General setup:
  agentshield setup --install   # install wrapper + policy packs
  agentshield setup             # show all integration instructions`,
	RunE: setupCommand,
}

var (
	installFlag bool
	disableFlag bool
)

func init() {
	setupCmd.Flags().BoolVar(&installFlag, "install", false, "Install wrapper script and default policy packs")
	setupWindsurfCmd.Flags().BoolVar(&disableFlag, "disable", false, "Remove AgentShield hooks and disable integration")
	setupCursorCmd.Flags().BoolVar(&disableFlag, "disable", false, "Remove AgentShield hooks and disable integration")
	setupOpenClawCmd.Flags().BoolVar(&disableFlag, "disable", false, "Remove AgentShield hooks and disable integration")
	setupCmd.AddCommand(setupWindsurfCmd)
	setupCmd.AddCommand(setupCursorCmd)
	setupCmd.AddCommand(setupOpenClawCmd)
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

// ─── Shared Disable Logic ────────────────────────────────────────────────────

func disableHook(hooksPath, ideName string) error {
	backupPath := hooksPath + ".bak"

	if _, err := os.Stat(hooksPath); os.IsNotExist(err) {
		fmt.Printf("ℹ  No hooks.json found for %s — nothing to disable.\n", ideName)
		return nil
	}

	data, err := os.ReadFile(hooksPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", hooksPath, err)
	}

	if !strings.Contains(string(data), "agentshield hook") {
		fmt.Printf("ℹ  %s hooks.json does not contain AgentShield — nothing to disable.\n", ideName)
		return nil
	}

	// Back up then remove
	if err := os.Rename(hooksPath, backupPath); err != nil {
		return fmt.Errorf("failed to rename %s: %w", hooksPath, err)
	}

	fmt.Printf("✅ AgentShield hook disabled for %s\n", ideName)
	fmt.Printf("   Backup saved: %s\n", backupPath)
	fmt.Println()
	fmt.Printf("Restart %s to apply. Re-enable anytime with:\n", ideName)
	fmt.Printf("  agentshield setup %s\n", strings.ToLower(ideName))
	return nil
}

// ─── Windsurf Setup ─────────────────────────────────────────────────────────

func setupWindsurfCommand(cmd *cobra.Command, args []string) error {
	hooksPath := filepath.Join(os.Getenv("HOME"), ".codeium", "windsurf", "hooks.json")
	hooksDir := filepath.Dir(hooksPath)

	if disableFlag {
		return disableHook(hooksPath, "Windsurf")
	}

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
			fmt.Println("To disable: agentshield setup windsurf --disable")
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
	fmt.Println("To disable: agentshield setup windsurf --disable")
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

	if disableFlag {
		return disableHook(hooksPath, "Cursor")
	}

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
			fmt.Println("To disable: agentshield setup cursor --disable")
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
	fmt.Println("To disable: agentshield setup cursor --disable")
	fmt.Println()
	fmt.Println("Restart Cursor to activate the hook, then test by asking")
	fmt.Println("Agent to run: rm -rf /")
	fmt.Println()
	printStatus()
	return nil
}

// ─── OpenClaw Setup ─────────────────────────────────────────────────────────

func setupOpenClawCommand(cmd *cobra.Command, args []string) error {
	hookDir := filepath.Join(os.Getenv("HOME"), ".openclaw", "hooks", "agentshield")

	if disableFlag {
		return disableOpenClawHook(hookDir)
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + OpenClaw")
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

	// Check if openclaw is installed
	clawPath, err := exec.LookPath("openclaw")
	if err != nil {
		fmt.Println("⚠  openclaw not found in PATH. Install it first:")
		fmt.Println("   brew install openclaw")
		return nil
	}
	fmt.Printf("✅ openclaw found: %s\n", clawPath)

	// Check if hook already installed
	hookMd := filepath.Join(hookDir, "HOOK.md")
	if _, err := os.Stat(hookMd); err == nil {
		fmt.Printf("✅ AgentShield hook already installed: %s\n", hookDir)
		fmt.Println()
		fmt.Println("Hook is installed. Enable it and restart the gateway:")
		fmt.Println("  openclaw hooks enable agentshield")
		fmt.Println()
		fmt.Println("To disable: agentshield setup openclaw --disable")
		fmt.Println()
		printStatus()
		return nil
	}

	// Find the hook pack source
	hookSrc := findOpenClawHookSource()
	if hookSrc == "" {
		fmt.Println("⚠  Could not find openclaw-hook source directory.")
		fmt.Println("   Try installing from the repo:")
		fmt.Println("   openclaw hooks install /path/to/Agentic-gateway/openclaw-hook")
		return nil
	}

	// Copy hook files to ~/.openclaw/hooks/agentshield/
	if err := os.MkdirAll(hookDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", hookDir, err)
	}

	hookFiles := []string{"HOOK.md", "handler.ts", "AGENTSHIELD.md"}
	for _, f := range hookFiles {
		src := filepath.Join(hookSrc, "agentshield", f)
		dst := filepath.Join(hookDir, f)
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", src, err)
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", dst, err)
		}
	}

	fmt.Printf("✅ Hook installed: %s\n", hookDir)
	fmt.Println()

	// Try to enable the hook via openclaw CLI
	enableCmd := exec.Command("openclaw", "hooks", "enable", "agentshield")
	enableOut, err := enableCmd.CombinedOutput()
	if err != nil {
		fmt.Println("⚠  Could not auto-enable hook. Enable it manually:")
		fmt.Println("   openclaw hooks enable agentshield")
	} else {
		outStr := strings.TrimSpace(string(enableOut))
		if outStr != "" {
			// Print the last meaningful line (skip the OpenClaw banner)
			lines := strings.Split(outStr, "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				line := strings.TrimSpace(lines[i])
				if line != "" && !strings.HasPrefix(line, "🦞") && !strings.HasPrefix(line, "(node:") {
					fmt.Printf("✅ %s\n", line)
					break
				}
			}
		}
	}

	// Install policy packs
	cfg, _ := config.Load("", "", "")
	if cfg != nil {
		packsDir := filepath.Join(cfg.ConfigDir, "packs")
		if err := os.MkdirAll(packsDir, 0755); err == nil {
			packsSrc := findPacksSource()
			if packsSrc != "" {
				installed := installPacks(packsSrc, packsDir)
				if installed > 0 {
					fmt.Printf("✅ %d policy packs installed to %s\n", installed, packsDir)
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("How it works:")
	fmt.Println("  1. OpenClaw starts a session with the agent")
	fmt.Println("  2. AgentShield hook injects security instructions (AGENTSHIELD.md)")
	fmt.Println("  3. Agent wraps all exec calls through `agentshield run --`")
	fmt.Println("  4. Each command is evaluated by the 6-layer security pipeline")
	fmt.Println("  5. Dangerous commands are blocked before execution")
	fmt.Println()
	fmt.Println("Restart the OpenClaw gateway to activate the hook.")
	fmt.Println()
	fmt.Println("To disable: agentshield setup openclaw --disable")
	fmt.Println()
	printStatus()
	return nil
}

func disableOpenClawHook(hookDir string) error {
	hookMd := filepath.Join(hookDir, "HOOK.md")
	if _, err := os.Stat(hookMd); os.IsNotExist(err) {
		fmt.Println("ℹ  No AgentShield hook found for OpenClaw — nothing to disable.")
		return nil
	}

	// Try to disable via openclaw CLI first
	disCmd := exec.Command("openclaw", "hooks", "disable", "agentshield")
	_ = disCmd.Run() // ignore errors — hook dir removal is the real action

	// Remove the hook directory
	backupDir := hookDir + ".bak"
	if err := os.Rename(hookDir, backupDir); err != nil {
		return fmt.Errorf("failed to remove hook: %w", err)
	}

	fmt.Println("✅ AgentShield hook disabled for OpenClaw")
	fmt.Printf("   Backup saved: %s\n", backupDir)
	fmt.Println()
	fmt.Println("Restart the OpenClaw gateway to apply.")
	fmt.Println("Re-enable anytime with: agentshield setup openclaw")
	return nil
}

// findOpenClawHookSource looks for the openclaw-hook directory in known locations.
func findOpenClawHookSource() string {
	candidates := []string{
		filepath.Join(getShareDir(), "openclaw-hook"),
	}

	// Check relative to binary
	if binPath, err := exec.LookPath("agentshield"); err == nil {
		binDir := filepath.Dir(binPath)
		candidates = append(candidates,
			filepath.Join(binDir, "..", "share", "agentshield", "openclaw-hook"),
			filepath.Join(binDir, "..", "openclaw-hook"),
		)
	}

	// Check current working directory (for dev)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "openclaw-hook"))
	}

	for _, c := range candidates {
		hookMd := filepath.Join(c, "agentshield", "HOOK.md")
		if _, err := os.Stat(hookMd); err == nil {
			return c
		}
	}
	return ""
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

	fmt.Println("─── OpenClaw ──────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Uses native OpenClaw Hooks (agent:bootstrap).")
	fmt.Println("  One command to install:")
	fmt.Println()
	fmt.Println("    agentshield setup openclaw")
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

	fmt.Println("─── Disable / Re-enable ──────────────────────────────")
	fmt.Println()
	fmt.Println("  # Remove hooks (permanent until re-enabled):")
	fmt.Println("  agentshield setup windsurf --disable")
	fmt.Println("  agentshield setup cursor   --disable")
	fmt.Println()
	fmt.Println("  # Quick bypass (env var, current session only):")
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
