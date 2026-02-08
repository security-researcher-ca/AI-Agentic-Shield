package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gzhole/agentshield/internal/config"
	"github.com/gzhole/agentshield/internal/logger"
	"github.com/gzhole/agentshield/internal/normalize"
	"github.com/gzhole/agentshield/internal/policy"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Run a command through AgentShield",
	Long: `Run a command through AgentShield's policy enforcement layer.
The command and its arguments should be provided after --.

Example:
  agentshield run -- echo "hello world"
  agentshield run --policy ./custom.yaml -- npm install lodash`,
	RunE: runCommand,
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func runCommand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command provided. Usage: agentshield run -- <command> [args...]")
	}

	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	auditLogger, err := logger.New(cfg.LogPath)
	if err != nil {
		return fmt.Errorf("failed to initialize audit logger: %w", err)
	}
	defer auditLogger.Close()

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "unknown"
	}

	cmdStr := strings.Join(args, " ")

	// Normalize command
	normalized := normalize.Normalize(args, cwd)

	// Load base policy
	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	// Merge enabled policy packs
	packsPath := filepath.Join(cfg.ConfigDir, "packs")
	pol, _, err = policy.LoadPacks(packsPath, pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to load packs: %v\n", err)
	}

	engine, err := policy.NewEngine(pol)
	if err != nil {
		return fmt.Errorf("failed to create policy engine: %w", err)
	}

	// Evaluate policy with extracted paths
	evalResult := engine.Evaluate(cmdStr, normalized.Paths)

	event := logger.AuditEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Command:        cmdStr,
		Args:           args,
		Cwd:            cwd,
		Decision:       string(evalResult.Decision),
		TriggeredRules: evalResult.TriggeredRules,
		Reasons:        evalResult.Reasons,
		Mode:           cfg.Mode,
	}

	// Handle decision
	switch evalResult.Decision {
	case policy.DecisionBlock:
		fmt.Fprintln(os.Stderr, "\n\xf0\x9f\x9b\x91 BLOCKED by AgentShield")
		fmt.Fprintln(os.Stderr, evalResult.Explanation)
		if err := auditLogger.Log(event); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write audit log: %v\n", err)
		}
		os.Exit(1)

	case policy.DecisionAudit, policy.DecisionAllow:
		// Both AUDIT and ALLOW execute the command.
		// AUDIT adds a flag marker in the log for review.
		if evalResult.Decision == policy.DecisionAudit {
			event.Flagged = true
		}

		execCmd := exec.Command(args[0], args[1:]...)
		execCmd.Stdin = os.Stdin
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr

		execErr := execCmd.Run()
		if execErr != nil {
			event.Error = execErr.Error()
		}

		if err := auditLogger.Log(event); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write audit log: %v\n", err)
		}

		if execErr != nil {
			if exitErr, ok := execErr.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return execErr
		}
	}

	return nil
}
