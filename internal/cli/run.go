package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gzhole/agentshield/internal/approval"
	"github.com/gzhole/agentshield/internal/config"
	"github.com/gzhole/agentshield/internal/logger"
	"github.com/gzhole/agentshield/internal/normalize"
	"github.com/gzhole/agentshield/internal/policy"
	"github.com/gzhole/agentshield/internal/sandbox"
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

	// Load policy
	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
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
		Mode:           cfg.Mode,
		UserAction:     "",
	}

	// Handle decision
	switch evalResult.Decision {
	case policy.DecisionBlock:
		fmt.Fprintln(os.Stderr, "\n❌ BLOCKED by AgentShield")
		fmt.Fprintln(os.Stderr, evalResult.Explanation)
		if err := auditLogger.Log(event); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write audit log: %v\n", err)
		}
		os.Exit(1)

	case policy.DecisionRequireApproval:
		prompt := approval.Prompt{
			Command:        cmdStr,
			TriggeredRules: evalResult.TriggeredRules,
			Reasons:        evalResult.Reasons,
			Explanation:    evalResult.Explanation,
		}

		result := approval.Ask(prompt)
		event.UserAction = result.UserAction

		if !result.Approved {
			fmt.Fprintln(os.Stderr, "\n❌ Command denied by user")
			if err := auditLogger.Log(event); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to write audit log: %v\n", err)
			}
			os.Exit(1)
		}

		// User approved - execute the command
		fmt.Fprintln(os.Stderr, "\n✅ Approved - executing command...")
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

	case policy.DecisionSandbox:
		fmt.Fprintln(os.Stderr, "\n🔒 SANDBOX MODE")
		fmt.Fprintln(os.Stderr, evalResult.Explanation)
		fmt.Fprintln(os.Stderr, "Running command in sandbox to preview changes...")

		runner, err := sandbox.NewRunner(cwd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create sandbox: %v\n", err)
			event.UserAction = "sandbox_error"
			event.Error = err.Error()
			auditLogger.Log(event)
			os.Exit(1)
		}
		defer runner.Cleanup()

		result := runner.Run(args)

		fmt.Fprintln(os.Stderr, "\n� Sandbox Results:")
		fmt.Fprintln(os.Stderr, result.DiffSummary)

		if len(result.ChangedFiles) == 0 {
			fmt.Fprintln(os.Stderr, "No changes detected. Nothing to apply.")
			event.UserAction = "sandbox_no_changes"
			auditLogger.Log(event)
			return nil
		}

		prompt := approval.Prompt{
			Command:        cmdStr,
			TriggeredRules: evalResult.TriggeredRules,
			Reasons:        []string{"Review the changes above before applying"},
		}

		approvalResult := approval.Ask(prompt)
		event.UserAction = "sandbox_" + approvalResult.UserAction

		if !approvalResult.Approved {
			fmt.Fprintln(os.Stderr, "\n❌ Changes not applied")
			auditLogger.Log(event)
			os.Exit(1)
		}

		fmt.Fprintln(os.Stderr, "\n✅ Applying changes to real workspace...")
		if err := runner.Apply(args); err != nil {
			event.Error = err.Error()
			auditLogger.Log(event)
			fmt.Fprintf(os.Stderr, "Error applying changes: %v\n", err)
			os.Exit(1)
		}

		auditLogger.Log(event)
		fmt.Fprintln(os.Stderr, "Changes applied successfully.")

	case policy.DecisionAllow:
		// Execute the command
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
