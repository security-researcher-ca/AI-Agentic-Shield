package approval

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

type Result struct {
	Approved   bool
	UserAction string
}

type Prompt struct {
	Command        string
	TriggeredRules []string
	Reasons        []string
	Explanation    string
}

func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func Ask(p Prompt) Result {
	if !IsInteractive() {
		return Result{
			Approved:   false,
			UserAction: "auto_deny_non_interactive",
		}
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "╔══════════════════════════════════════════════════════════════╗")
	fmt.Fprintln(os.Stderr, "║              ⚠️  APPROVAL REQUIRED                            ║")
	fmt.Fprintln(os.Stderr, "╚══════════════════════════════════════════════════════════════╝")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "Command: %s\n", p.Command)
	fmt.Fprintln(os.Stderr, "")

	if len(p.TriggeredRules) > 0 {
		fmt.Fprintf(os.Stderr, "Triggered rules: %s\n", strings.Join(p.TriggeredRules, ", "))
	}

	if len(p.Reasons) > 0 {
		fmt.Fprintln(os.Stderr, "Reasons:")
		for _, reason := range p.Reasons {
			fmt.Fprintf(os.Stderr, "  • %s\n", reason)
		}
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "  [a] Approve once - execute this command")
	fmt.Fprintln(os.Stderr, "  [d] Deny - block this command")
	fmt.Fprintln(os.Stderr, "")

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Fprint(os.Stderr, "Your choice [a/d]: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return Result{
				Approved:   false,
				UserAction: "error_reading_input",
			}
		}

		input = strings.TrimSpace(strings.ToLower(input))

		switch input {
		case "a", "approve", "yes", "y":
			return Result{
				Approved:   true,
				UserAction: "approve_once",
			}
		case "d", "deny", "no", "n":
			return Result{
				Approved:   false,
				UserAction: "deny",
			}
		default:
			fmt.Fprintln(os.Stderr, "Invalid input. Please enter 'a' to approve or 'd' to deny.")
		}
	}
}
