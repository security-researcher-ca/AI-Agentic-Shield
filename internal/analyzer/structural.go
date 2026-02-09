package analyzer

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// StructuralAnalyzer parses shell commands into an AST using mvdan.cc/sh/v3
// and performs structural checks that regex cannot: flag normalization, pipe
// target analysis, string-literal detection, path classification.
type StructuralAnalyzer struct {
	maxParseDepth int
	checks        []StructuralCheck
}

// StructuralCheck is a single structural detection rule implemented in Go.
// Each check receives the parsed command and returns zero or more findings.
type StructuralCheck interface {
	Name() string
	Check(parsed *ParsedCommand, raw string) []Finding
}

// NewStructuralAnalyzer creates a structural analyzer with built-in checks.
func NewStructuralAnalyzer(maxParseDepth int) *StructuralAnalyzer {
	if maxParseDepth <= 0 {
		maxParseDepth = 2
	}
	a := &StructuralAnalyzer{
		maxParseDepth: maxParseDepth,
	}
	a.checks = []StructuralCheck{
		&rmRecursiveRootCheck{},
		&rmSystemDirCheck{},
		&ddOutputTargetCheck{},
		&chmodSymbolicCheck{},
		&pipeToShellCheck{},
		&pipeToDangerousTargetCheck{},
	}
	return a
}

func (a *StructuralAnalyzer) Name() string { return "structural" }

// Analyze parses the command into an AST and runs structural checks.
// It enriches ctx.Parsed for downstream analyzers to consume.
func (a *StructuralAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	parsed := a.Parse(ctx.RawCommand)
	ctx.Parsed = parsed

	var findings []Finding
	for _, check := range a.checks {
		findings = append(findings, check.Check(parsed, ctx.RawCommand)...)
	}
	return findings
}

// Parse converts a raw command string into a ParsedCommand AST.
func (a *StructuralAnalyzer) Parse(command string) *ParsedCommand {
	return a.parseWithDepth(command, 0)
}

func (a *StructuralAnalyzer) parseWithDepth(command string, depth int) *ParsedCommand {
	if depth >= a.maxParseDepth {
		return nil
	}

	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil {
		// If the shell parser fails, fall back to simple splitting
		return a.fallbackParse(command)
	}

	pc := &ParsedCommand{}
	for _, stmt := range file.Stmts {
		a.walkStmt(pc, stmt, command, depth)
	}
	return pc
}

func (a *StructuralAnalyzer) walkStmt(pc *ParsedCommand, stmt *syntax.Stmt, raw string, depth int) {
	if stmt.Cmd == nil {
		return
	}

	// Collect redirects from the statement
	for _, redir := range stmt.Redirs {
		r := Redirect{Op: redirectOpString(redir)}
		if redir.Word != nil {
			r.Path = wordToString(redir.Word)
		}
		pc.Redirects = append(pc.Redirects, r)
	}

	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		seg := a.callExprToSegment(cmd, raw)
		// Check for indirect execution (bash -c, python -c, etc.)
		if seg.IsShell {
			inner := extractInlineCode(seg)
			if inner != "" {
				sub := a.parseWithDepth(inner, depth+1)
				if sub != nil {
					pc.Subcommands = append(pc.Subcommands, sub)
				}
			}
		}
		pc.Segments = append(pc.Segments, seg)

	case *syntax.BinaryCmd:
		// Handle pipelines and logical operators
		op := binaryOpString(cmd.Op)
		// Walk left and right, collecting segments
		leftPC := &ParsedCommand{}
		rightPC := &ParsedCommand{}
		a.walkStmt(leftPC, cmd.X, raw, depth)
		a.walkStmt(rightPC, cmd.Y, raw, depth)
		pc.Segments = append(pc.Segments, leftPC.Segments...)
		pc.Operators = append(pc.Operators, op)
		pc.Segments = append(pc.Segments, rightPC.Segments...)
		pc.Subcommands = append(pc.Subcommands, leftPC.Subcommands...)
		pc.Subcommands = append(pc.Subcommands, rightPC.Subcommands...)

	case *syntax.Subshell:
		for _, s := range cmd.Stmts {
			a.walkStmt(pc, s, raw, depth)
		}
	}
}

func (a *StructuralAnalyzer) callExprToSegment(call *syntax.CallExpr, raw string) CommandSegment {
	seg := CommandSegment{
		Flags: make(map[string]string),
	}

	words := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		words = append(words, wordToString(word))
	}

	if len(words) == 0 {
		return seg
	}

	seg.Executable = words[0]

	// Handle sudo: the real command is the first non-sudo-flag arg.
	// We simplify by treating sudo as transparent — skip sudo and its flags,
	// then re-assign the real executable.
	remaining := words[1:]
	if seg.Executable == "sudo" && len(remaining) > 0 {
		// Skip sudo flags (like -u, -E, etc.) to find the real command
		for len(remaining) > 0 {
			if strings.HasPrefix(remaining[0], "-") {
				remaining = remaining[1:]
			} else {
				break
			}
		}
		if len(remaining) > 0 {
			seg.Executable = remaining[0]
			remaining = remaining[1:]
		}
	}

	seg.IsShell = isShellInterpreter(seg.Executable)
	for i := 0; i < len(remaining); i++ {
		w := remaining[i]
		if strings.HasPrefix(w, "--") && len(w) > 2 {
			// Long flag: --recursive, --force, --registry=value
			flag := w[2:]
			if eqIdx := strings.Index(flag, "="); eqIdx >= 0 {
				seg.Flags[flag[:eqIdx]] = flag[eqIdx+1:]
			} else {
				seg.Flags[flag] = ""
			}
		} else if strings.HasPrefix(w, "-") && len(w) > 1 && !strings.HasPrefix(w, "--") {
			// Short flags: -rf, -r, -f
			// Each character is a separate flag
			for _, ch := range w[1:] {
				seg.Flags[string(ch)] = ""
			}
		} else {
			seg.Args = append(seg.Args, w)
		}
	}

	// Detect subcommand for known tools (npm install, pip install, etc.)
	if len(seg.Args) > 0 {
		if isSubcommandTool(seg.Executable) {
			seg.SubCommand = seg.Args[0]
			seg.Args = seg.Args[1:]
		}
	}

	// Build raw from original words
	seg.Raw = strings.Join(words, " ")
	return seg
}

// fallbackParse handles commands that mvdan.cc/sh can't parse.
func (a *StructuralAnalyzer) fallbackParse(command string) *ParsedCommand {
	pc := &ParsedCommand{}
	// Simple pipe splitting
	parts := strings.Split(command, "|")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		words := strings.Fields(part)
		seg := CommandSegment{
			Raw:        part,
			Executable: words[0],
			Flags:      make(map[string]string),
			IsShell:    isShellInterpreter(words[0]),
		}
		for _, w := range words[1:] {
			if strings.HasPrefix(w, "-") {
				for _, ch := range w[1:] {
					seg.Flags[string(ch)] = ""
				}
			} else {
				seg.Args = append(seg.Args, w)
			}
		}
		pc.Segments = append(pc.Segments, seg)
		if i < len(parts)-1 {
			pc.Operators = append(pc.Operators, "|")
		}
	}
	return pc
}

// ---------------------------------------------------------------------------
// Built-in structural checks
// ---------------------------------------------------------------------------

// rmRecursiveRootCheck detects rm with recursive+force flags targeting root.
// Fixes: FN-FSDESTR-002 (--recursive --force), FN-FSDESTR-003 (-r -f),
//
//	FN-FSDESTR-004 (rm -rf /*)
type rmRecursiveRootCheck struct{}

func (c *rmRecursiveRootCheck) Name() string { return "rm-recursive-root" }

func (c *rmRecursiveRootCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil {
		return nil
	}
	var findings []Finding
	for _, seg := range allSegments(parsed) {
		if seg.Executable != "rm" && seg.Executable != "sudo" {
			continue
		}
		// If sudo, check if the actual command is rm
		exec := seg.Executable
		args := seg.Args
		flags := seg.Flags
		if exec == "sudo" && len(args) > 0 && args[0] == "rm" {
			exec = "rm"
			// Re-parse remaining args as rm flags
			flags, args = reparseArgsAsFlags(args[1:])
		}
		if exec != "rm" {
			continue
		}

		hasRecursive := hasFlag(flags, "r") || hasFlag(flags, "R") || hasFlag(flags, "recursive")
		hasForce := hasFlag(flags, "f") || hasFlag(flags, "force")

		if !hasRecursive || !hasForce {
			continue
		}

		for _, arg := range args {
			if isRootTarget(arg) {
				findings = append(findings, Finding{
					AnalyzerName: "structural",
					RuleID:       "st-block-rm-recursive-root",
					Decision:     "BLOCK",
					Confidence:   0.95,
					Reason:       fmt.Sprintf("rm with recursive+force flags targeting root path: %s", arg),
					TaxonomyRef:  "destructive-ops/fs-destruction/recursive-root-delete",
					Tags:         []string{"destructive", "critical"},
				})
			}
		}
	}
	return findings
}

// rmSystemDirCheck detects rm with recursive+force targeting system directories.
// Fixes: FN-SYSDIR-004 (--recursive --force /boot)
type rmSystemDirCheck struct{}

func (c *rmSystemDirCheck) Name() string { return "rm-system-dir" }

func (c *rmSystemDirCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil {
		return nil
	}
	var findings []Finding
	for _, seg := range allSegments(parsed) {
		exec := seg.Executable
		args := seg.Args
		flags := seg.Flags
		if exec == "sudo" && len(args) > 0 && args[0] == "rm" {
			exec = "rm"
			flags, args = reparseArgsAsFlags(args[1:])
		}
		if exec != "rm" {
			continue
		}

		hasRecursive := hasFlag(flags, "r") || hasFlag(flags, "R") || hasFlag(flags, "recursive")
		hasForce := hasFlag(flags, "f") || hasFlag(flags, "force")
		if !hasRecursive || !hasForce {
			continue
		}

		for _, arg := range args {
			if isSystemDir(arg) {
				findings = append(findings, Finding{
					AnalyzerName: "structural",
					RuleID:       "st-block-rm-system-dir",
					Decision:     "BLOCK",
					Confidence:   0.95,
					Reason:       fmt.Sprintf("rm with recursive+force targeting system directory: %s", arg),
					TaxonomyRef:  "destructive-ops/fs-destruction/system-directory-delete",
					Tags:         []string{"destructive", "critical"},
				})
			}
		}
	}
	return findings
}

// ddOutputTargetCheck distinguishes dd writing to block devices (dangerous)
// from dd writing to regular files (benign).
// Fixes: FP-DISKWR-002 (dd if=/dev/zero of=./test.img)
type ddOutputTargetCheck struct{}

func (c *ddOutputTargetCheck) Name() string { return "dd-output-target" }

func (c *ddOutputTargetCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil {
		return nil
	}
	var findings []Finding
	for _, seg := range allSegments(parsed) {
		exec := seg.Executable
		if exec == "sudo" && len(seg.Args) > 0 && seg.Args[0] == "dd" {
			exec = "dd"
		}
		if exec != "dd" {
			continue
		}

		// dd uses key=value arguments, not standard flags.
		// Re-scan all args for if= and of= patterns.
		var ifPath, ofPath string
		allWords := append([]string{}, seg.Args...)
		// Also check flags map — some dd args parsed as flags by mistake
		for k, v := range seg.Flags {
			if v != "" {
				allWords = append(allWords, k+"="+v)
			}
		}
		for _, w := range allWords {
			if strings.HasPrefix(w, "if=") {
				ifPath = w[3:]
			} else if strings.HasPrefix(w, "of=") {
				ofPath = w[3:]
			}
		}

		hasDangerousInput := strings.HasPrefix(ifPath, "/dev/zero") ||
			strings.HasPrefix(ifPath, "/dev/urandom") ||
			strings.HasPrefix(ifPath, "/dev/random")

		if hasDangerousInput && ofPath != "" && !isBlockDevice(ofPath) {
			// dd to a regular file — this is an ALLOW (structural override)
			findings = append(findings, Finding{
				AnalyzerName: "structural",
				RuleID:       "st-allow-dd-to-file",
				Decision:     "ALLOW",
				Confidence:   0.90,
				Reason:       fmt.Sprintf("dd from %s to regular file %s (not a block device)", ifPath, ofPath),
				TaxonomyRef:  "destructive-ops/disk-ops/disk-overwrite",
				Tags:         []string{"structural-override"},
			})
		}
	}
	return findings
}

// chmodSymbolicCheck detects chmod a+rwx (equivalent to 777) on system paths.
// Fixes: FN-CHMOD-001 (chmod a+rwx /etc/passwd)
type chmodSymbolicCheck struct{}

func (c *chmodSymbolicCheck) Name() string { return "chmod-symbolic" }

func (c *chmodSymbolicCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil {
		return nil
	}
	var findings []Finding
	for _, seg := range allSegments(parsed) {
		exec := seg.Executable
		args := seg.Args
		if exec == "sudo" && len(args) > 0 && args[0] == "chmod" {
			exec = "chmod"
			args = args[1:]
		}
		if exec != "chmod" {
			continue
		}

		// Look for symbolic modes that are equivalent to 777
		for i, arg := range args {
			if isWorldWritableSymbolic(arg) {
				// Check if any subsequent arg is a system path
				for _, pathArg := range args[i+1:] {
					if isSystemPath(pathArg) {
						findings = append(findings, Finding{
							AnalyzerName: "structural",
							RuleID:       "st-block-chmod-world-writable",
							Decision:     "BLOCK",
							Confidence:   0.90,
							Reason:       fmt.Sprintf("chmod %s on system path %s (equivalent to 777)", arg, pathArg),
							TaxonomyRef:  "destructive-ops/permission-weakening/chmod-world-writable",
							Tags:         []string{"permission-weakening", "critical"},
						})
					}
				}
			}
		}
	}
	return findings
}

// pipeToShellCheck detects download-pipe-to-interpreter patterns.
// Catches python3, node, ruby, perl as pipe targets (regex only catches sh/bash/zsh).
// Fixes: FN-PIPESH-005 (curl ... | python3 -)
type pipeToShellCheck struct{}

func (c *pipeToShellCheck) Name() string { return "pipe-to-shell" }

func (c *pipeToShellCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil || len(parsed.Segments) < 2 {
		return nil
	}
	var findings []Finding
	for i := 0; i < len(parsed.Segments)-1; i++ {
		left := parsed.Segments[i]
		right := parsed.Segments[i+1]

		// Check if left is a download command and operator is pipe
		isDownload := isDownloadCommand(left.Executable)
		isPipe := i < len(parsed.Operators) && parsed.Operators[i] == "|"
		isInterpreter := isShellOrInterpreter(right.Executable)

		if isDownload && isPipe && isInterpreter {
			findings = append(findings, Finding{
				AnalyzerName: "structural",
				RuleID:       "st-block-pipe-to-interpreter",
				Decision:     "BLOCK",
				Confidence:   0.95,
				Reason: fmt.Sprintf("Download (%s) piped to interpreter (%s). "+
					"Download and inspect first.", left.Executable, right.Executable),
				TaxonomyRef: "unauthorized-execution/remote-code-exec/pipe-to-shell",
				Tags:        []string{"code-execution", "critical"},
			})
		}
	}
	return findings
}

// pipeToDangerousTargetCheck detects piping into dangerous commands (crontab, etc.)
// Fixes: FP-CRON-002 (echo "..." | crontab -)
type pipeToDangerousTargetCheck struct{}

func (c *pipeToDangerousTargetCheck) Name() string { return "pipe-to-dangerous-target" }

func (c *pipeToDangerousTargetCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil || len(parsed.Segments) < 2 {
		return nil
	}
	var findings []Finding
	for i := 0; i < len(parsed.Segments)-1; i++ {
		right := parsed.Segments[i+1]
		isPipe := i < len(parsed.Operators) && parsed.Operators[i] == "|"
		if !isPipe {
			continue
		}
		if isDangerousPipeTarget(right.Executable) {
			findings = append(findings, Finding{
				AnalyzerName: "structural",
				RuleID:       "st-audit-pipe-to-dangerous",
				Decision:     "AUDIT",
				Confidence:   0.85,
				Reason:       fmt.Sprintf("Pipe to %s — may modify system state via stdin", right.Executable),
				Tags:         []string{"pipe-target"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// wordToString converts a syntax.Word AST node to its string representation.
func wordToString(word *syntax.Word) string {
	var sb strings.Builder
	printer := syntax.NewPrinter()
	printer.Print(&sb, word)
	return sb.String()
}

func redirectOpString(redir *syntax.Redirect) string {
	switch {
	case redir.Op == syntax.RdrOut:
		return ">"
	case redir.Op == syntax.AppOut:
		return ">>"
	case redir.Op == syntax.RdrIn:
		return "<"
	default:
		return redir.Op.String()
	}
}

func binaryOpString(op syntax.BinCmdOperator) string {
	switch op {
	case syntax.Pipe:
		return "|"
	case syntax.AndStmt:
		return "&&"
	case syntax.OrStmt:
		return "||"
	default:
		return op.String()
	}
}

// allSegments returns all segments including those in subcommands.
func allSegments(parsed *ParsedCommand) []CommandSegment {
	if parsed == nil {
		return nil
	}
	segs := make([]CommandSegment, len(parsed.Segments))
	copy(segs, parsed.Segments)
	for _, sub := range parsed.Subcommands {
		segs = append(segs, allSegments(sub)...)
	}
	return segs
}

// reparseArgsAsFlags re-parses a list of args into flags and positional args.
// Used when sudo is stripped and remaining args need re-parsing.
func reparseArgsAsFlags(words []string) (map[string]string, []string) {
	flags := make(map[string]string)
	var args []string
	for _, w := range words {
		if strings.HasPrefix(w, "--") && len(w) > 2 {
			flag := w[2:]
			if eqIdx := strings.Index(flag, "="); eqIdx >= 0 {
				flags[flag[:eqIdx]] = flag[eqIdx+1:]
			} else {
				flags[flag] = ""
			}
		} else if strings.HasPrefix(w, "-") && len(w) > 1 {
			for _, ch := range w[1:] {
				flags[string(ch)] = ""
			}
		} else {
			args = append(args, w)
		}
	}
	return flags, args
}

var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true,
	"ksh": true, "fish": true, "csh": true, "tcsh": true,
}

var codeInterpreters = map[string]bool{
	"python": true, "python3": true, "python2": true,
	"node": true, "ruby": true, "perl": true, "lua": true,
	"php": true,
}

func isShellInterpreter(exe string) bool {
	return shellInterpreters[exe]
}

func isShellOrInterpreter(exe string) bool {
	return shellInterpreters[exe] || codeInterpreters[exe]
}

func isDownloadCommand(exe string) bool {
	switch exe {
	case "curl", "wget", "fetch", "aria2c":
		return true
	}
	return false
}

func isDangerousPipeTarget(exe string) bool {
	switch exe {
	case "crontab", "at", "tee", "dd", "mysql", "psql", "sqlite3":
		return true
	}
	return false
}

func isSubcommandTool(exe string) bool {
	switch exe {
	case "npm", "pip", "pip3", "yarn", "pnpm", "cargo", "go",
		"git", "docker", "kubectl", "brew", "apt", "apt-get",
		"systemctl", "service":
		return true
	}
	return false
}

func isRootTarget(path string) bool {
	cleaned := strings.TrimRight(path, "/")
	return cleaned == "" || cleaned == "/" || path == "/*"
}

var systemDirs = map[string]bool{
	"/etc": true, "/usr": true, "/usr/local": true, "/var": true,
	"/boot": true, "/sys": true, "/proc": true, "/lib": true,
	"/lib64": true, "/sbin": true, "/bin": true, "/opt": true,
	"/var/log": true, "/usr/bin": true, "/usr/lib": true,
}

func isSystemDir(path string) bool {
	cleaned := strings.TrimRight(path, "/")
	return systemDirs[cleaned]
}

func isSystemPath(path string) bool {
	if isSystemDir(path) {
		return true
	}
	// Check if path is under a system directory
	for dir := range systemDirs {
		if strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return path == "/" || path == "/*"
}

func isBlockDevice(path string) bool {
	return strings.HasPrefix(path, "/dev/sd") ||
		strings.HasPrefix(path, "/dev/hd") ||
		strings.HasPrefix(path, "/dev/nvme") ||
		strings.HasPrefix(path, "/dev/vd") ||
		strings.HasPrefix(path, "/dev/xvd") ||
		strings.HasPrefix(path, "/dev/md") ||
		strings.HasPrefix(path, "/dev/dm-") ||
		strings.HasPrefix(path, "/dev/loop")
}

// hasFlag checks if a flag key exists in the flags map.
// Flags are stored with empty string values, so key existence is the test.
func hasFlag(flags map[string]string, key string) bool {
	_, ok := flags[key]
	return ok
}

func isWorldWritableSymbolic(mode string) bool {
	// Matches: a+rwx, o+w, a+w, ugo+rwx, etc.
	mode = strings.ToLower(mode)
	// Quick numeric check
	if mode == "777" || mode == "0777" {
		return true
	}
	// Symbolic: "a+rwx", "a+w", "+rwx" (no user spec = all)
	if strings.Contains(mode, "a+") && strings.Contains(mode, "w") {
		return true
	}
	// "o+w" — other+write is world writable
	if strings.Contains(mode, "o+") && strings.Contains(mode, "w") {
		return true
	}
	// "+rwx" with no user prefix means all
	if strings.HasPrefix(mode, "+") && strings.Contains(mode, "w") {
		return true
	}
	return false
}

// extractInlineCode extracts the code argument from interpreters that accept
// inline code: bash -c 'code', python -c 'code', etc.
func extractInlineCode(seg CommandSegment) string {
	if !seg.IsShell && !codeInterpreters[seg.Executable] {
		return ""
	}
	// Look for -c flag followed by code argument
	if _, hasC := seg.Flags["c"]; hasC {
		// The code is typically the first positional arg after -c
		if len(seg.Args) > 0 {
			return seg.Args[0]
		}
	}
	return ""
}
