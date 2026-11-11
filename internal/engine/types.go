// Package engine contains agentleash's pure decision logic.
//
// Agents translate their hook payloads into a Request; the engine returns a Verdict.
// The engine never knows which agent is calling.
package engine

// Decision is the outcome of evaluating a Request.
type Decision string

const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Deny  Decision = "deny"
)

// ToolKind classifies the agent tool being invoked.
type ToolKind string

const (
	// ToolShell is a shell command (Claude Code Bash/PowerShell, Codex Bash/exec_command).
	ToolShell ToolKind = "shell"
	// ToolRead reads file contents (Read).
	ToolRead ToolKind = "read"
	// ToolSearch searches file contents or names (Grep, Glob).
	ToolSearch ToolKind = "search"
	// ToolWrite creates or modifies files (Edit, Write, apply_patch).
	ToolWrite ToolKind = "write"
	// ToolOther is any other tool; allowed unless future rules say otherwise.
	ToolOther ToolKind = "other"
)

// Shell identifies the shell dialect of a ToolShell command.
type Shell string

const (
	ShellBash       Shell = "bash"
	ShellPowerShell Shell = "powershell"
)

// Request is an agent-independent description of a tool call.
type Request struct {
	Tool ToolKind
	// Command is the raw command text for ToolShell.
	Command string
	// Shell is the dialect of Command (defaults to bash).
	Shell Shell
	// Paths are the file or directory paths touched by non-shell tools.
	Paths []string
	// Cwd is the working directory of the call (absolute).
	Cwd string
	// ProjectRoot is where .agentleash.yaml lives; relative secret globs are anchored here.
	ProjectRoot string
	// Home is the user's home directory, used to expand "~/".
	Home string
}

// Verdict is the engine's answer.
type Verdict struct {
	Decision Decision
	// Reason is shown to the agent: what was blocked and how to proceed.
	Reason string
	// Rule is the policy entry that triggered the decision (empty for Allow).
	Rule string
}
