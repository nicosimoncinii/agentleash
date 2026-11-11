// Package agents defines the contract every coding-agent adapter implements.
package agents

import (
	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// HookMarker is contained in every hook command agentleash installs. It lets Apply
// recognise (and update or remove) its own entries without touching the user's.
const HookMarker = "agentleash hook"

// Adapter connects agentleash to one coding agent.
type Adapter interface {
	// Name is the CLI identifier, e.g. "claude" or "codex".
	Name() string

	// DecodeHook converts the agent's PreToolUse stdin payload into an engine.Request.
	// projectRoot and home are used to fill Request.ProjectRoot and Request.Home.
	DecodeHook(payload []byte, projectRoot, home string) (engine.Request, error)

	// EncodeVerdict converts a verdict into the agent's expected stdout and process exit code.
	EncodeVerdict(v engine.Verdict) (stdout []byte, exitCode int)

	// Apply installs native rules and the hook into projectRoot, merging with existing
	// configuration. binary is the command used to invoke agentleash (e.g. its absolute path).
	// It returns the files it changed. It must be idempotent.
	Apply(projectRoot string, p *policy.Policy, binary string) (changed []string, err error)

	// Remove deletes everything Apply installed, leaving user configuration intact.
	Remove(projectRoot string) (changed []string, err error)
}
