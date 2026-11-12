// Package claude adapts agentleash to Claude Code.
//
// Hook: .claude/settings.json -> hooks.PreToolUse[], an exec-form command handler
// ({"command": <binary>, "args": ["hook", "claude"], "onFailure": "block"}).
// Native rules: a block of permissions.deny Read(...)/Edit(...) rules for secret globs,
// with Read(!...)/Edit(!...) carve-outs for allow_files, placed before the user's rules.
// The rules agentleash owns are recorded in .claude/agentleash-state.json.
// Docs: https://code.claude.com/docs/en/hooks , https://code.claude.com/docs/en/permissions
package claude

import (
	"github.com/nicosimoncinii/agentleash/internal/agents"
)

// Adapter implements agents.Adapter for Claude Code.
type Adapter struct{}

var _ agents.Adapter = Adapter{}

// Name returns the CLI identifier of this adapter.
func (Adapter) Name() string { return "claude" }
