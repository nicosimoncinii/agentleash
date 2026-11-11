// Package claude adapts agentleash to Claude Code.
//
// Hooks: .claude/settings.json -> hooks.PreToolUse[] (type "command", onFailure "block").
// Native rules: permissions.deny "Read(<glob>)".
// Docs: https://code.claude.com/docs/en/hooks , https://code.claude.com/docs/en/permissions
package claude

import (
	"errors"

	"github.com/nicosimoncinii/agentleash/internal/agents"
	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// Adapter implements agents.Adapter for Claude Code.
type Adapter struct{}

var _ agents.Adapter = Adapter{}

func (Adapter) Name() string { return "claude" }

// TODO(claude): implement (issue: Claude Code adapter).
func (Adapter) DecodeHook(payload []byte, projectRoot, home string) (engine.Request, error) {
	return engine.Request{}, errors.New("not implemented")
}

// TODO(claude): implement.
func (Adapter) EncodeVerdict(v engine.Verdict) ([]byte, int) {
	return nil, 2
}

// TODO(claude): implement.
func (Adapter) Apply(projectRoot string, p *policy.Policy, binary string) ([]string, error) {
	return nil, errors.New("not implemented")
}

// TODO(claude): implement.
func (Adapter) Remove(projectRoot string) ([]string, error) {
	return nil, errors.New("not implemented")
}
