// Package codex adapts agentleash to OpenAI Codex CLI.
//
// Hooks: .codex/hooks.json -> PreToolUse (type "command"); each hook must be trusted once via /hooks.
// Env: .codex/config.toml -> shell_environment_policy.exclude.
// PreToolUse does NOT support "ask": map engine.Ask to deny with an explanatory reason.
// Docs: https://learn.chatgpt.com/docs/hooks.md
package codex

import (
	"errors"

	"github.com/nicosimoncinii/agentleash/internal/agents"
	"github.com/nicosimoncinii/agentleash/internal/engine"
	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// Adapter implements agents.Adapter for Codex.
type Adapter struct{}

var _ agents.Adapter = Adapter{}

func (Adapter) Name() string { return "codex" }

// TODO(codex): implement (issue: Codex adapter).
func (Adapter) DecodeHook(payload []byte, projectRoot, home string) (engine.Request, error) {
	return engine.Request{}, errors.New("not implemented")
}

// TODO(codex): implement.
func (Adapter) EncodeVerdict(v engine.Verdict) ([]byte, int) {
	return nil, 2
}

// TODO(codex): implement.
func (Adapter) Apply(projectRoot string, p *policy.Policy, binary string) ([]string, error) {
	return nil, errors.New("not implemented")
}

// TODO(codex): implement.
func (Adapter) Remove(projectRoot string) ([]string, error) {
	return nil, errors.New("not implemented")
}
