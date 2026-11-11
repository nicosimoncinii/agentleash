package engine

import (
	"github.com/nicosimoncinii/agentleash/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

// Engine evaluates requests against a policy. It is safe for concurrent use.
type Engine struct {
	policy *policy.Policy
}

// New builds an Engine for a validated policy.
func New(p *policy.Policy) *Engine {
	return &Engine{policy: p}
}

// Evaluate decides whether a tool call may proceed.
// Precedence: deny > ask > allow. Fails closed on any doubt.
// TODO(engine): implement (issue: engine).
func (e *Engine) Evaluate(req Request) Verdict {
	if req.Tool == ToolShell {
		if _, err := syntax.NewParser().Parse(stringsReader(req.Command), ""); err != nil {
			return Verdict{Decision: Deny, Reason: "agentleash: could not parse shell command; blocked to be safe", Rule: "parse-error"}
		}
	}
	return Verdict{Decision: Allow}
}
