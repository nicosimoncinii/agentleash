package engine

import (
	"fmt"
	"strings"

	"github.com/nicosimoncinii/agentleash/internal/policy"
)

// maxDepth bounds recursion into nested shells (sh -c, eval, pwsh -c, ...).
// Deeper nesting is denied.
const maxDepth = 8

// Engine evaluates requests against a policy. It is safe for concurrent use.
type Engine struct {
	policy  *policy.Policy
	resolve func(string) (string, error)
	// protect analyses write-protected files (protect.go); nil inside it.
	protect *Engine
	// touch is set on the protect engine: see secretSet.touch.
	touch bool
}

// Option configures an Engine.
type Option func(*Engine)

// WithSymlinkResolver injects a function (typically filepath.EvalSymlinks)
// used to resolve concrete argument paths before matching them against
// secret globs. Without it the engine performs no filesystem access at all.
// Errors (e.g. the file does not exist) are ignored.
func WithSymlinkResolver(fn func(string) (string, error)) Option {
	return func(e *Engine) { e.resolve = fn }
}

// New builds an Engine for a validated policy.
func New(p *policy.Policy, opts ...Option) *Engine {
	e := &Engine{policy: p}
	for _, o := range opts {
		o(e)
	}
	e.protect = newProtectEngine(p, e.resolve)
	return e
}

// Evaluate decides whether a tool call may proceed.
// Precedence: deny > ask > allow. Fails closed on any doubt.
func (e *Engine) Evaluate(req Request) (v Verdict) {
	c, exhausted := e.analyse(req)
	if exhausted {
		// Analysis stopped early: whatever was found so far is incomplete.
		return Verdict{Decision: Deny, Rule: RuleTooComplex, Reason: reasonPrefix + tooComplexReason}
	}
	v = c.verdict()
	if v.Decision != Deny {
		// A protect ask does not replace an existing ask (keep its reason).
		if pv, ok := e.protectedVerdict(req); ok && (v.Decision == Allow || pv.Decision == Deny) {
			return pv
		}
	}
	return v
}

// analyse runs the checks and returns every finding. exhausted reports that
// the work budget ran out (the findings are then incomplete).
func (e *Engine) analyse(req Request) (c *collector, exhausted bool) {
	c = &collector{}
	defer func() {
		if r := recover(); r != nil {
			c = &collector{}
			c.deny(RuleInternal, fmt.Sprintf("internal error while checking this call (%v); blocked to be safe. Try a simpler command.", r))
			exhausted = false
		}
	}()
	if e == nil || e.policy == nil {
		c.deny(RuleNoPolicy, "no policy is loaded; blocked to be safe. Run `agentleash doctor`.")
		return c, false
	}
	sec := newSecretSet(e.policy, req, e.resolve)
	sec.touch = e.touch
	switch req.Tool {
	case ToolShell:
		if len(req.Command) > maxCommandBytes {
			c.deny(RuleTooComplex, tooComplexReason)
			break
		}
		e.evalShell(req, sec, c)
	case ToolRead:
		evalPaths(req.Paths, sec, c, "reading", false)
	case ToolWrite:
		evalPaths(req.Paths, sec, c, "writing", false)
	case ToolSearch:
		evalPaths(req.Paths, sec, c, "searching", true)
	case ToolOther:
	default:
		c.deny(RuleUnknownTool, fmt.Sprintf("unknown tool kind %q; blocked to be safe.", display(string(req.Tool))))
	}
	return c, sec.work.exhausted()
}

func (e *Engine) evalShell(req Request, sec *secretSet, c *collector) {
	// Paths touched by the shell call itself (e.g. Codex apply_patch run
	// through exec_command) are checked like file-tool paths.
	evalPaths(req.Paths, sec, c, "modifying", false)
	switch req.Shell {
	case ShellBash, "":
		newShellEval(e, sec, c, 0).withReq(req).run(req.Command)
	case ShellPowerShell:
		pe := newPwshEval(e, sec, c, 0)
		pe.req = req
		if !pe.run(req.Command) {
			c.deny(RuleParseError, "could not tokenize the PowerShell command (unterminated quote or here-string), so it was blocked to be safe.")
		}
	default:
		e.evalAuto(req, sec, c)
	}
}

// evalAuto handles ShellAuto (and unknown dialects): the command is analysed
// as bash, as PowerShell and with a cmd.exe pass; the strictest verdict
// wins. A dialect that fails to parse contributes nothing, but then a raw
// lexical check also runs; if no dialect parses, the call is denied.
//
// When bash parses cleanly, bash already analysed every argument: here-doc
// bodies are blanked out and the PowerShell/cmd passes only look at
// constructs specific to those dialects ($env:, %VAR%, cmdlets, type, ...),
// so commit messages or printf data mentioning ".env" are not treated as
// arguments by the other dialects.
func (e *Engine) evalAuto(req Request, sec *secretSet, c *collector) {
	sh := newShellEval(e, sec, c, 0).withReq(req)
	sh.ignoreParseErrors = true
	bashOK := sh.run(req.Command)
	text := req.Command
	if bashOK {
		text = blankHeredocs(req.Command)
	}
	pe := newPwshEval(e, sec, c, 0)
	pe.req = req
	pe.restricted = bashOK
	psOK := sec.work.exhausted() || pe.run(text)
	cmdOK := sec.work.exhausted() || evalCmdText(e, req, sec, c, 0, text, bashOK)
	switch {
	case !bashOK && !psOK && !cmdOK:
		c.deny(RuleParseError, "the command could not be parsed as bash, PowerShell or cmd, so it was blocked to be safe. Simplify the quoting.")
	case !bashOK || !psOK || !cmdOK:
		lexicalCheck(sec, c, text, bashOK)
	}
}

// evalPaths handles the file tools. For search tools a directory is fine
// unless it is (inside) a secret; globs are denied when they could match one.
func evalPaths(paths []string, sec *secretSet, c *collector, verb string, search bool) {
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		arg := literalToInternal(p)
		if search {
			arg = globToInternal(p)
			// A Glob/Grep pattern is relative to the search root (cwd), not
			// "anywhere": "**/*.go" must not overlap ~/.ssh/** unless the
			// search actually runs in or above the home directory.
			if !isAbsInternal(strings.ToLower(arg)) && !strings.HasPrefix(arg, "~") {
				arg = "./" + arg
			}
		}
		if m, ok := sec.checkPath(arg); ok {
			c.deny(RuleSecretFile+":"+m.pattern, secretFileReason(m, verb, sec))
			continue
		}
		if m, ok := sec.dirHoldsSecret(arg); ok {
			c.deny(RuleSecretFile+":"+m.pattern, dirReason(m, verb, sec))
		}
	}
}
