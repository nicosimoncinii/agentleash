package engine

import (
	"fmt"
	"strings"
)

// Stable rule identifiers. Rules that carry a policy entry are suffixed with
// ":<entry>" (e.g. "secret-file:.env", "command-deny:git push --force*").
const (
	RuleSecretFile   = "secret-file"   // + ":" + secrets.files entry
	RuleSecretEnv    = "secret-env"    // + ":" + secrets.env entry
	RuleEnvExposure  = "env-exposure"  // whole environment dumped
	RuleCommandDeny  = "command-deny"  // + ":" + commands.deny entry
	RuleCommandAsk   = "command-ask"   // + ":" + commands.ask entry
	RuleParseError   = "parse-error"   // shell text could not be parsed
	RuleDynamicPath  = "dynamic-path"  // runtime-built argument could name a secret
	RuleDynamicShell = "dynamic-shell" // shell/eval of text unknown until runtime
	RuleObfuscation  = "obfuscation"   // decoding pipeline used to build commands
	RuleEncodedCmd   = "encoded-command"
	RuleSecretDir    = "secret-dir-copy" // recursive copy/archive of a dir that may hold secrets (ask)
	RuleSecretSearch = "secret-search"   // recursive search for a secret variable name over the project (ask)
	RuleNesting      = "nesting-limit"
	RuleTooComplex   = "too-complex"      // input exceeds the analysis limits
	RuleCredential   = "credential-print" //nolint:gosec // a rule identifier, not a credential
	RuleInternal     = "internal-error"
	RuleNoPolicy     = "no-policy"
	RuleUnknownTool  = "unknown-tool"
)

const reasonPrefix = "agentleash: "

type finding struct {
	decision Decision
	rule     string
	reason   string
}

// collector accumulates findings; the strongest wins (deny > ask > allow).
type collector struct {
	findings []finding
}

func (c *collector) add(d Decision, rule, reason string) {
	c.findings = append(c.findings, finding{decision: d, rule: rule, reason: reasonPrefix + reason})
}

func (c *collector) deny(rule, reason string) { c.add(Deny, rule, reason) }

func (c *collector) ask(rule, reason string) { c.add(Ask, rule, reason) }

// verdict returns the strongest finding. Among findings of the same
// decision, the most specific rule wins (a named secret explains more to
// the agent than "dynamic argument").
func (c *collector) verdict() Verdict {
	for _, want := range []Decision{Deny, Ask} {
		best := -1
		for i, f := range c.findings {
			if f.decision == want && (best < 0 || ruleRank(f.rule) < ruleRank(c.findings[best].rule)) {
				best = i
			}
		}
		if best >= 0 {
			f := c.findings[best]
			return Verdict{Decision: f.decision, Rule: f.rule, Reason: f.reason}
		}
	}
	return Verdict{Decision: Allow}
}

func ruleRank(rule string) int {
	order := []string{RuleSecretEnv, RuleSecretFile, RuleProtected, RuleEnvExposure, RuleCommandDeny, RuleEncodedCmd,
		RuleObfuscation, RuleDynamicShell, RuleDynamicPath, RuleCommandAsk, RuleSecretDir, RuleSecretSearch}
	for i, r := range order {
		if rule == r || strings.HasPrefix(rule, r+":") {
			return i
		}
	}
	return len(order)
}

// display shortens text for a reason. Reasons only ever quote paths, names
// and patterns from the command, never variable values.
func display(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == dynAny || r == dynStar {
			return '*'
		}
		if r < 0x20 {
			return ' '
		}
		return r
	}, s)
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

func dirReason(m match, verb string, s *secretSet) string {
	return fmt.Sprintf("%s %q is blocked: the directory contains secret files (secrets.files: %q in .agentleash.yaml). Work on the specific non-secret files you need instead. %s", verb, display(m.path), m.pattern, s.allowHint())
}

func secretFileReason(m match, verb string, s *secretSet) string {
	if m.builtin {
		return fmt.Sprintf("%s %q is blocked: process environment files expose every environment variable, including secrets. Read specific non-secret variables instead (e.g. echo \"$PATH\").", verb, display(m.path))
	}
	what := fmt.Sprintf("%s %q", verb, display(m.path))
	if m.glob {
		what = fmt.Sprintf("%s %q is blocked because it could match secret files", verb, display(m.path))
	} else {
		what += " is blocked"
	}
	return fmt.Sprintf("%s by .agentleash.yaml (secrets.files: %q). Do not try to access it another way. %s", what, m.pattern, s.allowHint())
}
