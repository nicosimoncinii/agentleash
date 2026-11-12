package agents

import (
	"regexp"
	"strings"
)

// IsAgentleashCommand reports whether a hook handler runs `agentleash hook <agent>`.
// agent == "" matches any agent.
//
// With args (exec form, what adapters install) the check is structural: the
// executable's base name, lower-cased and without ".exe", is "agentleash" and args
// start with ["hook", agent]. Without args the command is a legacy shell-form string
// such as `"C:\Program Files\agentleash\agentleash.exe" hook claude`; it matches only
// when the agentleash binary is the first word, so `echo 'not agentleash hook'` does not.
func IsAgentleashCommand(command string, args []string, agent string) bool {
	if len(args) > 0 {
		return isAgentleashBinary(command) && len(args) >= 2 && args[0] == "hook" &&
			(agent == "" || args[1] == agent)
	}
	m := legacyHookRe.FindStringSubmatch(command)
	return m != nil && (agent == "" || m[1] == agent)
}

func isAgentleashBinary(command string) bool {
	base := command[strings.LastIndexAny(command, `/\`)+1:]
	return strings.TrimSuffix(strings.ToLower(base), ".exe") == "agentleash"
}

// legacyHookRe matches a shell-form hook command whose first word is the agentleash
// binary (bare, or a path that is unquoted, "double-quoted" or 'single-quoted'),
// followed by `hook <agent>`. Group 1 is the agent.
var legacyHookRe = regexp.MustCompile(`(?i)^\s*(?:` +
	`"(?:[^"]*[\\/])?agentleash(?:\.exe)?"` +
	`|'(?:[^']*[\\/])?agentleash(?:\.exe)?'` +
	`|(?:[^\s"']*[\\/])?agentleash(?:\.exe)?` +
	`)\s+hook\s+([A-Za-z0-9_-]+)(?:\s|$)`)
