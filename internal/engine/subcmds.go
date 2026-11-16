package engine

import "strings"

// Subcommand roles (issue #34). The "directories holding secrets" rule
// (§7.1) treats a bare word such as `config` as the directory of an
// anchored pattern like config/secrets.yml. For CLIs whose first operand is
// always a subcommand (git, docker, npm, kubectl, ...) that word is a verb,
// not a path: `git config user.name x`, `docker compose config`,
// `npm config list`. verbArgs finds those positions so checkArg can skip
// only the directory rule for them; a verb that is itself a secret path is
// still denied, and every later operand keeps its path role.

// subcmdSpec describes one level of a subcommand CLI.
type subcmdSpec struct {
	// valueOpts take a separate value before the subcommand (git -C DIR,
	// kubectl --context NAME). The value is never a verb.
	valueOpts map[string]bool
	// flagOpts take no value. An option in neither set is ambiguous: the
	// next word could be its value (a path), so the scan stops there.
	flagOpts map[string]bool
	// nested lists subcommands whose own first operand is a subcommand too
	// (docker compose config, kubectl config view).
	nested map[string]subcmdSpec
}

var (
	composeSpec = subcmdSpec{
		valueOpts: set("-f", "--file", "-p", "--project-name", "--env-file", "--profile", "--project-directory",
			"--ansi", "--parallel", "--progress"),
		flagOpts: set("--all-resources", "--compatibility", "--dry-run", "--verbose"),
	}
	pkgMgrSpec = subcmdSpec{
		valueOpts: set("-C", "--dir", "--prefix", "--cwd", "--filter", "-F", "-w", "--workspace", "--loglevel"),
		flagOpts:  set("-g", "--global", "-r", "--recursive", "-s", "--silent", "--workspace-root", "-ws", "--workspaces", "-y", "--yes", "--offline", "--json"),
		nested:    map[string]subcmdSpec{"config": {}, "c": {}},
	}
	subcmdTools = map[string]subcmdSpec{
		"git": {
			valueOpts: set("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env", "--super-prefix"),
			flagOpts:  set("-p", "--paginate", "-P", "--no-pager", "--bare", "--no-replace-objects", "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks"),
		},
		"docker": {
			valueOpts: set("-c", "--context", "--config", "-H", "--host", "-l", "--log-level", "--tlscacert", "--tlscert", "--tlskey"),
			flagOpts:  set("-D", "--debug", "--tls", "--tlsverify"),
			nested: map[string]subcmdSpec{
				"compose": composeSpec, "config": {}, "context": {}, "secret": {}, "buildx": {}, "image": {}, "container": {},
			},
		},
		"podman":         {nested: map[string]subcmdSpec{"compose": composeSpec}},
		"docker-compose": composeSpec,
		"podman-compose": composeSpec,
		"kubectl": {
			valueOpts: set("--context", "--kubeconfig", "-n", "--namespace", "--cluster", "--user", "-s", "--server", "-v", "--v"),
			nested:    map[string]subcmdSpec{"config": {}},
		},
		"oc":     {valueOpts: set("--context", "--kubeconfig", "-n", "--namespace"), nested: map[string]subcmdSpec{"config": {}}},
		"helm":   {valueOpts: set("--kube-context", "--kubeconfig", "-n", "--namespace")},
		"npm":    pkgMgrSpec,
		"pnpm":   pkgMgrSpec,
		"yarn":   pkgMgrSpec,
		"bun":    {nested: map[string]subcmdSpec{"pm": {}}},
		"cargo":  {flagOpts: set("-q", "--quiet", "-v", "--verbose", "--offline", "--frozen", "--locked"), nested: map[string]subcmdSpec{"config": {}}},
		"go":     {},
		"gh":     {nested: map[string]subcmdSpec{"config": {}}},
		"gcloud": {nested: map[string]subcmdSpec{"config": {}}},
		"az":     {nested: map[string]subcmdSpec{"config": {}}},
		"aws":    {valueOpts: set("--profile", "--region", "--output"), nested: map[string]subcmdSpec{"configure": {}}},
		"pip":    {nested: map[string]subcmdSpec{"config": {}}},
		"pip3":   {nested: map[string]subcmdSpec{"config": {}}},
		"poetry": {nested: map[string]subcmdSpec{"config": {}}},
		"conda":  {nested: map[string]subcmdSpec{"config": {}}},
		"rustup": {},
		"systemctl": {
			flagOpts: set("--user", "--system", "--now", "-q", "--quiet", "--no-pager"),
		},
	}
)

// verbArgs returns the indexes of args (the arguments after the command
// name) that are subcommand words of a known CLI.
func verbArgs(name string, args []cmdArg) map[int]bool {
	spec, ok := subcmdTools[name]
	if !ok {
		return nil
	}
	var out map[int]bool
	for i := 0; i < len(args); i++ {
		t, ok := args[i].text()
		if !ok {
			return out
		}
		if strings.HasPrefix(t, "-") && t != "-" {
			switch {
			case t == "--" || strings.Contains(t, "="):
			case spec.valueOpts[t]:
				i++ // the value is never a verb
			case spec.flagOpts[t]:
			default:
				return out // unknown option: the next word may be its value
			}
			continue
		}
		if strings.ContainsAny(t, `/\`) || hasGlobMeta(escapeLit(t)) || t == "." || t == ".." {
			return out // looks like a path: keep the path role
		}
		if out == nil {
			out = map[int]bool{}
		}
		out[i] = true
		next, ok := spec.nested[t]
		if !ok {
			return out
		}
		spec = next
	}
	return out
}

// checkArgsRoles is checkArgs with the subcommand positions of known CLIs
// exempt from the directory-holding-secrets rule.
func (s *shellEval) checkArgsRoles(tool, name string, args []cmdArg) {
	verbs := verbArgs(tool, args)
	for i, a := range args {
		if verbs[i] {
			s.checkArgNoDir(name, a)
			continue
		}
		s.checkArg(name, a)
	}
}
