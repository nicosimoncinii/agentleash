package engine

import (
	"fmt"
	"strings"
)

// Built-in rule "credential-print": CLIs that print stored credentials with
// no secret path on the command line (the CLI reads ~/.kube/config,
// ~/.aws/credentials, the OS keychain, ... itself). Always denied.

type credentialCmd struct {
	name  string   // command basename ("docker-credential-*" matches a prefix)
	sub   []string // leading subcommand words
	flags []string // at least one of these must be present (empty: none needed)
	what  string   // what is printed, for the reason
}

var credentialCmds = []credentialCmd{
	{"gh", []string{"auth", "token"}, nil, "the GitHub CLI token"},
	{"gh", []string{"auth", "status"}, []string{"-t", "--show-token"}, "the GitHub CLI token"},
	{"kubectl", []string{"config", "view"}, []string{"--raw", "--flatten"}, "Kubernetes credentials from the kubeconfig"},
	{"aws", []string{"configure", "get"}, nil, "AWS configuration values (including secret keys)"},
	{"aws", []string{"configure", "export-credentials"}, nil, "AWS credentials"},
	{"aws", []string{"ecr", "get-login-password"}, nil, "a registry password"},
	{"aws", []string{"sts", "get-session-token"}, nil, "temporary AWS credentials"},
	{"git", []string{"credential", "fill"}, nil, "stored git credentials"},
	{"git", []string{"credential", "get"}, nil, "stored git credentials"},
	{"git", []string{"credential-store", "get"}, nil, "stored git credentials"},
	{"gcloud", []string{"auth", "print-access-token"}, nil, "a Google Cloud access token"},
	{"gcloud", []string{"auth", "print-identity-token"}, nil, "a Google Cloud identity token"},
	{"gcloud", []string{"auth", "application-default", "print-access-token"}, nil, "a Google Cloud access token"},
	{"az", []string{"account", "get-access-token"}, nil, "an Azure access token"},
	{"docker-credential-*", []string{"get"}, nil, "registry credentials"},
	{"npm", []string{"token", "list"}, nil, "npm tokens"},
	{"op", []string{"read"}, nil, "a 1Password secret"},
	{"op", []string{"item", "get"}, nil, "a 1Password item"},
	{"security", []string{"find-generic-password"}, []string{"-w", "-g"}, "a keychain password"},
	{"security", []string{"find-internet-password"}, []string{"-w", "-g"}, "a keychain password"},
	{"vault", []string{"read"}, nil, "a Vault secret"},
	{"vault", []string{"kv", "get"}, nil, "a Vault secret"},
	{"heroku", []string{"auth:token"}, nil, "the Heroku API token"},
	{"doctl", []string{"auth", "token"}, nil, "the DigitalOcean token"},
}

// credentialPrint reports whether argv (name already normalised) prints
// stored credentials.
func credentialPrint(argv []string) (string, bool) {
	if len(argv) == 0 {
		return "", false
	}
	name := argv[0]
	words := argv[1:]
	if name == "git" {
		words = gitVariants(argv)[0][1:]
		if what, ok := gitConfigCredential(words); ok {
			return what, true
		}
	}
	var positional []string
	for _, w := range words {
		if !strings.HasPrefix(w, "-") {
			positional = append(positional, w)
		}
	}
	for _, c := range credentialCmds {
		if !nameMatches(c.name, name) {
			continue
		}
		if len(positional) < len(c.sub) || !equalFold(positional[:len(c.sub)], c.sub) {
			continue
		}
		if len(c.flags) > 0 && !anyFlag(words, c.flags) {
			continue
		}
		return c.what, true
	}
	return "", false
}

// gitConfigCredential: `git config [--get|--get-all|--get-regexp] credential.*`
// without a value prints stored credential settings (and helpers' tokens).
func gitConfigCredential(words []string) (string, bool) {
	if len(words) == 0 || words[0] != "config" {
		return "", false
	}
	var keys []string
	for _, w := range words[1:] {
		if !strings.HasPrefix(w, "-") {
			keys = append(keys, w)
		}
	}
	if len(keys) == 1 && strings.HasPrefix(strings.ToLower(keys[0]), "credential") {
		return "git credential settings", true
	}
	return "", false
}

// nameMatches compares a catalogue name ("docker-credential-*" is a prefix).
func nameMatches(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

func equalFold(a, b []string) bool {
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

func anyFlag(words, flags []string) bool {
	for _, w := range words {
		for _, f := range flags {
			if w == f || strings.HasPrefix(w, f+"=") {
				return true
			}
		}
	}
	return false
}

func credentialReason(argv []string, what string) string {
	return fmt.Sprintf("`%s` prints %s, which agentleash treats as secret. Do not try to obtain it another way; if a command needs these credentials, ask the user to run it or to provide what is needed.", display(strings.Join(argv, " ")), what)
}

// checkCredentialPrint applies the rule to a static argv.
func checkCredentialPrint(c *collector, argv []string) {
	if what, ok := credentialPrint(argv); ok {
		c.deny(RuleCredential, credentialReason(argv[:min(len(argv), 4)], what))
	}
}
