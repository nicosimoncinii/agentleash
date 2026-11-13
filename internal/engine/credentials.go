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
	// valueShort lists the short options that take a value. A one-letter
	// flag ("-w") also matches inside a cluster ("-wa") when it comes before
	// any of these letters ("-aw" is -a with the value "w").
	valueShort string
}

var credentialCmds = []credentialCmd{
	{"gh", []string{"auth", "token"}, nil, "the GitHub CLI token", ""},
	{"gh", []string{"auth", "status"}, []string{"-t", "--show-token"}, "the GitHub CLI token", "h"},
	{"kubectl", []string{"config", "view"}, []string{"--raw", "--flatten"}, "Kubernetes credentials from the kubeconfig", ""},
	{"aws", []string{"configure", "get"}, nil, "AWS configuration values (including secret keys)", ""},
	{"aws", []string{"configure", "export-credentials"}, nil, "AWS credentials", ""},
	{"aws", []string{"ecr", "get-login-password"}, nil, "a registry password", ""},
	{"aws", []string{"sts", "get-session-token"}, nil, "temporary AWS credentials", ""},
	{"git", []string{"credential", "fill"}, nil, "stored git credentials", ""},
	{"git", []string{"credential", "get"}, nil, "stored git credentials", ""},
	{"git", []string{"credential-store", "get"}, nil, "stored git credentials", ""},
	{"git", []string{"credential-cache", "get"}, nil, "cached git credentials", ""},
	{"git", []string{"credential-osxkeychain", "get"}, nil, "stored git credentials", ""},
	{"git", []string{"credential-libsecret", "get"}, nil, "stored git credentials", ""},
	{"git", []string{"credential-wincred", "get"}, nil, "stored git credentials", ""},
	{"git", []string{"credential-manager", "get"}, nil, "stored git credentials", ""},
	{"git", []string{"credential-manager-core", "get"}, nil, "stored git credentials", ""},
	{"git-credential-*", []string{"get"}, nil, "stored git credentials", ""},
	{"gcloud", []string{"config", "config-helper"}, nil, "a Google Cloud access token", ""},
	{"gcloud", []string{"auth", "print-access-token"}, nil, "a Google Cloud access token", ""},
	{"gcloud", []string{"auth", "print-identity-token"}, nil, "a Google Cloud identity token", ""},
	{"gcloud", []string{"auth", "application-default", "print-access-token"}, nil, "a Google Cloud access token", ""},
	{"az", []string{"account", "get-access-token"}, nil, "an Azure access token", ""},
	{"docker-credential-*", []string{"get"}, nil, "registry credentials", ""},
	{"npm", []string{"token", "list"}, nil, "npm tokens", ""},
	{"op", []string{"read"}, nil, "a 1Password secret", ""},
	{"op", []string{"item", "get"}, nil, "a 1Password item", ""},
	{"security", []string{"find-generic-password"}, []string{"-w", "-g"}, "a keychain password", "acCDGjlrst"},
	{"security", []string{"find-internet-password"}, []string{"-w", "-g"}, "a keychain password", "acCdDjlprsPt"},
	{"vault", []string{"read"}, nil, "a Vault secret", ""},
	{"vault", []string{"kv", "get"}, nil, "a Vault secret", ""},
	{"heroku", []string{"auth:token"}, nil, "the Heroku API token", ""},
	{"doctl", []string{"auth", "token"}, nil, "the DigitalOcean token", ""},
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
	if name == "kubectl" || name == "oc" {
		if what, ok := kubectlSecretPrint(words); ok {
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
		if len(c.flags) > 0 && !anyFlag(words, c.flags, c.valueShort) {
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

// kubectlValueOpts are kubectl global/get options that take a separate
// value, so it is not mistaken for the verb or a resource.
var kubectlValueOpts = set("-n", "--namespace", "-l", "--selector", "--context", "--cluster", "--user",
	"-s", "--server", "--kubeconfig", "--field-selector", "--sort-by", "--template", "-c", "--container",
	"--as", "--as-group", "--token", "--request-timeout", "--chunk-size", "-L", "--label-columns")

// kubectlSecretPrint: `kubectl get secret[s] ... -o yaml|json|jsonpath=...|
// go-template=...` (or --template) prints the base64 secret data. The table
// view, -o name and -o wide only show names and sizes.
func kubectlSecretPrint(words []string) (string, bool) {
	var positional []string
	format := ""
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "-o" || w == "--output":
			if i+1 < len(words) {
				format = words[i+1]
				i++
			}
		case strings.HasPrefix(w, "--output="):
			format = strings.TrimPrefix(w, "--output=")
		case strings.HasPrefix(w, "-o") && !strings.HasPrefix(w, "--"):
			format = strings.TrimPrefix(w[2:], "=")
		case w == "--template" || strings.HasPrefix(w, "--template="):
			format = "go-template"
			if w == "--template" {
				i++
			}
		case kubectlValueOpts[w]:
			i++
		case strings.HasPrefix(w, "-"):
		default:
			positional = append(positional, w)
		}
	}
	if len(positional) < 2 || positional[0] != "get" {
		return "", false
	}
	if f := strings.ToLower(format); f == "" || f == "name" || f == "wide" {
		return "", false
	}
	for _, res := range positional[1:] {
		for _, r := range strings.Split(res, ",") {
			if i := strings.IndexByte(r, '/'); i >= 0 {
				r = r[:i]
			}
			if r = strings.ToLower(r); r == "secret" || r == "secrets" || strings.HasPrefix(r, "secret.") || strings.HasPrefix(r, "secrets.") {
				return "Kubernetes secret data", true
			}
		}
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

func anyFlag(words, flags []string, valueShort string) bool {
	for _, w := range words {
		for _, f := range flags {
			if w == f || strings.HasPrefix(w, f+"=") {
				return true
			}
			if len(f) == 2 && f[0] == '-' && clusterHas(w, f[1], valueShort) {
				return true
			}
		}
	}
	return false
}

// clusterHas reports whether the short-option cluster w ("-wa") sets the
// flag letter before any letter that takes a value (whose value would be
// the rest of the cluster).
func clusterHas(w string, letter byte, valueShort string) bool {
	if len(w) < 3 || w[0] != '-' || w[1] == '-' {
		return false
	}
	for i := 1; i < len(w); i++ {
		switch {
		case w[i] == letter:
			return true
		case strings.IndexByte(valueShort, w[i]) >= 0 || !isAlpha(w[i]):
			return false
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
