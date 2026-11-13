package engine

import "strings"

// The engine does not need a catalogue to be safe: ANY argument of ANY
// command that resolves to a secret path is denied. The catalogue only
// refines how dynamic arguments and globs are treated and improves reasons.

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// readers open their file arguments and can reveal their content. A dynamic
// argument (built at runtime) to a reader is denied when it could name a
// secret.
var readers = set(
	"cat", "tac", "nl", "head", "tail", "less", "more", "most", "bat", "batcat", "view",
	"vi", "vim", "nvim", "nano", "emacs", "ed", "ex", "pico", "micro", "code",
	"grep", "egrep", "fgrep", "rg", "ag", "ack", "zgrep", "git-grep",
	"cut", "sort", "uniq", "paste", "join", "comm", "diff", "diff3", "cmp", "sdiff", "colordiff",
	"strings", "od", "xxd", "hexdump", "hd", "base64", "base32", "basenc", "uuencode",
	"md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "b2sum", "cksum", "sum",
	"cp", "mv", "scp", "rsync", "dd", "tee", "install", "ln", "link",
	"tar", "zip", "cpio", "unzip", "gzip", "gunzip", "zcat", "bzip2", "bzcat", "xz", "xzcat", "zstd", "zstdcat", "7z", "7za", "lz4",
	"openssl", "gpg", "age", "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "sftp",
	"source", ".", "split", "csplit", "fold", "fmt", "pr", "expand", "unexpand", "column", "look",
	"iconv", "envsubst", "m4", "sops", "file", "wc", "type", "xargs", "readarray", "mapfile",
	"docker", "podman", "kubectl", "jq", "yq", "awk", "gawk", "mawk", "nawk", "sed",
)

// interpreters run code given inline or from a file argument.
var interpreters = set(
	"python", "python2", "python3", "pypy", "pypy3", "py",
	"node", "nodejs", "deno", "bun", "ruby", "irb", "perl", "php", "lua", "luajit",
	"rscript", "r", "osascript", "tclsh", "wish", "julia", "groovy",
	"awk", "gawk", "mawk", "nawk", "sed", "jq", "yq",
)

// shells re-parse a string argument (-c) or read a script.
var shells = set("sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "fish", "csh", "tcsh", "posh", "rbash")

// metadataOnly commands never reveal file contents; globs in their
// arguments are allowed (literal secret paths are still denied).
var metadataOnly = set(
	"ls", "dir", "vdir", "rm", "rmdir", "unlink", "mkdir", "touch", "chmod", "chown", "chgrp",
	"stat", "du", "test", "[", "realpath", "readlink", "basename", "dirname", "exa", "eza", "tree", "git-metadata",
)

// printOnly commands treat their arguments as data, never as files.
var printOnly = set("echo", "printf", ":", "true", "false")

// existenceOnly commands only test whether a path exists (test -f .env,
// [ -e .env ]); they never read content. [[ ... ]] is syntax and is not
// path-checked either.
var existenceOnly = set("test", "[")

// dirNavigation commands change directory; a directory holding secrets is
// fine to enter (files inside are still checked one by one).
var dirNavigation = set("cd", "pushd", "popd")

// globBenign commands take globs as directory/package selectors and never
// print file contents (cd */, pnpm --filter ./packages/*, mkdir -p a/*).
// Literal secret paths are still denied for them.
var globBenign = set("cd", "pushd", "pnpm", "npm", "npx", "yarn", "go", "cargo", "make", "mkdir", "turbo", "nx", "lerna")

// benignDynamic commands may receive runtime-built arguments without that
// being treated as suspicious.
var benignDynamic = set(
	"echo", "printf", "ls", "mkdir", "rm", "rmdir", "touch", "cd", "pushd", "popd", "test", "[",
	"true", "false", "exit", "return", "shift", "unset", "sleep", "kill", "wait", "read",
	"git", "go", "npm", "npx", "yarn", "pnpm", "make", "cargo", "pip", "pip3", "uv", "date", "seq",
	"expr", "chmod", "chown", "mktemp", "basename", "dirname", "printenv", "export", "local",
)

// embeddedHeads are first words that make a whitespace-containing argument
// worth re-parsing as a shell command (e.g. `ssh host 'cat .env'`,
// `git config alias.x '!cat .env'`).
var embeddedHeads = func() map[string]bool {
	m := set("echo", "printf", "env", "printenv", "set", "export", "declare", "eval", "exec",
		"sudo", "xargs", "find", "command", "builtin", "nohup", "timeout", "time", "nice")
	for _, src := range []map[string]bool{readers, interpreters, shells} {
		for k := range src {
			m[k] = true
		}
	}
	return m
}()

// recursiveCopiers can copy whole directory trees.
var recursiveCopiers = set("tar", "zip", "7z", "7za", "cp", "rsync", "scp", "diff")

// cmdBase normalises a command name: basename, lower-case, no Windows
// executable extension.
func cmdBase(name string) string {
	n := strings.ReplaceAll(name, `\`, "/")
	if i := strings.LastIndexByte(n, '/'); i >= 0 && i < len(n)-1 {
		n = n[i+1:]
	}
	n = strings.ToLower(n)
	for _, ext := range []string{".exe", ".cmd", ".bat", ".com"} {
		if strings.HasSuffix(n, ext) && len(n) > len(ext) {
			n = strings.TrimSuffix(n, ext)
			break
		}
	}
	// python3.12 -> python3, pip3.11 -> pip3
	if strings.HasPrefix(n, "python") || strings.HasPrefix(n, "pypy") {
		if i := strings.IndexByte(n, '.'); i > 0 {
			n = n[:i]
		}
	}
	return n
}

// verbFor describes what a command does with a path, for reasons.
func verbFor(name string) string {
	switch {
	case name == "":
		return "using"
	case printOnly[name]:
		return "using"
	case readers[name] || interpreters[name]:
		return "reading"
	default:
		return "passing to " + name
	}
}
