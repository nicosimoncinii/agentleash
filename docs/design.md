# agentleash — Design (v0.1)

> One policy file. Every coding agent. Secrets stay secret.

Status: **Approved** (2026-11-11)

## 1. Problem

Coding agents (Claude Code, Codex, Gemini CLI, Cursor, ...) can read files and run shell
commands on the developer's machine. Each agent has its **own** mechanism to keep secrets
out of reach (`Read(...)` deny rules, `shell_environment_policy`, `.geminiignore`, ...):

- there is **no shared standard**: a team using two agents must maintain two configs;
- the native rules are **easy to bypass through the shell**: Claude Code's own docs state that
  `Read(./.env)` deny rules do not stop `cat .env` run through Bash; Codex's
  `shell_environment_policy` does not stop the agent from reading `.env` as a text file.

## 2. Goals (v0.1)

1. One project-level policy file, `.agentleash.yaml`, committed to git.
2. Support **Claude Code** and **Codex** natively.
3. Block:
   - reading secret files (via the agent's file tools **and** via shell commands);
   - exposing secret environment variables (`printenv`, `env`, `echo $AWS_SECRET_ACCESS_KEY`, ...);
   - destructive/dangerous commands listed in the policy (`deny`) or requiring confirmation (`ask`).
4. Defense in depth: native agent rules **plus** a runtime hook.
5. Fail closed: when unsure or on internal error, block.
6. A public, growing **attack corpus** that must be 100% blocked, and a **benign corpus**
   that must be 100% allowed (no annoying false positives).

## 3. Non-goals (v0.1)

Network egress control, Gemini CLI / Cursor adapters, secret placeholders/injection,
audit log, OS sandboxing, GUI/frontend. See the roadmap in the README.

**Honesty clause:** both vendors describe hooks as "a guardrail, not a complete enforcement
boundary". agentleash raises the bar substantially; it is not a sandbox. The README says so.

## 4. User-facing CLI

```
agentleash init               # write .agentleash.yaml with sensible defaults
agentleash apply [--agent ..] # install native rules + hooks for Claude Code / Codex
agentleash check "<cmd>"      # dry run: would this shell command be blocked? why?
agentleash hook <agent>       # invoked by the agent on every tool call (stdin JSON -> decision)
agentleash doctor             # verify installation and report problems
agentleash version
```

## 5. Policy format

```yaml
# .agentleash.yaml
version: 1
secrets:
  files:            # path globs; relative = anchored at project root, /abs, or ~/ (home)
    - ".env"
    - ".env.*"
    - "**/*.pem"
    - "**/id_rsa*"
    - "~/.aws/credentials"
  allow_files:      # explicit exceptions, e.g. templates
    - ".env.example"
  env:              # environment variable name globs
    - "*_KEY"
    - "*_SECRET*"
    - "*_TOKEN"
    - "*PASSWORD*"
commands:
  deny:             # shell command patterns, matched per simple command
    - "rm -rf /"
    - "git push --force*"
  ask:              # Claude Code: ask the user. Codex (no "ask" support): deny with reason.
    - "curl * | sh"
```

The example above is abridged. `policy.Default()` (written by `agentleash init`) is a
superset. It also covers:
- nested `.env` files and `.envrc`;
- more key and credential files (`*.key`, `*.p12`, `.npmrc`, `.netrc`, `*.tfstate*`,
  `~/.ssh/**`, `~/.kube/config`, `~/.config/gcloud/**`, `~/.azure/**`, ...);
- template and public-key `allow_files` (`.env.example`, `.env.sample`, `.env.template`,
  `.env.dist`, `*.pub`);
- the env names `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
  `GITHUB_TOKEN`, `DATABASE_URL` and `*_CONNECTION_STRING*` (not `AWS_*`, so `AWS_REGION` and
  `AWS_PROFILE` stay visible);
- more deny and ask command patterns.

`internal/policy/policy.go` is the source of truth for the exact list. Its tests pin both
what must be blocked and common harmless names that must stay allowed.

**File globs** (`secrets.files`, `secrets.allow_files`):
- Syntax: `path.Match` syntax (`*`, `?`, `[...]`) within one `/`-separated segment, plus
  `**` as a whole segment for zero or more directories.
- These are **not** gitignore patterns. A relative glob is anchored at the project root and
  does not float to any depth: `.env` is only the root file, so use `**/.env` for any depth.
- A leading `/` is an absolute filesystem path, and `~/` is the user's home directory.
- `!` negation is rejected; list exceptions in `allow_files` instead.
- Use forward slashes only.

**Env globs** (`secrets.env`) use `path.Match` syntax over variable names.

**Protected files** (`protect.files`, optional) use the file glob syntax above. They may be
read but never modified by the agent (§7.9). A built-in list is always protected on top of
it (`policy.BuiltinProtected`): `./.agentleash.yaml`, `./.claude/settings.json`,
`./.claude/settings.local.json`, `./.claude/agentleash-state.json`, `./.codex/hooks.json`,
`./.codex/config.toml`, and `~/.claude/settings.json`, `~/.claude/settings.local.json`,
`~/.codex/config.toml`, `~/.codex/hooks.json`. A `./` prefix anchors an entry at the project
root.

**Command patterns** (`commands.deny`, `commands.ask`):
- `*` matches any run of characters, including `/` and spaces. `\*` matches a literal `*`,
  as in `rm -rf /\*`. Every other character is literal.
- Patterns are matched against the normalised simple command: whitespace is collapsed, and
  wrappers such as `sudo`, `env`, `nohup` and `timeout` are stripped.
- A pattern containing ` | ` is matched against a pipeline, stage by stage, with each stage
  glob-matched. All other patterns are matched against each simple command.
- Commands are also matched in canonical forms (§7.5): an argument naming the filesystem
  root, the home directory or an ancestor of the home is spelled `/` or `~` however it is
  written (`/*`, `~/*`, `~/..`, `../../..`, `cd / && rm -rf *`), so `rm -rf /` and `rm -rf ~`
  cover those spellings. A stage that runs code from stdin (`sudo -s`, `sh /dev/stdin`,
  `pwsh`, `python3` without a program) also matches `sh` and `bash`.
- `Validate` only checks that command patterns are non-empty and have no leading or trailing
  whitespace.
- Because `*` is this broad, keep patterns specific. For example, `rm -rf /*` would also
  match `rm -rf /tmp/build`.

**Loading rules.**
- Decoding is strict: unknown fields are errors reported with line numbers.
- An empty file, multiple YAML documents and null list items (`-`, `- ~`) are errors.
- `Validate` reports all problems at once and names the field (`secrets.files[2]: ...`).
  It rejects:
  - an unsupported or missing `version`;
  - empty or whitespace-padded entries;
  - invalid file or env globs;
  - backslashes, `~user` or a leading `!` in file globs;
  - whitespace or `=` in env globs;
  - duplicates within a list.
- `Find` walks up from the working directory to the nearest `.agentleash.yaml`. The root it
  returns is not symlink-resolved.

## 6. Architecture

```
            ┌──────────────── agentleash apply ────────────────┐
            │                                                  │
   .claude/settings.json                              .codex/hooks.json
   - permissions.deny: Read/Edit(<secret globs>)      - PreToolUse hook
   - PreToolUse hook (onFailure: block)               .codex/config.toml
                                                      - shell_environment_policy.exclude
            │                                                  │
            └──── agent calls `agentleash hook <agent>` ───────┘
                                  │ stdin JSON
                       internal/agents/<agent>  (decode -> engine.Request)
                                  │
                           internal/engine  (Evaluate -> Verdict)
                           - shell parser (mvdan.cc/sh): pipes, &&, $(), ``, subshells,
                             `sh -c "..."` / `bash -c` recursion, eval
                           - file-reading command catalogue (cat, head, grep, base64, cp, ...)
                           - path normalisation (~, relative, globs like `.en*`, symlinks)
                           - env exposure detection
                           - deny / ask command patterns
                                  │
                       internal/agents/<agent>  (Verdict -> stdout JSON + exit code)
```

### Packages

| Package | Responsibility |
|---|---|
| `cmd/agentleash` | CLI wiring (cobra) |
| `internal/policy` | Load, default, validate `.agentleash.yaml` |
| `internal/engine` | Pure decision logic: `Evaluate(Request) Verdict`. No I/O except optional filesystem lookups for glob/symlink resolution |
| `internal/agents/claude` | Hook I/O format + `apply` (merge into `.claude/settings.json`) |
| `internal/agents/codex` | Hook I/O format + `apply` (merge into `.codex/hooks.json`, `.codex/config.toml`) |
| `testdata/attacks`, `testdata/benign` | Corpora driven by `internal/engine/corpus_test.go` |

### Key contracts

See `internal/engine/types.go` and `internal/policy/policy.go`. Agents translate their payload
into `engine.Request` and translate `engine.Verdict` back. The engine never knows which agent
is calling.

Additive contract changes (issue #2): `engine.ShellAuto` (`"auto"`) for commands whose
dialect is unknown (Codex `exec_command`); `Request.Paths` is also honoured for `ToolShell`
(paths an adapter knows the command touches, e.g. `apply_patch` through `exec_command`);
`engine.New(p, opts...)` accepts `engine.WithSymlinkResolver`. See §7.
Issue #18 adds `Request.InteractiveStdin`: the agent can keep typing into the started process
without further checks (Codex `write_stdin`); see §7.10.

### Agent specifics (verified against official docs, 2026-11)

**Claude Code** — hooks in `.claude/settings.json` (`hooks.PreToolUse[]`, matcher, exec-form
handler `{"type":"command","command":"<abs binary>","args":["hook","claude"],"onFailure":"block"}`;
exec form needs no shell or quoting, and `onFailure` requires Claude Code v2.1.295+, below
which a failing hook does not block). Stdin: `tool_name`, `tool_input` (`command` for
Bash/PowerShell, `file_path` for Read/Edit/MultiEdit/Write, `notebook_path` for NotebookEdit,
`path` + `glob` for Grep where `pattern` is the content regex, `path` + `pattern` for Glob;
`path` defaults to `cwd`), `cwd`. Glob returns file *names* only, never contents, so the
adapter sends only its search root (`path`/`cwd`): Glob is denied only when the root is a
secret or inside a secret directory (`~/.ssh`), and `**/*.json` or `.env*` are allowed. Grep
reads contents, so its root and `glob` filter are both checked.
Block: exit 0 + `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}`
(`ask` supported). Allow prints nothing: an explicit `"allow"` would skip the user's
permission prompt. Native `permissions.deny` rules use gitignore syntax: `Read(...)` rules
cover Read and (best effort) Grep/Glob plus file commands Claude Code recognises in Bash
(`cat`, `head`, `tail`, `sed`, redirections) but not arbitrary subprocesses or `grep -r .`;
writes (Write/Edit/MultiEdit/NotebookEdit, `tee`, `> file`) need `Edit(...)` rules, so
agentleash emits both. Secret globs that match at any depth (`x`, `**/x`) are written as
unanchored relative rules (`Read(.env.*)`); globs with an inner slash are anchored at the
project root (`Read(/config/x.yml)`), `~/x` and absolute paths keep their `~/` and `//`
anchors. `allow_files` become `Read(!x)`/`Edit(!x)` carve-outs, which only reach the
unanchored relative rules listed before them in the same file (a `!` pattern is read
relative to the current directory and cannot reopen files inside a blocked directory);
agentleash's block therefore goes first in `permissions.deny`. Overlaps are computed
precisely (a path must match both globs). When an allow entry overlaps a secret rule that
cannot be carved (anchored or directory rules, `~/` or absolute allow entries), the native
rule is **kept** (fail closed): the allowed file stays blocked by Claude Code's native
layer although the policy and the hook allow it, and `apply` prints a note saying so
(default policy: `~/.ssh/*.pub` under `Read(~/.ssh/**)`).
`.claude/settings.json` is read from the session's primary working directory: start
`claude` at the project root.

**Codex** — hooks in `.codex/hooks.json` or `[hooks]` in `.codex/config.toml`; project hooks
load only when the project layer is trusted, and each hook must be trusted once via `/hooks`.
Intercepts `Bash`, `exec_command`, `apply_patch` (`Edit`/`Write`), MCP tools. Same deny JSON
shape; **`ask` is not supported in PreToolUse** (would fail open), so `ask` maps to `deny`
with an explanatory reason. `commandWindows` overrides the command on Windows.
`write_stdin` is transport for an existing unified-exec session and does not run PreToolUse
again, so the adapter sets `Request.InteractiveStdin` on every shell request (§7.10).

### Merging config files

`apply` never overwrites user configuration. It merges, preserving key order and unknown
keys, and recognises its own entries so re-running `apply` is idempotent and
`apply --remove` can clean up:

- Hook handlers are recognised structurally with `agents.IsAgentleashCommand` (executable
  base name `agentleash[.exe]` with args `hook <agent>`; legacy shell-form strings only when
  the agentleash binary is the first word).
- Native rules carry no marker, so the rules agentleash added are recorded in a sidecar
  state file next to the config (Claude Code: `.claude/agentleash-state.json`, committed
  with `settings.json`). Remove deletes only recorded rules; identical user rules survive.
  A corrupt state file is an error with recovery steps; a missing one while the hook is
  installed produces a warning (earlier rules are then kept as the user's).
- A run that changes nothing in meaning writes nothing. Before the first modification of
  an existing file the original is saved as `<file>.bak`; later runs never overwrite it,
  so it always holds the pre-agentleash version.

## 7. Decision semantics

Order: **deny > ask > allow**. Any internal error, unparsable command, or unknown construct
that could hide a secret read results in `deny` with a reason (fail closed). Reasons are
written for the agent to read, so they explain *what* was blocked and *how to proceed*
(e.g. "use .env.example"; native rules carve `allow_files` out, so such advice stays valid).

The engine is pure: no disk writes, no network. The only optional filesystem access is an
injected symlink resolver (`engine.WithSymlinkResolver(filepath.EvalSymlinks)`); without it
the engine never touches the filesystem. The resolver also canonicalises `ProjectRoot`, `Cwd`,
`Home` and concrete argument paths (on Windows `EvalSymlinks` expands 8.3 short names such as
`C:\Users\RUNNER~1`); when a path resolves, only its literal spellings and its canonical form
are matched, so `allow_files` keep working (#26). A nil policy, an unknown `ToolKind` or a panic
inside the engine all yield `deny`.

### 7.1 Secret path semantics (`secrets.files`, `allow_files`)

| Pattern | Meaning |
|---|---|
| `.env`, `*.pem`, `id_rsa*` (no `/`) | basename at **any depth, anywhere on the filesystem** (stricter than gitignore: a copy in `/tmp` is still secret) |
| `**/x` | same as `x`: anywhere |
| `config/secrets.yml` (contains `/`) | anchored at `Request.ProjectRoot` (fallback `Cwd`; if both are empty: anywhere) |
| `~/.aws/credentials` | anchored at `Request.Home` |
| `/etc/x`, `C:\keys\*.pfx` | absolute, as written |
| anchored path, trailing `/`, `/**` | **covers everything below it** (`~/.ssh` protects `~/.ssh/id_ed25519`, `secrets/` any file inside) |
| basename glob (`*.pem`, `.env`) | constrains the **last path segment only**: `cat */package.json` does not match through a directory named `x.pem` |
| `*` `?` `[...]` `**` | gitignore-style; `*` never crosses `/` |
| `\*` | literal `*` (in a policy, a backslash before any other character is a Windows separator) |

- Matching is **case-insensitive on every platform** (NTFS/APFS are; on Linux this only adds
  harmless false positives).
- Arguments are normalised before matching: `~`, `~user`, `$HOME`, `$PWD`; relative paths are
  joined with `Cwd`, `ProjectRoot` **and every directory a `cd`/`pushd`/`-C dir` (PowerShell
  `Set-Location`/`Push-Location`/`sl`, cmd `cd /d`, `%USERPROFILE%`) in the script may switch
  to** (a `cd` to a runtime value: see §7.7); `..` cleaning; **in bash a backslash is an
  ordinary character** (`grep '\.env'` is a regex, not `/.env`), except that a path-role
  argument that looks like a Windows path (drive prefix `C:\`, `.\`/`..\`, UNC `\\host\`, or `\`
  between segments as in `sub\.env`) is also checked with `\` → `/`, because Git Bash on Windows
  reads `cat 'C:\proj\.env'` (#22); in PowerShell, cmd and file-tool paths `\` → `/`; drive letters, `/c/…`, `/mnt/c/…`, `/cygdrive/c/…`, `\\?\`; `/proc/*/cwd`;
  Windows trailing dots/spaces (`.env.`), alternate data streams (`.env::$DATA`) and 8.3 short
  names (`SECRE~1.YML`, only when the request paths look like Windows).
- `allow_files` exempt **concrete** paths only. A glob or runtime-built argument that could
  match a secret is not exempted (we cannot prove it only hits allowed files).
- Engine built-in: `/proc/*/environ` is treated as an environment dump.

**Shell globs are checked against the patterns, not the filesystem**: an argument glob is
denied when *some* file name could match both the glob and a secret pattern (glob–glob
intersection). Bash's dotfile rule is honoured (`*` does not match `.env`) unless the
script mentions `dotglob`/`GLOBIGNORE`. When both sides contain `*`, an overlap that exists
only because each star swallows the other side's literal text is ignored (`*.md` vs
`id_rsa*`). Without `shopt -s globstar`, an unquoted `**` is `*`. Commands that never
reveal content (`ls`, `rm`, `mkdir`, `chmod`, `stat`, `du`, `find` without `-exec`, ...) and
directory/package selectors (`cd */`, `pnpm --filter ./packages/*`, `make`, `go`) may take
globs.

**Literal secret paths** are denied for every command except:
- data arguments: `echo`/`printf`/`:`, the pattern of `grep`/`rg`/`ag` (unless given with
  `-f FILE`, also clustered as `-hf FILE`), the script of `sed` (only its `r`/`w` file names,
  `e` commands and the commands run by the `s///e` flag are checked; an `s///e` replacement
  built from the input, `&` or ``, is `dynamic-shell`),
  the program of `awk` and the filter of `jq`/`yq` (scanned as code), and `--option=value`
  values unless the option takes a path (`--env-file=`, `--file=`, ...) or the value contains
  `/` (`git log --grep=.env` is fine);
- existence checks and metadata-only commands, which never read content: `test`, `[`,
  `[[ ]]`, `Test-Path`, `ls`, `stat`, `touch`, `chmod`, `chown`, `rm`, `Get-ChildItem`,
  `Get-Item`, `git check-ignore`, `git rm --cached`, `git ls-files`
  (`test -f .env && cat .env` is still denied by the `cat`);
- write-only destinations: `cp`/`mv`/`install`/`Copy-Item`/`Move-Item` **onto** a secret path
  from a non-secret source (`cp .env.example .env`) returns **ask**, not deny. A Write tool
  call or a `>` redirection to a secret path stays deny.

**Directories holding secrets:** an argument (or a Search tool path) that is a directory and
a real ancestor of an *anchored* pattern's fixed prefix is denied too: `~/.ssh` for
`~/.ssh/id_*`, `~/.config` for `~/.config/gcloud/**`, `rsync -a ~/.ssh/ host:`. A file
(`~/.ssh/id_ed25519.pub`) is never treated as such a directory, so `allow_files` apply to it
normally. Exceptions: directory navigation (`cd`, `pushd`), metadata-only commands,
directories that contain the project root or home (covered by the recursive copy/search
**ask** rules), and the subcommand words of known CLIs (#34): for `git`, `docker`/`podman`
(and `compose`), `kubectl`/`oc`, `npm`/`pnpm`/`yarn`, `cargo`, `gh`, `gcloud`, `az`, `aws`,
`pip`, `poetry`, `conda`, ... the leading operands that name subcommands (`git config`,
`docker compose config`, `npm config list`, `kubectl config view`) are verbs, not paths, so
`config` does not match `config/secrets.yml`. Only the directory rule is skipped for them (a
verb that is itself a secret path is still denied). The scan stops at the first operand
that is not a known nested subcommand, at a word that looks like a path (`/`, `.`, a glob),
and at an unknown option (its value could be a path); values of known options (`git -C
config`, `docker compose -f config`) keep their path role, as do `cat config`, `tar czf x.tgz
config` and `cp -r config /tmp`.

**Tool-expanded globs:** values of `grep --include`, `rg -g/--glob/--iglob`, `ag -G`, and git
pathspecs of content commands (`log`, `diff`, `show`, `grep`, `archive`, `blame`; arguments
after `--` and `:(glob)` magic) are globs the tool expands itself: `*` matches dotfiles and
crosses directories. They are denied when they could match a secret.

**Links in the same command:** `ln [-s]`, `cp -s`, `mount --bind` and `bindfs` register an
alias, and later paths through the link are also matched under the target
(`ln -s ~ h; cat h/.aws/credentials`). A runtime target makes reads through the link
runtime-built paths.

File tools: `ToolRead`/`ToolWrite` deny any secret path in `Request.Paths`; `ToolSearch`
allows a directory unless it is (inside) a secret and denies a glob that could match one. A
relative Glob/Grep pattern is anchored at the search root (`Cwd`), so `**/*.go` from the
project only meets patterns that can match under the project; home-anchored patterns such as
`~/.ssh/**` apply when the search runs in, above, or inside the home directory (#23).
For `ToolShell`, `Request.Paths` is optional (e.g. Codex `apply_patch` run through
`exec_command`); any secret path there denies the call.

### 7.2 Shell analysis (`ShellBash`)

Commands are parsed with `mvdan.cc/sh/v3/syntax`; a parse error is `deny` (`parse-error`).
Everything is walked: lists, pipelines, subshells, blocks, `$()`, backticks, process
substitution, here-docs/strings, `if/for/while/case`, functions, redirections (`< .env`,
`> .env`, `exec 3< .env`). Wrappers are unwrapped and re-analysed: `sh/bash/zsh/dash -c`,
`eval`, `xargs` (with the producer's output: static `echo`, `find -name`, `git ls-files`),
`find -exec`, `env` (incl. `-S`), `sudo`, `doas`, `nohup`, `time`, `nice`, `timeout`,
`command`, `builtin`, `exec`, `watch`, `su -c`, `script -c`, `flock`, `stdbuf`, `strace`,
`busybox`, `pwsh -c`, `cmd /c`, `at`/`crontab -`, piping static text into a shell, and
package/project runners: `npx`/`pnpx`/`bunx`/`uvx`, `npm exec|x`, `pnpm dlx|exec`,
`yarn dlx|exec`, `bun x`, `poetry`/`pipenv`/`pdm`/`hatch`/`uv`/`pipx`/`conda`/`foreman`/`honcho
run`, `envdir DIR` (their `-c`/`--call` strings are re-parsed; `npx prettier .` is analysed as
`prettier .`). File lists read from stdin (`cpio -o|-p`, `tar -T -`/`--files-from=-`,
`zip -@`/`--names-stdin`) are checked like `xargs` input: the producer's static words or
`find`/`git ls-files` globs are paths; a list from any other source (a redirected file, an
unknown producer) is opaque and denied (`dynamic-path`).

**Conservative rule:** any argument of any command that resolves to a secret path is denied.
Arguments are also split on `=`, `:`, `,`, `@` (leading, as in `-d @.env`, or mid-word, as
in `name@.env`) and attached short options, repeatedly, so `if=.env`, `HEAD:.env`,
`-sd@.env`, `f@.env` and `--env-file=.env` are caught; arguments containing a shell command
(`git config alias.x '!cat .env'`, `ssh host 'cat .env'`) are re-parsed.

Words are evaluated statically: quoting, `$'…'` escapes, extglobs, brace expansion (which,
as in bash, turns one word into several fields: `{cat,.env}` is `cat .env`), and variables
assigned anywhere in the script (flow-insensitive: every assigned value is an alternative;
`for` items keep their glob meaning; `${X:-default}` includes the default). Unquoted
expansions are re-split on `IFS` (the default whitespace when unassigned, so `cat${IFS}.env`
is `cat .env`), and the command word itself is checked when a static fragment is glued to a
runtime part.

**Assignments:** prefix assignments (`VAR=value cmd`, `env VAR=value cmd`) are path-checked.
Variables that hold a command or a file a program runs or loads (`PAGER`, `GIT_PAGER`,
`MANPAGER`, `GIT_EDITOR`, `EDITOR`, `VISUAL`, `GIT_EXTERNAL_DIFF`, `GIT_SSH_COMMAND`,
`LESSOPEN`, `LESSCLOSE`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `NODE_OPTIONS`, `PYTHONSTARTUP`,
`PERL5OPT`, `RUBYOPT`, `GIT_CONFIG_VALUE_*`, ...) are re-parsed as commands wherever they are
assigned (including `export`); a runtime value for them is denied. `npm_config_*` values are
path-checked.

**Credential-printing CLIs** (`credential-print`, always deny): `gh auth token`,
`gh auth status -t/--show-token`, `kubectl config view --raw/--flatten`,
`aws configure get|export-credentials`, `aws ecr get-login-password`, `git credential
fill|get`, `git config --get credential.*`, `gcloud auth print-access-token|print-identity-token`,
`az account get-access-token`, `docker-credential-* get`, `npm token list`, `op read`,
`op item get`, `security find-generic-password|find-internet-password -w|-g` (also clustered,
`-wa`), `vault read|kv get`, `heroku auth:token`, `doctl auth token`,
`git credential-cache|credential-osxkeychain|credential-manager|... get`,
`git-credential-* get`, `gcloud config config-helper`, `kubectl`/`oc get secret[s] -o
yaml|json|jsonpath|go-template` (the table view, `-o name` and `-o wide` are fine). They print stored credentials without any secret path on the command
line; the reason asks the agent to get the user involved.

Anything only known at runtime becomes a wildcard:

- a runtime-built argument that could match a secret is denied for file readers,
  interpreters and unknown/runtime-chosen commands (`cat $F`, `cat ${X}env`), and for other
  commands only if a static fragment is glued to it (`ln -s ${X}env y`); `echo $HOME`,
  `go build -o $OUT/app` stay allowed;
- `$(…)`/`<(…)` containing a decoder (`base64 -d`, `xxd -r`, `openssl -d`, `rev`, `printf`
  with `\x`/octal escapes) is denied (`obfuscation`);
- `eval`/`sh -c`/`source` of runtime text, and piping unknown or decoded data into a shell or
  interpreter (`curl … | bash`, `bash <(curl …)`) are denied (`dynamic-shell`).

**Write-then-run in the same command.** A file the script writes with static content and
then runs is analysed as what it is. Writes: a `>`/`>>`/`>|`/`&>` redirect of `echo`,
`printf` (escapes decoded) or `cat` with a heredoc/here-string, `tee` fed by such a producer
or a heredoc, and `cp`/`mv`/`install` of a written file. Appends are concatenated in source
order (every suffix of the writes is a possible content, flow-insensitive; echo's trailing
newline is kept), so `printf 'cat .' > x; printf 'env' >> x; sh x` is `cat .env`. Runs:
`bash`/`sh`/`zsh FILE`, `source FILE`, `. FILE`, `./FILE` (through wrappers such as `sudo`),
an interpreter given `FILE` (`python3 FILE`, `node FILE`, ...), and a shell or interpreter
reading `FILE` on stdin (`bash < FILE`). A shell script is analysed by a child evaluator
(every rule applies, including parse errors); interpreter code goes through the one-liner
scanner below; a directly executed file is a shell script unless its shebang (also through
`env [-S]`) names an interpreter, and an unknown shebang program is `dynamic-shell`. A file
is matched by its cleaned path or, conservatively, by its base name. Content only known at
runtime (any other producer, an expansion, a compound command, a non-stdout fd) written to a
file that is later run is denied (`dynamic-shell`), except the output of a downloader (`curl`,
`wget`, `iwr`/`irm`, written by a redirect or `tee`): like `curl -o f URL && sh f`, it is
matched by the command patterns as `curl … | sh` (§7.5), so `curl … > i.sh && sh i.sh` is
**ask** under the default policy.
Writes inside `sh -c` strings are seen by later runs in the outer script. Each distinct
content is analysed once per request and charged to the work budget (§7.8); a file written
more than 16 times counts as runtime content. A script written in an earlier call is still
only checked by its path (§7.7).

Interpreter one-liners (`python -c`, `node -e`, `perl -e`, `ruby -e`, `php -r`, `lua -e`,
`elixir -e`, `erl -eval`, `guile -c`, `racket -e`, `ghc -e`, `clisp -x`, `sbcl --eval`,
`scala -e`, `nix eval --expr`, `emacs --eval`/`-eval`/`--execute`/`-execute` (operands are
files to visit and do not stop the scan; `-l`/`--load`/`--script` files are path-checked),
awk/sed/jq programs, code piped or heredoc'd into stdin interpreters such as `tclsh` and
`jshell -`) are scanned heuristically:
- string literals and bare tokens go through the path rules. Literals are decoded first
  (C escapes, `\N{FULL STOP}`, `\u{2e}`, Lua decimal `\46`, literal interpolation `#{"nv"}`/
  `${'nv'}`) and also checked after slicing (`'x.env'[1:]`, `.slice(1)`), `%`/`.format()`
  substitution with literal arguments, and concatenation with `+`, `.` and `.join`, both per
  argument (`open('.e'+'nv','r')`) and across a comma-separated list
  (`''.join(['.e','nv'])`). Lists of printable byte values (`bytes([46,101,110,118])`,
  `String.fromCharCode(...)`) are decoded too;
- when the program reads its operands (`sys.argv`, `process.argv`, `ARGV`, ...), adjacent
  operands are joined and path-checked (`python -c '…argv[1]+argv[2]…' .e nv`);
- environment accessors must name a non-secret variable literally: `environ` in any spelling
  (`os.`, `posix.`, `nt.`, a module alias, `__import__('os').`), `getenv`/`getenvb`/`getEnv`/
  `get_env`/`lookupEnv` (also Lisp/Haskell/nix `getenv "NAME"`), `process.env.X`,
  `process['env']`, `sys.env`, `ENV[...]`, `$ENV{...}`, `ENVIRON[...]`, Tcl `$env(X)`, jq `env`,
  and `perl -MEnv=NAME`/`use Env qw(...)`. Whole-environment dumps are denied: `php -i`,
  `phpinfo()`, `process.report`, `Object.const_get(:ENV)`, `-MEnv` without names, Emacs Lisp
  `process-environment`/`initial-environment`, and the
  JavaScript `process` object used as a value: an alias or destructuring (`p=process`,
  `const {env}=process`), a spread, an argument (`console.log(process)`, but not an array
  callback such as `forEach(process)`), a returned value or a bare expression (`node -p
  process`). Property names (`obj.process`, `{process: 1}`) and comments are ignored. A
  concatenated literal that spells an accessor (`"get"."env"`, `'envi'+'ron'`) is denied;
- implicit loaders count as reads: dotenv libraries without an explicit path
  (`load_dotenv()`, `dotenv_values()`, `require('dotenv')`, `python -m dotenv`) read `./.env`,
  and code that lists the current, home, root or a runtime-chosen directory (`os.listdir`,
  `readdirSync`, `iterdir`, `os.walk`, `Dir.children`, Lisp `(directory-files "." …)`, ...)
  and opens or runs what it finds is treated as reading every file there, but only when the
  code also reads file contents (`open(`, `read_text`, `readFileSync`, `cat`,
  `insert-file-contents`, `find-file`, ...). Listing a named subdirectory, or only printing
  or passing on the names, is allowed;
- decode + file/exec primitives together are denied; strings passed to
  `system()`/`subprocess`/`exec`/`shell-command(-to-string)`/`call-process`/`start-process`
  are re-parsed as shell.

Every scan is linear in the program and charged to the work budget (§7.8). One interpreter
program larger than 64 KB is not scanned and is denied (`too-complex`).

Recursive copies/archives (`tar c`, `zip -r`, `cp -r`, `rsync`, `scp -r`), `diff -r`
(without `-x`/`--exclude`) and `rg` with every ignore rule disabled (`-uu`, `-uuu`, repeated
`-u`/`--unrestricted`, or `--hidden`/`-.` together with `-u`/`--no-ignore[-vcs]`) of a
directory containing the project root or home (no path operand means `.`), and recursive
`grep`/`rg --hidden` for a secret variable name over such a directory, return **ask**
(`secret-dir-copy`, `secret-search`). An `rg -uu` restricted by `-g`/`--glob`/`-t`/`--type`,
or printing no content (`-l`, `-c`, `-q`, `--files`), is allowed; plain `rg foo` respects
`.gitignore` and hidden-file rules and is allowed.

### 7.3 Environment exposure

Denied: `printenv`/`env`/`set`/`export`/`export -p`/`declare -x|-p`/`typeset` without names;
`printenv NAME`, `declare -p NAME`, `$NAME`, `${NAME}`, `${#NAME}`, `${!ref}`, namerefs and
arithmetic references where NAME matches a `secrets.env` glob (case-insensitive);
`/proc/*/environ`; `ps e`, `ps -E`; `systemctl show-environment`; `launchctl getenv NAME`
(like `printenv NAME`). `${NAME:+x}` (set-ness only) and
`${!PREFIX*}` (names only) are allowed. PowerShell/cmd: `$env:NAME`, `${env:NAME}`,
`env:` drive listings, `[Environment]::GetEnvironmentVariable(s)`, `%NAME%`, `!NAME!`, cmd `set`
and `set PREFIX`.

### 7.4 PowerShell (`ShellPowerShell`) and unknown dialects (`ShellAuto`)

There is no Go PowerShell parser. A conservative tokenizer (quotes, here-strings, backtick
escapes, `$var`/`${var}`/`$env:X`, `$(…)` analysed recursively, comments, type literals,
separators) feeds the same path, env and command-pattern rules. `Get-Content`/`gc`/`type`/
`cat`/`-Path`/`[IO.File]::ReadAllText('…')`/`Copy-Item`/`Select-String` and string
concatenation (`'.e'+'nv'`, `-join`) are covered. Denied: `-EncodedCommand` (any accepted
prefix: `-e`, `-ec`, `-enc`, …), `iex`/`Invoke-Expression` of non-literal text or pipeline
input, `[scriptblock]::Create`, `& $x`, decode primitives (`FromBase64String`, `[char]`,
`-bxor`, …) combined with a read or execution, runtime-built paths given to readers.
Recursion into `powershell -Command`, `cmd /c`, `bash -c`, `wsl`. Native interpreters
(`python -c`, `node -e`, `ruby -e`, ...) are routed through the same one-liner scanner as in
bash. Pipeline input to content readers is checked: a string value (`'.env' | gc`) is a path,
and a listing (`gci`, `ls`, `dir`, `Get-Item`, with `-Filter`/`-Recurse`, no path meaning the
cwd) is a glob without a dotfile rule (`Get-ChildItem -Force | Get-Content`,
`ls -Force | % { gc $_ }`). `Remove-Item -Recurse -Force ~` is matched as `rm -rf ~` (§7.5).
Registry and WMI env dumps (`reg query HKCU\Environment`, `wmic environment`,
`Win32_Environment`) count as env dumps. An unterminated quote is `parse-error`.
**Limits:** no expression semantics (method chains, splatting, loops, functions, runtime
aliases, `-f` format strings), scripts on disk are not inspected.

`ShellAuto` (`"auto"`, e.g. Codex `exec_command`, where the model may have used bash, pwsh
or cmd) analyses the command as bash, as PowerShell and with a cmd.exe pass (`^` escapes,
`type`, `%VAR%`, `set`); the strictest verdict wins. A dialect that fails to parse
contributes nothing (a plain PowerShell command is not denied because bash cannot parse it),
but if any dialect fails a raw lexical check (secret path tokens, `$NAME`/`$env:NAME`/
`%NAME%` of secret variables, env dumps, `-enc`) also runs. If no dialect parses: `deny`.
**When bash parses cleanly**, bash has already analysed every argument: here-doc bodies are
blanked out, and the PowerShell/cmd passes only analyse statements that are specific to those
dialects (cmdlets such as `Get-Content`, `type`, `copy`, `cmd`, `set`, `[IO.File]::…`), plus
`$env:`/`%VAR%` references and `cd`/`Set-Location` targets everywhere; the lexical check is
then limited to `$env:NAME`/`%NAME%`. So `git commit -F - <<EOF … .env … EOF`,
`printf '.env' >> .gitignore` and `find . -not -path './.env'` are allowed in auto mode.
An unrecognised `Shell` value is treated as `ShellAuto`.

### 7.5 Command patterns (`commands.deny`/`commands.ask`)

See §5 for the pattern language. Implementation notes: patterns are matched against every
simple command at every wrapper level (so `sudo`, `env X=1`, `timeout 5`, `sh -c '…'`,
`xargs`, `find -exec` are transparent) and against a canonical form where short-flag
clusters are merged and sorted (`rm -r -f /` = `rm -fr /`), `--` is dropped and paths are
cleaned (`//` → `/`). In that form the home directory (`~`, `~/`, `$HOME`, `"$HOME"`, the
literal `Request.Home`) is spelled `~` and a Windows drive root (`C:\`) is spelled `/`. For
`rm`, `-R`/`--recursive` → `-r`, `--force` → `-f` (also as unambiguous GNU abbreviations:
`--rec`, `--f`, `--for`), options that do not change the target (`--no-preserve-root`, `-v`,
`-d`, `-I`, ...) are dropped and empty operands removed, so `rm --rec --for --no-pres /`
matches `rm -rf /`. A multi-operand `rm` is also matched once per operand (`rm -rf ./build /`
and the brace expansions `rm -rf /{,}`, `rm -rf {/,}` match `rm -rf /`). PowerShell
`Remove-Item`/`ri`/`rm`/`rd` (`-Recurse`, `-Force`, `-Path`, cmd `/s /q`) is also matched as
the equivalent `rm -rf PATH`.

**Root and home targets.** In an extra form, every non-option argument that names the
filesystem root or a drive root is spelled `/`, and one that names the home directory or one
of its ancestors (deleting it deletes the home) is spelled `~`. Before that check, trailing
segments that are globs matching every entry (`*`, `**`, `?*`) are dropped (`/*`, `/*/`,
`~/*`, `C:\*`, Git Bash `/c/*`); `~`, `$HOME`, `~user` of the same user and Git Bash/WSL
spellings of a Windows home (`/c/Users/u`) are the home; `~/..` and `"$HOME"/..` are resolved
against the home (`path.Clean("~/..")` is not `.`); and a relative path (`..`, `*`, `.`) is
resolved against every possible working directory: `Request.Cwd`, the project root and the
`cd`/`pushd` targets in the same script, including a bare `cd` (home). The `cd` tracking is
flow-insensitive, like the rest of §7.2 (`cd / && ls; rm -rf *` is also denied). Other paths
are not rewritten, so `rm -rf ./build`, `rm -rf node_modules/*` and `cd /tmp && rm -rf *`
stay allowed and broad user patterns such as `rm -rf /*` keep their meaning.

**dd.** Operands are order-free: an extra form puts `if=` first (`if=/dev/stdin` when
absent) and `of=` last, so `dd * of=/dev/*` matches `dd of=/dev/sda if=/dev/zero` and
`… | dd of=/dev/sda`.

Fork bombs (a function that calls itself in a pipeline or in the background, e.g.
`:(){ :|:& };:`) are recognised structurally and always denied, because no simple command
is left to match after parsing. For `git`, global options (`-C dir`, `-c k=v`, `--git-dir=…`) are
removed; aliases are expanded when defined inline (`git -c alias.p='push -f' p`) or by
`git config [--global] alias.p 'push -f'` anywhere in the same script, including chains of
aliases. A shell alias (`alias.p='!git push -f origin main'`) is analysed at the call site
like `sh -c`, with the call's arguments appended as git does (`git p --force` runs
`git push --force`), so every rule applies to it (patterns, secret paths, env exposure).
Expansion is bounded (8 values per alias name, 64 names, 32 expansions per call, every
expansion charged to the work budget, §7.8); exceeding a bound is `too-complex`. `git push -f …`, `git push origin +main`, `git push --mirror`,
abbreviations of `--force`/`--mirror` (`--mirr`) and `git send-pack --force` are also matched
as `git push --force …`; an abbreviated `--hard` (`git reset --ha`) is matched as `--hard`.
Command names are lower-cased basenames (`/bin/RM` → `rm`; PowerShell aliases are matched
both as typed and resolved). If a match depends on a runtime value (`rm -rf $DIR` vs
`rm -rf /`) the decision is downgraded from deny to **ask**.

**Remote code patterns.** In a `|` pattern, a stage that runs code read from stdin is also
matched as `sh` and `bash`: a shell without a script or with `-s`, `-`, `/dev/stdin`;
`sudo -s`/`-i`/`--login`, `doas -s`, `su` without `-c`; `pwsh`/`powershell` without a script or
with `-Command -`; an interpreter (`python3`, `node`, …) without a program. Two shapes without
a `|` are matched as the equivalent pipeline: a process substitution used as the script
(`python3 <(curl …)` = `curl … | python3`) and a file downloaded and run in the same script
(`curl -o f URL && sh f`, `wget URL; bash ./i.sh`, `./f`) = `curl … | sh`. So
`curl * | sh` covers all of them. Not covered: a download in an earlier call (§7.7).

### 7.6 Rule identifiers

`secret-file:<pattern>`, `secret-env:<glob>`, `env-exposure`, `command-deny:<pattern>`,
`command-ask:<pattern>`, `parse-error`, `dynamic-path`, `dynamic-shell`, `obfuscation`,
`encoded-command`, `credential-print`, `secret-dir-copy` (ask), `secret-search` (ask),
`nesting-limit`, `too-complex`, `internal-error`, `no-policy`, `unknown-tool`,
`protected-file:<pattern>` (§7.9),
`interactive-session` (§7.10).
`secret-file:<pattern>` is **ask** (not deny) when a secret path is only the destination of
a copy from a non-secret file. When several rules fire, the verdict carries
the most specific one (named secret before generic dynamic rules).

### 7.7 Known limitations (not covered by the engine)

- Write-then-execute across calls: a script written with the Write tool, or by a shell command
  in an *earlier* call, and run later is only checked by its path, not its content; the same
  holds for `make`, `npm run`, Makefiles and other files read by tools. Within one command,
  a script written by `echo`/`printf`/a heredoc/`tee` and then run is analysed (§7.2), and a
  `curl`/`wget` download run in the same command is matched as `curl … | sh` (§7.5). Not
  modelled within one command: files written by other programs (`python -c "open('x','w')…"`,
  `sed -i`), a `cd` between the write and the run when the base names differ, `awk -f`/`make
  -f` of a written file, and `deno run`-style subcommands.
- Command patterns only see one call: a git alias configured in an earlier call
  (`git config --global alias.p 'push -f'`, then `git p` later) or through
  `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n` is not expanded, and a `cd` made in an earlier call is
  only known through `Request.Cwd`.
- Plain recursive reads of a directory: `grep -r foo .` reads `.env` and prints lines that
  match `foo`; only searches for a secret variable *name* are flagged (and `rg` with every
  ignore rule disabled, `-uu`, is asked, §7.2; plain `rg` skips gitignored and hidden files,
  but a `.env` that is not gitignored is still searched). `docker build .` sends
  `.env` to the daemon unless `.dockerignore` excludes it.
- Symlinks/hardlinks created in an *earlier* call (`ln -s .env x`, then `cat x` later) are only
  caught with the injected symlink resolver; hardlinks are never caught. Links created in the
  same command are tracked (§7.1).
- A `cd` to a runtime value (`cd "$(git rev-parse --show-toplevel)"`, `cd $DIR`) makes relative
  paths match only the "anywhere" patterns (`.env`, `*.pem`): we assume a runtime `cd` does not
  enter a home-anchored secret directory (`cd "$(dirname ~/.aws/credentials)" && cat
  credentials` is not caught).
- Interpreter scanning is heuristic: computed strings beyond literal concatenation, slicing and
  formatting (variables: `p='.e'; open(p+'nv')`), reflection with runtime names, compression,
  custom encodings, and directory listings of a named subdirectory that holds a nested secret
  are not caught.
- Tools with their own command languages are partially covered (`sqlite3` `readfile()`,
  `.shell`/`.system`, `.read`/`.import` file names and `-cmd` are checked; `emacs --eval` is
  scanned heuristically like other interpreters, §7.2): `make --eval`, vim ex commands without
  a literal secret, `less` commands, `ssh` remote commands, and Emacs Lisp files loaded with
  `-l` (checked by path only).
- Subcommand words (#34) are recognised only for the CLIs listed in §7.1; for other tools a
  bare word that names the directory of an anchored secret pattern is still denied.
- Env forwarding is partially covered: `docker run -e NAME`, `dotenv`/`direnv exec`/`op run`/
  `doppler run` are handled. CLIs that load `./.env` implicitly and print it are denied as a
  read of that file (`dotenv list|get`, `python -m dotenv`, `dotenvx get|keypair|decrypt
  --stdout`, `dotenv-cli -p NAME`, `docker compose config|convert` unless `-q`,
  `--services`/`--volumes`/`--profiles`/`--images` or `--no-interpolate`; with `--env-file` the
  given files replace `.env` and only a secret one is denied; otherwise, when `secrets.env` has
  globs, it is **ask** (`env-exposure`), because it also interpolates referenced variables from
  the process environment); runners that only load it into the
  environment (`pipenv run`, `foreman run`) are unwrapped instead; `envsubst` over secret names, namerefs to variables assigned later
  in the script (`declare -n r=f; f=.env; cat $r`) are not.
- PowerShell is tokenized, not parsed (see §7.4): `-f` format strings, method chains and
  splatting are not resolved; recursive `Select-String` for a secret name is not flagged.
- cmd: `set x=.e& call type %x%nv` (variable substitution) is not modelled.
- Network exfiltration of non-secret data and reading secrets on other machines are out of
  scope (§3).

### 7.8 Resource limits

Every request shares one work budget (about tens of milliseconds of analysis) that counts
syntax nodes, word evaluations, path checks, pattern matches and re-parses through `$()`,
subshells, `sh -c`, `eval` and PowerShell sub-expressions. Word evaluations and pipeline
producers are memoised, so nested substitutions are linear. Hard caps: 256 KB of command
text, 24 nested substitutions, 256 pipeline stages, 60 000 syntax nodes, 32 possible working
directories (beyond that, relative paths match anywhere), 64 alternatives per word, 8 levels
of nested shells, git aliases (8 values per name, 64 names, 32 expansions per call; each
expansion and each generated command form is charged to the work budget), 1 MiB of text
produced by parameter expansion per request (charged at one unit per KB; repeating or
doubling a long value is not bounded by the command size). Exceeding any limit returns **deny** (`too-complex`): "too complex to analyse
safely". Glob and pattern matching is linear in the length of a word, so inputs up to 64 KB
are answered in well under 100 ms and a single 256 KB argument in about 150 ms at most.

### 7.9 Self-protection (`protect.files`, #17)

Protected files (§5) are analysed by a second engine whose `secrets.files` are the protected
globs, in **mention mode**: the exemptions that exist because a command reads no content
(`rm`, `touch`, `chmod`, `ls`, `git rm --cached`, `Remove-Item`, the destination of `cp`, sed
scripts and grep patterns, `find -delete` outputs) are switched off, so every reference
counts, through globs, directories that hold a protected file, nested shells, `cd`, and
interpreter literals. It runs only when the main verdict is not already deny. Also in mention
mode:

- `rm`/`rmdir`/`mv`/`unlink`/`shred` of an *ancestor* of the project or home (`rm -rf .`,
  `rm -rf ..`) and `Remove-Item`/`Move-Item` of one count as touching every protected file;
- `agentleash init` and `agentleash apply` (any flags) count as touching `.agentleash.yaml`;
- a runtime-built path given to a writing command (`rm "$F"`, `ls | xargs rm`, a PowerShell
  writer fed by the pipeline) is **ask** (`protected-file:(runtime path)`), unless the main
  verdict already asks;
- a PowerShell argument containing whitespace or `"` is also checked piece by piece, because
  PowerShell 5.1 passes embedded quotes to native programs, which split it again.

- `Write`/`Edit`/`apply_patch` paths (including patches carried by Codex `exec_command`)
  that touch a protected file: **deny**.
- `Read`, `Grep`, `Glob`: never restricted by protection.
- A shell command that touches a protected file is allowed only when it is **provably
  read-only**; otherwise **deny** (`protected-file:<pattern>`). The proof accepts literal
  words only (no expansions, substitutions, backslash escapes, unquoted braces or glob
  characters; `[`/`]` of `test` are fine), `if`/`[[ ]]` built from such parts, no output
  redirection
  other than `/dev/null` and fd duplication, no background jobs, environment assignments
  limited to `LANG`/`LC_*`/`TZ`/`TERM`/`NO_COLOR`/`COLUMNS`, and commands from an allowlist:
  `cat head tail less more wc stat ls nl od hexdump cmp comm diff grep egrep fgrep rg`
  (without `--pre`) `jq md5sum sha*sum cksum b2sum realpath readlink dirname basename test
  echo pwd cd type findstr`; `find` without `-delete`/`-exec*`/`-ok*`/`-fprint*`/`-fls`; `sed` with only
  `-n -E -r -s -u -z` and print-only scripts (`1,200p`, `$p`, `10q`, `/re/,+5p`); `git` `status log show
  diff blame ls-files rev-parse cat-file add commit` with no global options other than
  `--no-pager`, `-P`, `--no-optional-locks`, `-C DIR` and no `--output`/`--ext-diff`/`-O`;
  `bash|sh|zsh|dash -c SCRIPT` whose script is itself provable (3 levels). PowerShell
  statements may also use `Get-Content Select-String Get-ChildItem Get-Item Test-Path
  Get-FileHash Format-Hex Measure-Object Select-Object Get-Location Set-Location
  Resolve-Path Write-Output Out-Host Format-List Format-Table ConvertFrom-Json ConvertTo-Json
  Sort-Object Where-Object Out-String`, with no `$`, `@`, `()`, `{}`, `"`, backtick or
  redirection other than `2>/dev/null`/`2>nul` in any word. `ShellAuto` requires both proofs,
  refuses `&`, `^` and `%`, which only cmd.exe would interpret, and refuses words containing
  whitespace (cmd.exe does not treat `'` as a quote) except the script of `bash -c`.
- `git add` and `git commit` are accepted although they are not strictly read-only: they
  never change the working tree, but they run repository hooks, as `diff`/`show` honour
  `diff.external` and textconv drivers from `.git/config`, which is not protected.
- Claude Code also gets native `Edit(<path>)` deny rules for every protected entry (no
  `Read` rule), after the secret rules.

Limits: protection is lexical, a speed bump against an agent that edits its own leash, not a
guarantee. A write that never names a protected file is not seen: a script, patch or archive
written in an earlier call and then run or applied (`python3 x.py`, `git apply x.diff`,
`patch`, `tar x`, `unzip -o`), and git commands that rewrite the working tree (`git checkout
.`, `git restore .`, `git stash`, `git reset --hard`, `git pull`, switching branches).

### 7.10 Interactive sessions (`Request.InteractiveStdin`, #18)

When `InteractiveStdin` is set, a simple command whose stdin is the session's own stdin (not
a pipe, a file redirection or a here-doc/here-string; PowerShell statements that receive
pipeline input are exempt) is **denied** (`interactive-session`) when it would read commands
typed later:

- programs that run code from stdin (§7.5 `stdinCodeRunner`): shells without a script or
  `-c`, `sudo -s|-i`, `su`, `pwsh` without a command, interpreters without a program;
- interpreters with a REPL flag (`python -i`, `node -i`, `php -a`), `irb`, `pry`, `iex`;
- `cmd` without `/c`, `wsl` without a command;
- `ssh` without a remote command (not `-N`, `-V`, `-G`, `-O`, `-Q`);
- `docker|podman|nerdctl exec|run|debug` with `-i`/`--interactive`, `attach`, and
  `kubectl|oc exec|run|debug` with `-i`/`--stdin`, `attach`;
- database shells without a query: `psql` (no `-c`/`-f`), `mysql`/`mariadb` (no `-e`),
  `sqlite3` with fewer than two operands, `redis-cli`/`valkey-cli` without a command,
  `mongosh`/`mongo` without `--eval`/`-f`/script;
- `gdb`/`lldb` without batch mode, `sftp` without `-b`, `ftp`, `telnet`;
- editors and pagers with shell escapes: `vi vim nvim view ex ed nano pico micro`, `emacs`
  without `--batch`/`--script`, `less more most man`; `tmux screen script expect`.

Every wrapper level (`sudo`, `env`, `nohup`, ...) is checked. Not covered: programs started
indirectly that become interactive (a pager opened by `git log` on a terminal, an editor opened
by `git commit` without `-m`), and arbitrary programs that read and execute their own input
format.

## 8. Testing strategy

- Unit tests per package (table-driven).
- Corpus tests: every file in `testdata/attacks/*.yaml` must evaluate to `deny`/`ask`;
  every file in `testdata/benign/*.yaml` must evaluate to `allow`. The attack corpus is
  written by a separate "red team" contributor, not by the engine author.
- Golden tests for generated agent config files.
- End-to-end: pipe real hook payloads into the built binary.
- CI: `go test -race` on Linux, macOS, Windows; `golangci-lint`; `govulncheck`.

## 9. Distribution

Single static Go binary. GoReleaser builds for linux/darwin/windows × amd64/arm64 on tag.
`go install github.com/nicosimoncinii/agentleash/cmd/agentleash@latest`.
