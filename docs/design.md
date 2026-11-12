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

**Command patterns** (`commands.deny`, `commands.ask`):
- `*` matches any run of characters, including `/` and spaces. `\*` matches a literal `*`,
  as in `rm -rf /\*`. Every other character is literal.
- Patterns are matched against the normalised simple command: whitespace is collapsed, and
  wrappers such as `sudo`, `env`, `nohup` and `timeout` are stripped.
- A pattern containing ` | ` is matched against a pipeline, stage by stage, with each stage
  glob-matched. All other patterns are matched against each simple command.
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
   - permissions.deny: Read(<secret globs>)           - PreToolUse hook
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

### Agent specifics (verified against official docs, 2026-11)

**Claude Code** — hooks in `.claude/settings.json` (`hooks.PreToolUse[]`, matcher, handler
`type: command`, `onFailure: "block"`). Stdin: `tool_name`, `tool_input` (`command` for
Bash/PowerShell, `file_path` for Read/Edit/Write, `path`/`pattern` for Grep/Glob), `cwd`.
Block: exit 0 + `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}`
(`ask` supported). Native `permissions.deny` `Read(...)` rules use gitignore syntax and cover
Read/Grep/Glob/Edit/Write but not Bash.

**Codex** — hooks in `.codex/hooks.json` or `[hooks]` in `.codex/config.toml`; project hooks
load only when the project layer is trusted, and each hook must be trusted once via `/hooks`.
Intercepts `Bash`, `exec_command`, `apply_patch` (`Edit`/`Write`), MCP tools. Same deny JSON
shape; **`ask` is not supported in PreToolUse** (would fail open), so `ask` maps to `deny`
with an explanatory reason. `commandWindows` overrides the command on Windows.

### Merging config files

`apply` never overwrites user configuration. It merges, and marks its own entries
(e.g. the hook command contains `agentleash hook`) so re-running `apply` is idempotent and
`apply --remove` can clean up. Before writing, a `.bak` copy is kept.

## 7. Decision semantics

Order: **deny > ask > allow**. Any internal error, unparsable command, or unknown construct
that could hide a secret read results in `deny` with a reason (fail closed). Reasons are
written for the agent to read, so they explain *what* was blocked and *how to proceed*
(e.g. "use .env.example").

The engine is pure: no disk writes, no network. The only optional filesystem access is an
injected symlink resolver (`engine.WithSymlinkResolver(filepath.EvalSymlinks)`); without it
the engine never touches the filesystem. A nil policy, an unknown `ToolKind` or a panic
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
  ordinary character** (`grep '\.env'` is a regex, not `/.env`), while in PowerShell, cmd and
  file-tool paths `\` → `/`; drive letters, `/c/…`, `/mnt/c/…`, `/cygdrive/c/…`, `\\?\`; `/proc/*/cwd`;
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
  `-f FILE`), the script of `sed` (only its `r`/`w` file names and `e` commands are checked),
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
normally. Exceptions: directory navigation (`cd`, `pushd`), metadata-only commands, and
directories that contain the project root or home (covered by the recursive copy/search
**ask** rules).

**Tool-expanded globs:** values of `grep --include`, `rg -g/--glob/--iglob`, `ag -G`, and git
pathspecs of content commands (`log`, `diff`, `show`, `grep`, `archive`, `blame`; arguments
after `--` and `:(glob)` magic) are globs the tool expands itself: `*` matches dotfiles and
crosses directories. They are denied when they could match a secret.

**Links in the same command:** `ln [-s]`, `cp -s`, `mount --bind` and `bindfs` register an
alias, and later paths through the link are also matched under the target
(`ln -s ~ h; cat h/.aws/credentials`). A runtime target makes reads through the link
runtime-built paths.

File tools: `ToolRead`/`ToolWrite` deny any secret path in `Request.Paths`; `ToolSearch`
allows a directory unless it is (inside) a secret and denies a glob that could match one.
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
`busybox`, `pwsh -c`, `cmd /c`, `at`/`crontab -`, piping static text into a shell.

**Conservative rule:** any argument of any command that resolves to a secret path is denied.
Arguments are also split on `=`, `:`, `,`, `@` and attached short options, so `if=.env`,
`HEAD:.env`, `-d @.env` and `--env-file=.env` are caught; arguments containing a shell command
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
`op item get`, `security find-generic-password -w`, `vault read|kv get`, `heroku auth:token`,
`doctl auth token`. They print stored credentials without any secret path on the command
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

Interpreter one-liners (`python -c`, `node -e`, `perl -e`, `ruby -e`, `php -r`, awk/sed/jq
programs, heredocs fed to interpreters) are scanned heuristically: string literals (also
concatenated with `+`, `,`, `.join`) and bare tokens go through the path rules; environment
accessors (`os.environ[...]`, `process.env.X`, `ENV[...]`, `$ENV{...}`, `ENVIRON[...]`,
`getenv(...)`, jq `env`) must name a non-secret variable literally; decode + file/exec
primitives together are denied; strings passed to `system()`/`subprocess`/`exec` are
re-parsed as shell.

Recursive copies/archives (`tar c`, `zip -r`, `cp -r`, `rsync`, `scp -r`) of a directory
containing the project root or home, and recursive `grep`/`rg --hidden` for a secret variable
name over such a directory, return **ask** (`secret-dir-copy`, `secret-search`).

### 7.3 Environment exposure

Denied: `printenv`/`env`/`set`/`export`/`export -p`/`declare -x|-p`/`typeset` without names;
`printenv NAME`, `declare -p NAME`, `$NAME`, `${NAME}`, `${#NAME}`, `${!ref}`, namerefs and
arithmetic references where NAME matches a `secrets.env` glob (case-insensitive);
`/proc/*/environ`; `ps e`; `systemctl show-environment`. `${NAME:+x}` (set-ness only) and
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
`rm`, `-R`/`--recursive` → `-r`, `--force` → `-f`, and options that do not change the target
(`--no-preserve-root`, `-v`, `-d`, `-I`, ...) are dropped, so `rm --recursive --force
--no-preserve-root /` matches `rm -rf /`. PowerShell `Remove-Item`/`ri`/`rm`/`rd`
(`-Recurse`, `-Force`, `-Path`, cmd `/s /q`) is also matched as the equivalent `rm -rf PATH`.
Fork bombs (a function that calls itself in a pipeline or in the background, e.g.
`:(){ :|:& };:`) are recognised structurally and always denied, because no simple command
is left to match after parsing. For `git`, global options (`-C dir`, `-c k=v`, `--git-dir=…`) are
removed and `git push -f …`/`git push origin +main` are also matched as
`git push --force …`. Command names are lower-cased basenames (`/bin/RM` → `rm`; PowerShell
aliases are matched both as typed and resolved). If a match depends on a runtime value
(`rm -rf $DIR` vs `rm -rf /`) the decision is downgraded from deny to **ask**.

### 7.6 Rule identifiers

`secret-file:<pattern>`, `secret-env:<glob>`, `env-exposure`, `command-deny:<pattern>`,
`command-ask:<pattern>`, `parse-error`, `dynamic-path`, `dynamic-shell`, `obfuscation`,
`encoded-command`, `credential-print`, `secret-dir-copy` (ask), `secret-search` (ask),
`nesting-limit`, `too-complex`, `internal-error`, `no-policy`, `unknown-tool`.
`secret-file:<pattern>` is **ask** (not deny) when a secret path is only the destination of
a copy from a non-secret file. When several rules fire, the verdict carries
the most specific one (named secret before generic dynamic rules).

### 7.7 Known limitations (not covered by the engine)

- Write-then-execute: a script written with the Write tool (or `cat > x.sh <<EOF`) and run
  later is only checked by its path, not its content; the same holds for `make`, `npm run`,
  `python script.py`, Makefiles and other files read by tools.
- Plain recursive reads of a directory: `grep -r foo .` reads `.env` and prints lines that
  match `foo`; only searches for a secret variable *name* are flagged. `docker build .` sends
  `.env` to the daemon unless `.dockerignore` excludes it.
- Symlinks/hardlinks created in an *earlier* call (`ln -s .env x`, then `cat x` later) are only
  caught with the injected symlink resolver; hardlinks are never caught. Links created in the
  same command are tracked (§7.1).
- A `cd` to a runtime value (`cd "$(git rev-parse --show-toplevel)"`, `cd $DIR`) makes relative
  paths match only the "anywhere" patterns (`.env`, `*.pem`): we assume a runtime `cd` does not
  enter a home-anchored secret directory (`cd "$(dirname ~/.aws/credentials)" && cat
  credentials` is not caught).
- Interpreter scanning is heuristic (computed strings beyond simple concatenation, `getattr`,
  `'%senv' % '.'` formatting, reflection, compression, custom encodings).
- Tools with their own command languages are partially covered: `sqlite3 '.read .env'`,
  `make --eval`, `emacs --eval`, vim ex commands without a literal secret, `less` commands,
  `ssh` remote commands.
- Env forwarding is partially covered: `docker run -e NAME`, `dotenv`/`direnv exec`/`op run`/
  `doppler run` are handled; `envsubst` over secret names, namerefs to variables assigned later
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
of nested shells. Exceeding any limit returns **deny** (`too-complex`): "too complex to analyse
safely". Inputs up to 64 KB are answered in well under 100 ms.

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
