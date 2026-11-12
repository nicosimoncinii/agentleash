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
