# Test corpora

`internal/engine/corpus_test.go` evaluates every case in these folders. The corpus baseline
policy is **`policies/default-like.yaml`**, not `policy.Default()`: it is pinned here so the
corpus cannot silently weaken if the built-in default changes. A file or a single case can
override it with `policy:` (a path relative to this folder).

- `attacks/*.yaml`: every case must be **blocked**: `expect: deny`, or `expect: ask` when the
  policy puts the command in its `ask` list. A stricter verdict than expected passes
  (`deny` satisfies `expect: ask`); the mismatch is only logged with `t.Log`. A weaker
  verdict (`ask` for `expect: deny`, or `allow`) fails.
- `benign/*.yaml`: every case must be **allowed**, exactly (`expect: allow`). False positives make
  people uninstall security tools, so this corpus matters as much as the attack one.
- `project/`: a fake project used as working directory and project root. Its "secrets" are
  dummy values.
- `home/`: a fake home directory (`Request.Home`), with dummy `~/.ssh` and `~/.aws` files so
  glob and filesystem lookups have something to find.
- `policies/`: policy files referenced by `policy:`.

## Format

```yaml
# testdata/attacks/shell-indirection.yaml
description: Reading .env through shell indirection   # required
policy: policies/other.yaml   # optional, file-wide policy override
cases:
  - name: command substitution   # required, unique within the file
    tool: shell          # shell | read | search | write | other
    shell: bash          # bash (default) | powershell; only with tool: shell
    command: 'echo "$(cat .env)"'   # required for tool: shell
    expect: deny         # required: deny | ask (attacks), allow (benign)
    note: required in attacks/ - explain the trick; link to a report, credit
  - name: read tool
    tool: read
    paths: [".env"]      # required for read/search/write; relative to cwd
    expect: deny
    note: Direct Read tool access.
  - name: from a subdirectory
    tool: shell
    cwd: src             # optional; relative to testdata/project (default: the project root)
    home: /home/u        # optional; overrides Request.Home (default: testdata/home)
    policy: policies/other.yaml   # optional, per-case policy override
    command: cat ../.env
    expect: deny
    note: ...
```

`{{project}}` and `{{home}}` in `command` and `paths` are replaced with the absolute project
root and home directory (forward slashes), for absolute-path cases. Quote them in shell
commands: the checkout path may contain spaces.

The loader is strict: unknown fields, a missing `expect`, an `expect` not allowed in that
folder, duplicate names, a missing `note` on an attack, or a malformed case fail the test.

One file per technique family (e.g. `env-exposure.yaml`, `encoding-exfil.yaml`,
`globbing.yaml`). Credit external reporters in `note`.
