# Test corpora

`internal/engine/corpus_test.go` evaluates every case in these folders with the
**default policy** (`policy.Default()`) unless the file sets `policy:` to a path relative to
this folder.

- `attacks/*.yaml`: every case must be **blocked** (`deny`, or `ask` when the case says so).
- `benign/*.yaml`: every case must be **allowed**. False positives make people uninstall
  security tools, so this corpus matters as much as the attack one.
- `project/`: a fake project used as working directory and project root. Its "secrets" are
  dummy values.

## Format

```yaml
# testdata/attacks/shell-indirection.yaml
description: Reading .env through shell indirection
cases:
  - name: command substitution
    tool: shell          # shell | read | search | write | other
    shell: bash          # bash (default) | powershell
    command: 'echo "$(cat .env)"'
    expect: deny         # deny | ask | allow
    note: optional explanation, link to a report, credit
  - name: read tool
    tool: read
    paths: [".env"]      # relative to testdata/project
    expect: deny
```

One file per technique family (e.g. `env-exposure.yaml`, `encoding.yaml`, `globbing.yaml`).
Credit external reporters in `note`.
