---
name: longline-repo-allowlist
description: Add per-repo longline allowlist rules so specific commands stop prompting in a given project. Use when the user says commands are getting "ask" in a repo and wants them allowed, or asks to create/update a `.claude/longline.yaml` project config. Triggers include "allow kubectl in this repo", "stop asking about X commands", "add longline rules for this project", "allowlist commands in repo Y".
---

# Longline Per-Repo Allowlist

Create or update `.claude/longline.yaml` in a target repo so that specific commands get `allow` instead of `ask`.

## Workflow

### 1. Identify commands to allow

Check the longline audit log for recent `ask` decisions scoped to the target repo:

```bash
tail -500 ~/.claude/hooks-logs/longline.jsonl | grep '"ask"' | grep '<target-cwd>' | tail -50
```

Extract the distinct command names (first word of each command string, or basename if absolute path). Note any companion commands that appear in compound expressions (e.g. `export` in `export KUBECONFIG=... && kubectl ...`).

### 2. Check for compound-command companions

Longline evaluates compound statements by flattening to leaf nodes; the **most-restrictive** decision wins. A command like:

```bash
export FOO=bar && kubectl get pods
```

has two leaves: `export` and `kubectl`. If `export` is not allowlisted, the whole command gets `ask` even when `kubectl` is allowed. Common companions to watch for:

- `export` (setting env vars before the real command)
- `source` / `.` (loading env files — note: intentionally excluded from core allowlist due to secrets risk; only add per-project when appropriate)

### 3. Create or update the project config

File location: `<repo-root>/.claude/longline.yaml`

All fields are optional. Schema:

```yaml
# override_safety_level: critical | high | strict
# override_trust_level: minimal | standard | full

allowlists:
  commands:
    - { command: "<name>", trust: standard, reason: "<why>" }
    # trust: minimal | standard | full
    # reason is optional but recommended

# rules: []        # append custom rules (same schema as rules/*.yaml)
# disable_rules: [] # remove built-in rules by ID
```

Allowlist entries match by command basename, so both `kubectl` and `/usr/local/bin/kubectl` match a `{ command: kubectl }` entry. Multi-word entries like `{ command: "docker compose" }` match the command plus its first argument.

### 4. Verify

Test representative commands from the logs against the new config:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"<cmd>"},"session_id":"test","cwd":"<repo-path>"}' \
  | longline --config <rules-path>
```

If longline is not on PATH, use `cargo run --manifest-path <longline-repo>/Cargo.toml --` instead.

Confirm the output shows `"permissionDecision":"allow"`. Test at least:
- A simple invocation (`kubectl get pods`)
- A compound invocation (`export VAR=val && kubectl get pods`)
- A pipeline if present in the logs (`kubectl ... | grep ...`)

### 5. Gotchas

- **`export` is not in the core allowlist.** If the repo's commands use `export VAR=... && cmd`, add `export` to the project allowlist.
- **`source` / `.` are not in the core allowlist** (secrets risk). Only add per-project when you understand what files are being sourced.
- **`sed` / `awk` are in the core allowlist** at `trust: standard`, so pipelines like `kubectl ... | sed ...` work without extra entries.
- **Rules evaluate before allowlist.** If a built-in rule denies a command pattern (e.g. writing to sensitive paths), the allowlist won't override it. Use `disable_rules` to remove specific rules if needed.
- **Unknown fields cause exit code 2** (fail-closed). Double-check field names against the schema above.
