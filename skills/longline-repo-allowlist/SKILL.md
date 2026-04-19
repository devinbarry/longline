---
name: longline-repo-allowlist
description: Use when scoping allow/ask rules for a command family (kubectl, oc, terraform, aws, gcloud, docker, etc.) to one repository so routine invocations stop prompting only inside that repo. Triggers include "allow kubectl in this repo", "stop asking about X commands", "add longline rules for this project", "allowlist commands in repo Y", or creating/updating a `.claude/longline.yaml` project config.
---

# Longline Per-Repo Allowlist

Create or update `.claude/longline.yaml` in a target repo so specific commands get `allow` (or a narrower `ask`) instead of the default `ask`.

**Core mechanism:** longline walks up from the hook invocation's `cwd` looking for `.git` or `.claude`, finds `<repo>/.claude/longline.yaml`, and **overlays it on top of the embedded defaults**. You never pass `--config` (that would replace the defaults), never edit the global `PreToolUse` hook, and never touch `~/.claude/settings.json`.

**Core technique:** rules evaluate *before* allowlists. That lets you allowlist a broad prefix (`oc get`) and add a narrow rule that overrides it (`oc get secret` → ask).

## Workflow

### 1. Identify commands to allow

longline writes every decision to `~/.claude/hooks-logs/longline.jsonl`. Filter for the target repo and tool — use real usage, not guesses from docs:

```bash
jq -r 'select(.cwd | startswith("/abs/path/to/target-repo"))
       | select(.command | startswith("TOOL "))
       | .command' \
  ~/.claude/hooks-logs/longline.jsonl | sort -u
```

Quick grep variant if jq isn't handy:

```bash
grep '"cwd":"/abs/path/to/target-repo' ~/.claude/hooks-logs/longline.jsonl \
  | grep '"decision":"ask"' | tail -50
```

### 2. Classify: safe vs unsafe

| Safe → allowlist        | Unsafe → ask (default)                            |
|-------------------------|---------------------------------------------------|
| `get`, `list`, `describe`, `logs`, `status`, `version`, `history`, `explain`, `api-resources`, `whoami`, `auth can-i`, `config view` | `apply`, `create`, `delete`, `patch`, `edit`, `replace`, `set`, `scale`, `rollout undo/restart`, `exec`, `rsh`, `cp`, `port-forward`, `login --token`, `import-image`, `start-build`, `debug`, `new-*` |

Credential-exposing reads (`get secret`, `extract`, `describe secret`) go in the **ask-rule** bucket even though they look read-only.

### 3. Check for compound-command companions

longline flattens compound statements to leaf nodes and the **most-restrictive decision wins**. `export FOO=bar && kubectl get pods` has two leaves: `export` and `kubectl`. If `export` isn't allowlisted the whole command asks.

Common companions:
- `export` (setting env vars before the real command) — **not** in core allowlist
- `source` / `.` (loading env files) — intentionally excluded from core (secrets risk); add per-project only when you know what's being sourced

### 4. Write `<repo>/.claude/longline.yaml`

All fields are optional. `deny_unknown_fields` is on — typos exit 2 and block every Bash hook call.

```yaml
# override_safety_level: critical | high | strict
# override_trust_level: minimal | standard | full
# disable_rules: [rule-id]     # remove built-in rules by ID

allowlists:
  commands:
    # Ordered argv prefix match. "TOOL get" covers "TOOL get pods -n ns -o yaml"
    # but not "TOOL describe pods".
    - { command: "TOOL get",       trust: minimal }
    - { command: "TOOL describe",  trust: minimal }
    - { command: "TOOL logs",      trust: minimal }
    # Companion commands from step 3, if your repo needs them:
    # - { command: "export",       trust: standard, reason: "env setup before TOOL" }

rules:
  # Override allowlist for sensitive variants — rules run first.
  - id: tool-get-secret
    level: high
    match:
      command: TOOL
      args:  { any_of: ["secret", "secrets", "secret/*", "secrets/*"] }
      flags: { any_of: ["get", "describe", "extract"] }
    decision: ask
    reason: "TOOL get/describe/extract on secrets reveals credentials"
```

**Matcher notes:**
- Allowlist entries match by **basename**, so `kubectl` and `/usr/local/bin/kubectl` both match `{ command: kubectl }`.
- Multi-word allowlist entries (`"docker compose"`) match the command plus its first argument(s) as an ordered prefix.
- Rule `args.any_of` / `flags.any_of` match anywhere in argv; glob syntax via `glob_match` (`secret/*` works).

### 5. Verify

Batch-test candidate commands (including traps — the rule/allowlist precedence is the part most likely to surprise):

```bash
printf 'TOOL get pods
TOOL get secret foo
TOOL describe pod bar
TOOL delete pod baz
TOOL apply -f x.yaml
export FOO=bar && TOOL get pods
' | longline check --dir /abs/path/to/target-repo
```

Output is a `DECISION | RULE | COMMAND` table. The `Project config:` banner at the top confirms the overlay loaded. `(allowlist)` / `(default)` show the fallback; a rule ID means a rule fired. Confirm at minimum: one safe case allows, one mutating case asks, one credential trap asks, and any compound case you care about resolves correctly.

Inspect only the project additions:

```bash
longline rules --dir /abs/path/to/target-repo --filter source:project
```

## Gotchas

| Mistake | Fix |
|---|---|
| Using `--config` to point at the new file | Don't. That replaces embedded defaults. Just write `.claude/longline.yaml` — longline overlays it automatically. |
| Editing `~/.claude/settings.json` for a per-repo hook | Unnecessary — the existing `longline` invocation reads `cwd` from stdin and picks up the overlay. |
| Allowing `TOOL get` without an ask-rule for `get secret` | Secret contents leak. Always pair broad `get`/`describe` allowlists with a narrow secret-ask rule. |
| Guessing the subcommand list from docs | You'll miss real-usage variants (`get dc/foo`, `rollout history dc/x`, `adm policy who-can`). Always harvest the JSONL log. |
| `export`/`source` not allowlisted but used as compound prefix | Whole command asks because of the leaf. Add `export` to the project allowlist; only add `source`/`.` if you understand what's being sourced. |
| `allowlist:` (singular) or `rule:` (singular) or `decision: allowed` | `deny_unknown_fields` → exit 2 → silently blocks every Bash hook call. Keys are plural: `allowlists:`, `rules:`; decisions are `allow` / `ask` / `deny`. |
| Skipping verification | Rule-vs-allowlist precedence surprises. Always run `longline check --dir` with a safe case, a mutating case, and a credential trap before reporting done. |

## Quick reference

- Overlay path: `<repo>/.claude/longline.yaml`
- Log path: `~/.claude/hooks-logs/longline.jsonl`
- Verify: `printf '…' | longline check --dir <repo>`
- Inspect loaded rules: `longline rules --dir <repo> --filter source:project`
- Source of truth: `src/policy/config.rs` (`ProjectConfig`, `load_project_config`, `merge_project_config`)
