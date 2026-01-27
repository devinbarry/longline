# longline Stage 2 Design

Builds on the MVP to add file path rules, `find` semantic analysis, log-to-test import, expanded rule coverage (150+), and `additionalContext` support.

## 1. Read/Edit/Write Path Rules

### Tool routing

The CLI adapter routes by `tool_name`:
- `Bash` -> parser + policy engine (MVP flow)
- `Read` | `Edit` | `Write` -> path policy engine (new)

For Read/Edit/Write, `tool_input.file_path` is the primary input. Paths are resolved relative to `cwd` before matching.

### Path rule syntax

Rules live in the same `rules.yaml` file. The `tool` matcher distinguishes them:

```yaml
rules:
  - id: read-env-file
    level: critical
    match:
      tool: { any_of: [Read, Edit, Write] }
      path:
        pattern: "**/.env"
        exclude: ["**/.env.example", "**/.env.sample", "**/.env.template",
                   "**/.env.schema", "**/.env.defaults"]
    decision: deny
    reason: "Sensitive environment file"

  - id: read-ssh-key
    level: critical
    match:
      tool: { any_of: [Read] }
      path:
        pattern: "~/.ssh/id_*"
    decision: deny
    reason: "SSH private key"

  - id: write-etc-hosts
    level: high
    match:
      tool: { any_of: [Write, Edit] }
      path:
        pattern: "/etc/hosts"
    decision: deny
    reason: "System hosts file modification"
```

### Path matching

- Glob patterns (not regex) -- natural for file paths.
- `exclude` field for allowlist exceptions.
- `~` expanded to home directory.
- Same "most restrictive wins" evaluation as Bash rules.

## 2. `find` Semantic Analyzer

Dedicated matcher type for `find` commands. The parser extracts `find`'s structure (path, predicates, actions); the rules DSL matches against it.

### What makes `find` dangerous

- `-delete` flag
- `-exec` / `-execdir` with destructive commands (rm, shred, truncate)
- `-exec` piping to network tools

### What makes `find` safe

- Filtering predicates only: `-name`, `-type`, `-mtime`, `-size`
- Safe output actions: `-print`, `-print0`, `-ls`
- Read-only exec: `-exec cat {} \;`, `-exec grep ... {} \;`

### Rules DSL

```yaml
- id: find-delete
  level: high
  match:
    find:
      actions: { any_of: ["-delete"] }
  decision: deny
  reason: "find with -delete flag"

- id: find-exec-destructive
  level: high
  match:
    find:
      exec_command: { any_of: [rm, shred, truncate] }
  decision: deny
  reason: "find -exec with destructive command"

- id: find-exec-exfiltrate
  level: high
  match:
    find:
      exec_command: { any_of: [curl, scp, rsync, nc] }
  decision: deny
  reason: "find -exec with network exfiltration tool"
```

### Matcher fields

- `find.actions`: match action flags (`-delete`, `-prune`)
- `find.exec_command`: match the command name inside `-exec` / `-execdir`
- `find.path`: match the search root path

## 3. `import-log` Subcommand

Converts JSONL decision logs into golden test case stubs.

### Usage

```bash
# Import 'ask' decisions from last 7 days
longline import-log --filter decision=ask --since 7d

# Import parse failures
longline import-log --filter parse_ok=false

# Import from specific session
longline import-log --filter session_id=abc123

# Output to file
longline import-log --filter decision=deny -o tests/golden/regression.yaml
```

### Output format

```yaml
# Auto-generated from logs. Review and set expected decisions.
tests:
  - id: imported-2026-01-27-001
    command: "npm run build && rm -rf dist"
    actual_decision: ask
    actual_rule_id: rm-recursive-path
    expected:
      decision: ask
      rule_id: rm-recursive-path
```

### Workflow

1. Logs accumulate during normal use.
2. Run `import-log` periodically to extract interesting decisions.
3. Human reviews stubs, confirms or corrects expected decisions.
4. Move approved cases into `tests/golden/`, remove `actual_*` fields.
5. `cargo test` catches regressions.

## 4. Expanded Default Rules (150+)

### Rule categories

| Category | Count | Examples |
|----------|-------|---------|
| Filesystem destruction | ~20 | rm root, dd disk, mkfs, truncate, shred |
| Secrets exposure | ~25 | .env, SSH keys, cloud creds, certificates |
| Exfiltration | ~15 | curl upload, scp, rsync, nc, base64 encode secrets |
| VCS destructive | ~15 | force push, reset hard, clean -f, branch -D |
| Shell injection | ~10 | curl\|sh, eval, fork bombs |
| Network/process ops | ~20 | kill system procs, iptables, firewall, DNS, port binding |
| Package manager abuse | ~15 | untrusted npm/pip/gem install, custom indices |
| System config modification | ~20 | /etc/hosts, sudoers, crontab, shell profiles, launchctl |
| find operations | ~10 | -delete, destructive -exec, exfiltration -exec |

### Allowlists (shipped defaults)

- Safe read-only commands: `ls`, `cat`, `head`, `tail`, `grep`, `find` (without destructive flags), `wc`, `file`, `which`, `type`, `echo`
- Safe git operations: `status`, `diff`, `log`, `branch`, `show`, `stash list`
- Safe env files: `.env.example`, `.env.sample`, `.env.template`, `.env.schema`, `.env.defaults`
- Safe paths: `/tmp/**`, project-local `node_modules`, `target/`, `dist/`, `build/`

## 5. `additionalContext` Support

Rules can include a `context` field that maps to the hook protocol's `additionalContext`. This injects guidance into Claude's conversation.

### Rules DSL

```yaml
- id: crontab-edit
  level: high
  match:
    command: crontab
    flags:
      any_of: ["-e", "-r"]
  decision: ask
  reason: "System crontab modification"
  context: "Consider using a project-local task scheduler instead of system crontab."
```

### Output

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "[crontab-edit] System crontab modification",
    "additionalContext": "Consider using a project-local task scheduler instead of system crontab."
  }
}
```

### Behavior

- `context` field is optional in rules. If absent, no `additionalContext` in output.
- For `deny` decisions, context helps Claude understand what to do instead.
- For `ask` decisions, context helps the user make an informed approval choice.

## Key decisions (Stage 2)

| Decision | Choice |
|----------|--------|
| Path matching | Globs with exclude patterns |
| Path rules location | Same rules.yaml as Bash rules |
| find analyzer | Rules DSL matcher (not hardcoded) |
| Default rule count | 150+ across 9 categories |
| additionalContext | Optional `context` field in rules |
| import-log output | YAML stubs with actual + expected fields |
