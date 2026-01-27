# longline MVP Design

System-installed Rust CLI that acts as a Claude Code PreToolUse hook. Parses Bash commands with Tree-sitter, applies configurable safety rules, outputs allow/ask/deny decisions.

## Architecture

```
stdin (JSON) --> CLI Adapter --> Bash Parser --> Policy Engine --> stdout (JSON)
                                                      |
                                                      v
                                                  JSONL Logger
```

Four modules: `cli`, `parser`, `policy`, `logger`.

## Scope

MVP handles `Bash` tool only. Read/Edit/Write path rules deferred to Stage 2.

## Hook Protocol

### Input (stdin)

Claude Code sends this JSON:

```json
{
  "session_id": "abc123",
  "cwd": "/Users/dev/project",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "rm -rf /tmp/build",
    "description": "Clean build directory"
  },
  "tool_use_id": "toolu_01ABC123..."
}
```

### Output (stdout)

**Allow** (no objection -- passes through):
```json
{}
```

**Block or ask** (with reason):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "[rm-recursive-root] Recursive delete targeting critical system path"
  }
}
```

Valid `permissionDecision` values: `allow`, `ask`, `deny`.

- `allow` reason is shown to the user (not Claude).
- `ask` reason is shown to the user (not Claude) as a confirmation prompt.
- `deny` reason is shown to Claude (so it can adjust its approach).

### Exit codes

- **0**: Success. JSON in stdout is parsed and processed.
- **2**: Blocking error. stderr shown to Claude, tool call blocked. Used for config errors.
- **Other**: Non-blocking error. stderr shown to user in verbose mode.

## CLI Adapter

- Reads hook JSON from stdin, extracts `tool_name` and `tool_input.command`.
- For non-Bash tools, outputs `{}` (pass through) in MVP.
- Flags: `--config <path>` (override rules location), `--dry-run` (testing mode).

### Error handling

| Failure | Behavior |
|---------|----------|
| Malformed hook JSON | Output ask decision with reason |
| Bash parse failure | Output ask decision with reason |
| Rules file missing/malformed | Exit code 2, error to stderr |

## Parser

Uses `tree-sitter` + `tree-sitter-bash` to parse command strings into a normalized model.

### Normalized model

```rust
enum Statement {
    SimpleCommand(SimpleCommand),
    Pipeline(Pipeline),
    List(List),
    Subshell(Box<Statement>),
    CommandSubstitution(Box<Statement>),
    Opaque(String), // eval, heavy indirection, unhandled nodes
}

struct SimpleCommand {
    name: Option<String>,
    argv: Vec<String>,
    redirects: Vec<Redirect>,
    assignments: Vec<Assignment>,
}

struct Pipeline {
    stages: Vec<Statement>,
    negated: bool,
}

struct List {
    first: Box<Statement>,
    rest: Vec<(ListOp, Statement)>,
}

enum ListOp { Semi, And, Or }

struct Redirect {
    fd: Option<u32>,
    op: RedirectOp,
    target: String,
}
```

### Parsing strategy

1. Feed command to tree-sitter with Bash grammar.
2. Walk CST recursively, map known node types to model types.
3. Unhandled node types become `Opaque(raw_text)`.
4. Command substitutions parsed recursively as nested `Statement`.
5. Opaque nodes don't poison siblings -- each part analyzed independently.

## Policy Engine

### Rule loading

- Load from `~/.config/longline/rules.yaml` (or `--config` override).
- Validate schema on startup. Invalid config = exit code 2 with diagnostic to stderr.
- Rules kept in memory for the single invocation.

### Evaluation flow

1. Flatten parsed `Statement` into leaf `SimpleCommand` and `Opaque` nodes.
2. For each leaf:
   - Check allowlists first. Match = `allow`.
   - Evaluate all rules. Collect matches.
   - `Opaque` nodes = `ask` (unless allowlisted).
3. Final decision = most restrictive across all leaves: `deny > ask > allow`.
4. Return decision + reason from the most restrictive matching rule.

### Rules DSL

```yaml
version: 1
default_decision: ask
safety_level: high

allowlists:
  commands:
    - git status
    - git diff
    - git log
  paths:
    - "/tmp/**"

rules:
  - id: rm-recursive-root
    level: critical
    match:
      command: rm
      flags:
        any_of: ["-r", "-R", "--recursive"]
      args:
        any_of: ["/", "/*", "/home", "/etc"]
    decision: deny
    reason: "Recursive delete targeting critical system path"

  - id: curl-pipe-shell
    level: critical
    match:
      pipeline:
        stages:
          - command: { any_of: [curl, wget] }
          - command: { any_of: [sh, bash, zsh] }
    decision: deny
    reason: "Remote code execution: piping download to shell"
```

### Matcher types (MVP)

- `command`: exact match on command name
- `flags.any_of` / `flags.all_of`: flag presence in argv
- `args.any_of`: positional arg match (supports globs)
- `pipeline.stages`: ordered command matchers across pipeline stages
- `redirect`: match redirect operator and target path

## Logging

Single JSONL file at `~/.claude/hooks-logs/longline.jsonl`.

```json
{
  "ts": "2026-01-27T14:30:00.123Z",
  "tool": "Bash",
  "cwd": "/Users/dev/project",
  "command": "rm -rf /tmp/build",
  "decision": "allow",
  "matched_rules": [],
  "reason": null,
  "parse_ok": true,
  "session_id": "abc123"
}
```

- Command field truncated at 1024 chars.
- Create log directory if missing.
- Logging failure does not block decision output (error to stderr).

## Testing

Golden tests in `tests/golden/**/*.yaml` using the actual shipped rules file.

```yaml
tests:
  - id: rm-rf-root
    command: "rm -rf /"
    expected:
      decision: deny
      rule_id: rm-recursive-root

  - id: rm-tmp-file
    command: "rm /tmp/build/output.o"
    expected:
      decision: allow
```

Test runner: standard `#[test]` function discovering and loading YAML files.
MVP target: 200+ golden test cases.

## Config location

`~/.config/longline/rules.yaml` with `--config` CLI override.

## Key decisions

| Decision | Choice |
|----------|--------|
| MVP scope | Bash only |
| Hook protocol | `hookSpecificOutput` with `permissionDecision` |
| Parser | tree-sitter + tree-sitter-bash |
| Unknown constructs | Explicit `Opaque` variant |
| Rule conflicts | Most restrictive wins |
| Arg matching | Structured argv (name + flags + args) |
| Compound commands | Flatten, evaluate independently |
| All parse/protocol errors | `ask` (fail-closed) |
| Bad rules file | Exit code 2 (blocking error to stderr) |
| Log rotation | None (MVP) |
