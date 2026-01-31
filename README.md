# longline

A safety hook for [Claude Code](https://claude.ai/code) that parses Bash commands and enforces configurable security policies.

## What it does

longline acts as a Claude Code `PreToolUse` hook. It intercepts Bash commands before execution, parses them using tree-sitter, evaluates them against YAML-defined safety rules, and returns allow/ask/deny decisions.

**Key features:**
- Structured parsing of pipelines, redirects, command substitutions, and complex shell constructs
- Configurable safety levels (critical, high, strict)
- 300+ golden test cases for accuracy
- JSONL audit logging
- Fail-closed design: unknown/unparseable constructs default to `ask`

## Installation

```bash
# Build and install
cargo install --path .

# Copy default rules
mkdir -p ~/.config/longline
cp rules/default-rules.yaml ~/.config/longline/rules.yaml
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
            "command": "longline --config ~/.config/longline/rules.yaml"
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
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | longline --config rules/default-rules.yaml

# Inspect rules
longline rules --config rules/default-rules.yaml

# Check a specific command
longline check "rm -rf /" --config rules/default-rules.yaml
```

## Rules

Rules are defined in YAML with three matcher types:

- **command**: Match command name and arguments
- **pipeline**: Match command sequences (e.g., `curl | sh`)
- **redirect**: Match output redirection targets

Example rule:
```yaml
- id: rm-rf-root
  level: critical
  decision: deny
  reason: "Catastrophic: would delete entire filesystem"
  match:
    command:
      name: rm
      flags:
        all_of: ["-r", "-f"]
      args:
        any_of: ["/", "/*"]
```

## Safety levels

- **critical**: Catastrophic operations (rm -rf /, dd to disk, etc.)
- **high**: Dangerous operations (secret access, network exfiltration)
- **strict**: Potentially risky operations requiring review

## Decision model

- `allow`: Command is safe, proceed without prompting
- `ask`: Command requires user approval
- `deny`: Command is blocked (can be downgraded to `ask` with `--ask-on-deny`)

## License

MIT
