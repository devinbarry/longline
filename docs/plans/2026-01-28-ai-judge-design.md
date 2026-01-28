# AI Judge Design

## Problem

`python`, `python3`, `node`, `ruby`, `perl` are allowlisted as bare commands. This means `python3 -c "import shutil; shutil.rmtree('/')"` passes as `allow`. Inline code execution via interpreters is equivalent to arbitrary shell access and should not be auto-allowed.

Claude frequently uses `python -c` for file processing, JSON/YAML manipulation, and data transformations. During heavy Python sessions, every invocation triggers `ask`, requiring manual approval — often 15+ times in a row.

## Solution

Two changes:

1. **Remove interpreters from the allowlist.** Add rules for known-safe patterns (`--version`, `-m json.tool`). Everything else defaults to `ask`.
2. **Add an AI judge (`--ask-ai` flag).** When enabled, interpreter + inline code commands are evaluated by an LLM instead of prompting the user. The LLM can only return `allow` or `ask` — never `deny`.

## CLI Flag

```
longline --config rules/default-rules.yaml --ask-ai
```

Toggle in hook config. No flag = normal behavior. Flag present = LLM evaluates inline code.

## Config File (`~/.config/longline/ai-judge.yaml`)

```yaml
command: codex exec
timeout: 15
triggers:
  interpreters:
    - name: [python, python3]
      inline_flag: "-c"
    - name: [node]
      inline_flag: "-e"
    - name: [ruby]
      inline_flag: "-e"
    - name: [perl]
      inline_flag: "-e"
```

If `--ask-ai` is passed but no config file exists, use these as defaults. The config is for customization (swap LLM backend, adjust timeout), not required.

## Prompt Template

Baked into the binary:

```
Security evaluation of inline {language} code to be executed on a developer's machine.

Working directory: {cwd}

\`\`\`{language}
{code}
\`\`\`

Evaluate safety. Respond with EXACTLY one line, no other output:

ALLOW: <brief reason>
— Code only does: computation, data formatting, printing output, reading/writing
  files in the working directory or temp directories (/tmp, $TMPDIR, tempfile
  module), string/regex operations, JSON/YAML/CSV parsing, encoding, hashing,
  math, type checking, or version queries.

ASK: <brief reason>
— Code does ANY of: write/delete/move/rename files outside temp dirs or the
  working directory, network requests, subprocess or shell execution (os.system,
  subprocess), access secrets or credentials (.env, SSH keys, tokens), modify
  system configuration, install packages, or access sensitive paths outside the
  working directory.
```

## Rules Changes (`default-rules.yaml`)

Remove from allowlist:
```yaml
# Remove these:
- python
- python3
- node
- ruby
```

Add rules for known-safe invocations:
```yaml
- id: interpreter-version
  level: critical
  match:
    command:
      any_of: [python, python3, node, ruby, perl]
    flags:
      any_of: ["--version", "-V", "-v"]
  decision: allow
  reason: "Version check"

- id: python-module-safe
  level: critical
  match:
    command:
      any_of: [python, python3]
    flags:
      any_of: ["-m"]
    args:
      any_of: ["json.tool", "py_compile", "compileall", "this", "antigravity"]
  decision: allow
  reason: "Safe Python module invocation"
```

Everything else (including `python3 script.py` and `python3 -c "..."`) defaults to `ask`, which the AI judge can intercept when `--ask-ai` is active.

## Architecture

```
stdin JSON -> cli.rs -> parser.rs -> policy.rs
                                       |
                                 interpreter + inline flag?
                                    |           |
                                   no          yes + --ask-ai
                                    |           |
                               normal flow   ai_judge.rs
                                              |         |
                                           ALLOW:     ASK: / timeout / error
                                              |         |
                                         allow out   ask out
```

### New module: `ai_judge.rs`

- `fn evaluate(language: &str, code: &str, cwd: &str) -> Decision`
- Loads config from `~/.config/longline/ai-judge.yaml` (or defaults)
- Builds prompt from template, substituting `{language}`, `{code}`, `{cwd}`
- Spawns `codex exec "{prompt}"` via `std::process::Command`
- Applies timeout (default 15s)
- Scans output lines for first `^ALLOW:` or `^ASK:` match
- Returns `Allow` on ALLOW match, `Ask` on everything else

### Hook point: `policy.rs`

In `evaluate_leaf()`, after rules check, before allowlist/default fallback:

1. Check if `--ask-ai` is active
2. Check if the command matches a trigger (interpreter name in `cmd.name`, inline flag in `cmd.argv`)
3. If both: extract the code string (the argv element after the inline flag), call `ai_judge::evaluate()`
4. Return the AI judge's decision

### Fail-safe property

Every error path resolves to `ask`:

| Scenario | Result |
|----------|--------|
| `--ask-ai` not passed | Normal `ask` behavior |
| Config file missing | Use defaults, continue |
| `codex` not installed | `ask` |
| Timeout exceeded | `ask` |
| Unparseable output | `ask` |
| LLM says ASK | `ask` |
| LLM says ALLOW | `allow` |

The AI judge can only reduce friction, never bypass safety.

## Implementation Order

1. Remove interpreters from allowlist, add safe-pattern rules, add golden tests
2. Add `--ask-ai` CLI flag (clap)
3. Add `ai_judge.rs` module with config loading and prompt building
4. Add `codex exec` invocation with timeout and output parsing
5. Wire into `policy.rs` evaluation flow
6. Integration tests with mock LLM command

## Future Extensions

- Audit log: record AI judge decisions in the JSONL log alongside rule decisions
- Cache: hash the code string, cache ALLOW decisions for identical code within a session
- Multi-backend: config already supports swapping `codex exec` for `claude -p` or `gemini`
- Script file evaluation: read the file content for `python script.py` and evaluate it too
