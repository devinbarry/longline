# Project Brief: `longline` — System-Installed Safety Hook for Claude Code

## Summary
Build a single, system-installed command-line tool that acts as a **Claude Code PreToolUse hook** to enforce safety policies consistently across many repos. The tool will **block or require approval** for dangerous operations while **auto-allowing** common harmless actions to reduce prompt fatigue.

The tool will use **Tree-sitter (Bash grammar)** to parse shell commands into a structured representation (AST → normalized model) and apply a **configurable rule set** (YAML/JSON DSL). Accuracy and maintainability are driven by a **large table-driven test corpus** (1000+ cases) and regression tests sourced from logs.

---

## Goals
- **Accuracy-first decisions** for Bash commands using structured parsing:
  - Correct handling of pipelines (`curl | sh`), separators (`;`, `&&`, `||`), redirects (`>`, `2>`), and nested command substitutions (`$(...)`).
- **Policy consistency across repositories** via a single installed binary (no per-repo code copies).
- **Configurable safety levels** (`critical`, `high`, `strict`) and a clear decision model:
  - `allow` for safe operations
  - `ask` for ambiguous/risky operations requiring approval
  - `deny` for catastrophic operations
- **Extensive unit testing**:
  - Golden tests in YAML for fast iteration and broad coverage (1000+ cases)
  - Regression corpus imported from logs
  - Optional fuzz/property-style tests for bypass resistance
- **Transparent logging** of decisions and rule hits for auditing and regression.

---

## Non-Goals
- Full shell evaluation (variable expansion, alias/function resolution, `eval` execution semantics).
- System policy enforcement outside Claude Code (e.g., replacing OS permissions / sudo policies).
- Perfect classification of commands involving heavy indirection (e.g., `cmd="rm -rf /"; eval "$cmd"`). These will default to **`ask`**.

---

## Users and Use Cases
### Primary user
- Developer running Claude Code across many local repos, wanting consistent guardrails.

### Core use cases
- Prevent catastrophic operations (`rm -rf /`, `dd of=/dev/sdX`, `mkfs /dev/...`).
- Prevent secret exposure/exfiltration (reading `.env`, SSH keys, cloud credentials; upload attempts via `curl/scp/rsync/nc`).
- Reduce noise by auto-allowing safe operations (`find` without `-delete` or destructive `-exec`, safe read-only `-exec`).
- Provide actionable reasons when decisions are `ask` or `deny`.

---

## High-Level Architecture

### 1) CLI Wrapper (Hook Adapter)
- Reads hook JSON from `stdin` and outputs Claude hook decision JSON to `stdout`.
- Validates tool context and routes to appropriate analyzers:
  - `Bash` → command parsing + policy rules
  - `Read|Edit|Write` → path policy rules
- Minimal logic; delegates to core engine.

### 2) Parser + Normalizer (Bash)
- Uses **Tree-sitter Bash** to parse the command string into a syntax tree.
- Normalizes to a simplified internal model suitable for matching:
  - `Command { argv, assignments, redirects }`
  - `Pipeline { stages: [Command] }`
  - Lists/sequences (`;`, `&&`, `||`)
  - Subshells / command substitutions as nested statements

### 3) Policy Engine
- Loads a ruleset from YAML/JSON DSL.
- Applies:
  - Allowlists (paths/commands) first
  - Tool-specific matchers next
  - Decision model with safety-level threshold
- Safe default:
  - Parse failures, unhandled AST nodes, heavy indirection → **`ask`** (configurable)

### 4) Logging + Regression Capture
- JSONL logs to `~/.claude/hooks-logs/` (or configurable).
- Include: timestamp, tool, cwd, command/path (truncated), decision, rule id, reason, session metadata.
- Optional: log unknown patterns / parse failures to feed regression tests.

---

## Rules DSL (Configuration)

### Top-level
- `version`, `default_decision`, `safety_level`
- `allowlists` for known-safe templates/paths (e.g., `.env.example`)
- `rules` list with stable IDs and structured matchers

### Rule fields
- `id`: stable string used in logs/tests
- `level`: `critical|high|strict` (compared to configured threshold)
- `match`: structured matcher (tool, command, pipeline, redirect, `find` semantics)
- `decision`: `allow|ask|deny`
- `reason`: human-readable explanation

### Supported matcher types (v1 target)
- `tool`: match `Bash` vs `Read|Edit|Write`, with nested match
- `command`: match command name and argv tokens
- `pipeline`: match stage sequence (e.g., download tool → shell)
- `redirect`: match redirect operator and target path
- `find`: semantic matcher for `find` operations (e.g., `-delete`, `-exec` target)

---

## Testing Strategy

### A) Golden Tests (table-driven)
- YAML test cases specifying tool + input + expected `{decision, rule_id}`.
- Designed for rapid addition of new cases as Claude produces novel command patterns.

### B) Regression Tests from Logs
- Periodically extract:
  - parse failures
  - `ask` decisions (ambiguous/risky)
  - unexpected allows/denies
- Convert into golden tests to prevent backsliding.

### C) Optional Fuzz / Property Tests
- Generate syntactic variations:
  - whitespace, quoting, separators, nesting
- Assert invariants:
  - catastrophic patterns must never return `allow`
  - known-safe patterns must not be forced to `ask` once covered

---

## Milestones (Suggested)
1. **MVP**
   - CLI hook adapter (stdin JSON → stdout decision JSON)
   - Read/Edit/Write path rules (regex/glob) + allowlist
   - Bash parsing via Tree-sitter + normalized model for simple commands/pipelines
   - Basic rules DSL + 200 golden tests

2. **Structured Bash Coverage**
   - Pipelines, redirects, separators, command substitutions
   - `find` semantic analyzer (safe allowlist vs destructive ops)
   - Expand to 1000+ golden tests + regression import script

3. **Hardening**
   - Better ambiguity detection (eval/indirection patterns → `ask`)
   - Performance tuning (parser reuse, compiled regex/glob sets)
   - Release packaging (Homebrew/apt, or a single static binary)

---

## Risks and Mitigations
- **Shell complexity / edge cases**
  - Mitigation: structured parsing + conservative `ask` fallback; expand tests via regression logs.
- **False positives causing prompt fatigue**
  - Mitigation: AST-aware matching, allowlists, rule refinement driven by golden tests.
- **False negatives / bypasses**
  - Mitigation: treat indirection as `ask`; add fuzz/property tests; prioritize catastrophic blocks.

---

## Deliverables
- `longline` Rust binary (system-installed)
- Ruleset file (YAML) with documented defaults
- Test corpus (YAML) with 1000+ cases + CI test runner
- JSONL logging + simple tooling to convert logs → tests
- Documentation: installation, configuration, safety levels, rule authoring, troubleshooting

---

## Success Criteria
- Blocks/asks for all known dangerous patterns in the test corpus.
- Minimal false positives for common safe workflows (`find`, `git status`, safe reads).
- Easy policy updates via rules file without changing per-repo configuration.
- CI runs the full test suite quickly (target: seconds, not minutes).
