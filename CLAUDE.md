# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

longline is a Rust CLI that acts as a Claude Code PreToolUse hook. It parses Bash commands via tree-sitter, evaluates them against configurable YAML safety rules, and outputs allow/ask/deny decisions via the hook protocol (JSON stdin/stdout).

## Commands

```bash
cargo build                    # debug build
cargo build --release          # release build
cargo test                     # all tests (unit + golden + integration)
cargo test --lib               # unit tests only
cargo test golden              # golden tests only
cargo test --test integration  # integration tests only
cargo test test_name           # single test by name
cargo clippy -- -D warnings    # lint
cargo fmt                      # format
```

Manual testing:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | cargo run -- --config rules/default-rules.yaml
```

## Architecture

```
stdin JSON → cli.rs → parser.rs (tree-sitter → Statement AST) → policy.rs (rules + allowlist) → stdout JSON
                                                                                               → logger.rs (JSONL audit log)
```

**Key modules:**
- `cli.rs` — Hook protocol adapter, orchestrates parse/evaluate/log
- `parser.rs` — tree-sitter Bash CST → `Statement` enum (SimpleCommand, Pipeline, List, Subshell, CommandSubstitution, Opaque)
- `policy.rs` — Loads YAML rules, evaluates leaves against matchers (command/pipeline/redirect), applies allowlists
- `types.rs` — Hook I/O types and `Decision` enum (Deny > Ask > Allow ordering)
- `logger.rs` — Non-blocking JSONL append to `~/.claude/hooks-logs/longline.jsonl`

**Critical design decisions:**
- Rules evaluate **before** allowlist — rules can override safe commands (e.g., `cat .env` denies despite `cat` being allowlisted)
- Unknown/unparseable constructs become `Opaque` nodes and result in `ask` (fail-closed)
- Complex statements are flattened to leaf nodes; most-restrictive decision across all leaves wins
- Non-Bash tools get `{}` (pass-through); parse failures get `ask`
- Exit code 2 = blocking config error; exit code 0 = normal operation

## Rules DSL

Rules live in `rules/default-rules.yaml`. Three matcher types: `command` (name + flags/args globs), `pipeline` (stage subsequence), `redirect` (operator + target glob). Safety levels: Critical < High < Strict (config selects threshold).

## Tests

Golden tests in `tests/golden/*.yaml` (307+ cases across 11 files) define input commands and expected decisions. The runner in `tests/golden_tests.rs` loads each YAML and asserts against `rules/default-rules.yaml`. Integration tests in `tests/integration.rs` exercise the full binary via the hook protocol.

## Hook Protocol

- **Input:** `{"tool_name":"Bash","tool_input":{"command":"..."},"session_id":"...","cwd":"..."}`
- **Output:** `{}` for allow, or `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask|deny","permissionDecisionReason":"..."}}`
- **Config:** `~/.config/longline/rules.yaml` (override with `--config`)
