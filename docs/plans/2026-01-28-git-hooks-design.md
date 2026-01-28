# Git Hooks Design

## Goal

Auto-install pre-commit and pre-push hooks so formatting, linting, and tests run automatically.

## Tool

**cargo-husky** (dev-dependency) with `user-hooks` feature. Hooks install automatically on first `cargo test`.

## Hooks

| Hook | Commands | Purpose |
|------|----------|---------|
| pre-commit | `cargo fmt --check`, `cargo clippy -- -D warnings` | Fast feedback: formatting + lint |
| pre-push | `cargo test` | Full test suite before code leaves machine |

## Files

- `Cargo.toml` -- add `[dev-dependencies.cargo-husky]`
- `.cargo-husky/hooks/pre-commit` -- fmt + clippy
- `.cargo-husky/hooks/pre-push` -- test

## How It Works

1. `cargo test` triggers cargo-husky build script
2. Build script copies `.cargo-husky/hooks/*` into `.git/hooks/`
3. Git runs hooks automatically on commit/push
