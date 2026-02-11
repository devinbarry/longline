# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-02-11

### Added

- **Project config discovery via `--dir` flag**: Rules, check, and files subcommands can now discover and merge per-project configs, with a SOURCE column in table output distinguishing global vs project rules
- **Transparent wrapper unwrapping**: Commands like `env`, `nice`, `timeout`, `nohup`, etc. are now recognized as transparent wrappers; their inner commands are extracted (with chaining and depth limits) and evaluated against policy rules
- **Expanded core allowlist**: Added shasum, network diagnostics (ip/arp/route read-only), longline self-reference, and brew (read-only subcommands plus mutation rules for upgrade/uninstall/update/tap/services/link/cleanup)

### Changed

- Golden tests added for network diagnostics, shasum, longline, brew, and transparent wrapper commands

## [0.3.1] - 2026-02-09

### Added

- **Embedded default rules**: Rules are now compiled into the binary at build time; longline works out of the box without a config file, falling back to embedded defaults
- **`longline init` subcommand**: Extracts the embedded rules to disk for customization
- Renamed "manifest" to "rules" throughout the codebase for clarity

### Fixed

- `check` subcommand now errors on TTY stdin instead of silently blocking

## [0.3.0] - 2026-02-08

### Added

- **Per-project config**: Projects can place `.claude/longline.yaml` in their repo root to add project-specific rules and allowlists, discovered via `.git` or `.claude` directory; unknown fields produce exit code 2
- **Trust-level tiered allowlists**: Allowlist entries now carry a trust tier, shown as a breakdown in the `files` subcommand; all allowlist files migrated to the tagged trust format (bare string backwards-compat removed)

### Fixed

- Project root discovery now detects git worktrees correctly

## [0.2.2] - 2026-02-07

### Added

- Log rotation with 10-file retention
- Allowlisted `curl` with rules for unsafe flags (data exfiltration)
- Bare `--version` / `-V` now allowed on any command

### Fixed

- AI judge subprocesses are killed on timeout instead of orphaned
- Raw stdout/stderr logged on unparseable AI judge responses

## [0.2.1] - 2026-02-07

### Added

- **Docker rules**: Allowlist for safe Docker/Compose commands, with destructive operation rules for `docker compose down --rmi`, `--remove-orphans`, etc.
- Expanded git allowlist with read-only commands (`check-ignore`, `symbolic-ref`, `show-ref`)
- Allowlisted `git-cliff`, `just release`, and `uv run python manage.py migrate`

### Fixed

- AI judge now uses gpt-5.1-codex-mini with medium reasoning effort
- git-cliff dash-prefixed options handled via flags matcher
- Removed duplicate module declarations and test execution issues

## [0.2.0] - 2026-02-05

### Added

- **Compound bash statement support**: Pipelines, lists, and other compound constructs are now parsed and evaluated as individual leaf nodes

### Fixed

- Eliminated flaky AI judge script execution tests

## [0.1.14] - 2026-02-04

### Added

- **Lenient AI judge mode**: New `--ask-ai-lenient` flag for a less strict AI evaluation threshold

### Fixed

- Increased AI judge timeout to 30s

## [0.1.13] - 2026-02-04

### Added

- **AI judge for Python scripts**: Python script executions (via interpreter invocations) are now sent to the AI judge for safety evaluation

### Fixed

- GitLab CI: use `pull_policy: always` for runner compatibility
- Hook logs no longer truncated

## [0.1.12] - 2026-02-04

### Added

- Expanded Python code extraction to cover more execution forms (`python -c`, heredocs, etc.)

### Fixed

- Consistent `longline:` prefix on all AI judge decision reasons

## [0.1.11] - 2026-02-04

### Fixed

- Tightened git/just allowlists to prevent overly broad matches
- Removed duplicate test IDs across golden test files

## [0.1.10] - 2026-02-04

### Changed

- **Middle-ground policy for ln/cp/mv/tee**: These commands now ask instead of blanket allow/deny, balancing usability with safety

### Fixed

- Bare `git` and `just` added to allowlist so `-C` flag variations still work

## [0.1.9] - 2026-02-02

### Added

- **Multi-file rule loading**: Rules config now supports a manifest format that includes multiple domain-specific YAML files, with backwards compatibility for monolithic configs
- **`files` subcommand**: Shows all loaded rule files with counts
- **Domain-split rules**: Monolithic rules file split into `git.yaml`, `filesystem.yaml`, `secrets.yaml`, `network.yaml`, `docker.yaml`, `system.yaml`, `interpreters.yaml`, etc.
- Comprehensive package installation security rules

### Fixed

- All `git rebase` commands now require ask

## [0.1.8] - 2026-02-02

### Added

- Expanded allowlist for CI/CD tooling (gh, glab, glp) with API mutation rules

### Fixed

- Secured allowlist matching with positional argument checking and path normalization to prevent bypasses

## [0.1.7] - 2026-02-02

### Added

- Django `manage.py` command safety rules (destructive management commands require ask/deny)

### Changed

- Allowlist path matching now applies subdirectory-only constraints and normalizes only path-like arguments

## [0.1.6] - 2026-02-01

### Fixed

- Handle BrokenPipe gracefully in missing config test

## [0.1.5] - 2026-02-01

### Fixed

- Module structure and rule example corrections

## [0.1.4] - 2026-02-01

### Fixed

- Non-Bash tools now get passthrough (`{}`) instead of an explicit allow decision
- Restored filter-repo replacement rule in CI

## [0.1.3] - 2026-02-01

### Added

- **GitLab CI pipeline** and README for public release
- Expanded allowlist with common safe commands (cd, sleep, just, glp, glab, git-cliff)

### Changed

- **Module refactoring**: Parser and policy converted from single files to directory modules, extracting helpers, converters, config types, matchers, and allowlist logic into focused submodules

### Fixed

- CI fixes: Docker tag for runners, rustfmt/clippy installation, cargo-husky hook disabled in CI

## [0.1.2] - 2026-01-30

### Fixed

- Changelog formatting consistency

## [0.1.1] - 2026-01-30

### Added

- **New flag matchers**: `none_of` for inverse matching and `starts_with` for combined flag prefixes
- **Security rules**: Filesystem destructive operations, git destructive operations, and package manager install rules
- **Release tooling**: Justfile with dev commands and release workflow, cargo-release and git-cliff configuration
- Version field in log entries

### Fixed

- AI judge now handles pipelines correctly and returns decision reasons

## [0.1.0] - 2026-01-28

### Added

- **Core engine**: Tree-sitter bash parser converting CST to a normalized Statement AST, policy engine with YAML rule loading and evaluation, JSONL decision logger, and CLI adapter implementing the Claude Code hook protocol
- **Rule matchers**: Command (name + flags/args globs), pipeline (stage subsequence), and redirect (operator + target glob) matchers
- **Safety rules**: 40+ default rules across 8 categories covering filesystem destruction, secrets exposure, git history rewriting, network exfiltration, and more
- **Diagnostic subcommands**: `rules` for config inspection and `check` for testing commands against the loaded ruleset, with colored table output and NO_COLOR support
- **AI judge**: Optional `--ask-ai` flag that sends ambiguous commands to an LLM for safety evaluation
- **Command substitution handling**: Embedded command substitutions (`$(...)`) detected, extracted, and evaluated against policy
- **Allowlist with rules-override**: Rules evaluate before allowlist so dangerous patterns (e.g., `cat .env`) are caught even for allowlisted commands
- `--ask-on-deny` flag to downgrade deny decisions to ask
- Explicit allow decisions emitted to bypass Claude Code's built-in permission prompts
- Git hooks via cargo-husky for fmt, clippy, and test
- Golden test framework with 307+ cases across 11 categories
- End-to-end integration tests for the binary hook protocol
