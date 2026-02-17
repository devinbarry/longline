# Changelog

All notable changes to this project will be documented in this file.

## [0.5.0] - 2026-02-17

Closes 21 policy gaps found via red TDD tests. Significantly improves detection of dangerous commands hidden inside substitutions, redirects, absolute paths, compound statements, and wrapper commands.

### Added

- Basename normalization: `/usr/bin/rm -rf /` now matches rules for `rm` and pipeline rules match regardless of path prefix
- `time` transparent wrapper support: commands wrapped in `time` are now evaluated like other wrappers (env, timeout, nice, etc.)
- `uv run` subcommand-based wrapper: `uv run pytest` is unwrapped for policy; `uv pip install` is not
- `find -exec` and `xargs` inner command extraction: `find . -exec rm {} \;` and `xargs rm` are now evaluated against rules instead of relying on the base command's allowlist status
- Redirect rules for stdin secret exposure (`< ~/.ssh/id_rsa`, `< .env`) and system path writes (`> /etc/hosts`, `> /dev/sda`)
- Compound statement redirect propagation: redirects on `{ ...; } > target` and `( ... ) > target` are now applied to inner leaf commands
- Command substitution detection in string nodes, concatenation nodes, bare assignments (`FOO=$(rm -rf /)`), and redirect targets (`> $(cat .env)`)
- Strict config validation: unknown fields in `rules.yaml` now cause exit code 2 instead of being silently ignored

### Changed

- 26 new red_policy_issues regression tests covering all gaps
- Golden test corpus expanded to 1600+ cases

## [0.4.5] - 2026-02-16

### Fixed

- Reclassify trust levels for git and cli-tool allowlists so `gh`/`glab` remote-write commands require correct trust tier

## [0.4.4] - 2026-02-16

### Added

- Typed filter system for `rules` subcommand: filter by `decision:deny`, `level:critical`, `source:project`, `trust:full`

## [0.4.3] - 2026-02-16

### Fixed

- Tighten git push safety rules: `git push --force`, `--force-with-lease`, and variants now correctly trigger `ask`

## [0.4.2] - 2026-02-14

Documentation overhaul release.

### Changed

- Rewrote README for embedded defaults, removed stale manifest.yaml references
- Rewrote SECURITY.md to focus on security model and known limitations
- Auto-push commits and tags in `just release` recipe

## [0.4.1] - 2026-02-13

### Added

- Allowlists for JS dev tool runners: npx, pnpm, pnpm exec, bunx, yarn dlx, yarn exec -- each with an explicit list of known-safe tools (test runners, linters, formatters, build tools)

### Fixed

- Remove blanket `pnpm exec`, `yarn exec`, `poetry run`, `pdm run`, and `rye run` allowlist entries that allowed arbitrary command execution
- Remove command-wrapper tools (npx, bunx, etc.) from bare allowlist -- only specific tool invocations are allowed

## [0.4.0] - 2026-02-11

Three features: project config discovery in subcommands, safe command allowlist expansion, and transparent wrapper support.

### Added

- `--dir` CLI flag for project config discovery in `rules`, `check`, and `files` subcommands
- SOURCE column in table output showing global vs project origin, with project config path banner
- Allowlist additions: shasum, network diagnostics (ping, dig, nslookup, traceroute), ip/arp/route read-only, longline, brew read-only subcommands
- Brew mutation rules (upgrade/uninstall/update/tap/services/link/cleanup)
- Transparent wrapper unwrapping: `env`, `timeout`, `nice`, `nohup`, `strace` are parsed through to evaluate the inner command, with chaining support and depth limit

## [0.3.1] - 2026-02-09

### Added

- Rules are now embedded into the binary at compile time -- no external files needed
- `longline init` subcommand to extract embedded rules to `~/.config/longline/` for customization
- Automatic fallback: `--config` > `~/.config/longline/rules.yaml` > embedded defaults

### Fixed

- `check` subcommand now errors on TTY stdin instead of silently blocking

## [0.3.0] - 2026-02-08

Two features: per-project config overrides and trust-level tiered allowlists.

### Added

- Per-project config via `.claude/longline.yaml`: override safety level, disable rules, add project-specific allowlists and rules
- Project root discovery via `.git` or `.claude` directory (including git worktrees)
- Trust-level tiered allowlists: commands tagged `minimal`, `standard`, or `full` -- project config selects threshold
- `files` subcommand shows trust tier breakdown

### Changed

- All allowlist entries migrated to tagged trust format (breaking: bare string format removed)

## [0.2.2] - 2026-02-07

### Added

- Log rotation with 10-file retention
- Allowlist curl with rules for unsafe flags (`-o`, `--upload-file`, etc.)
- `--version` and `-V` flags auto-allowed on any command

### Fixed

- Kill AI judge subprocesses on timeout instead of leaking them
- Log raw stdout/stderr when AI judge response is unparseable

## [0.2.1] - 2026-02-07

### Added

- Git read-only commands: check-ignore, symbolic-ref, show-ref
- Docker allowlist and destructive operation rules (docker rm, rmi, system prune, compose down)
- Allowlist entries for git-cliff, just release, uv run python manage.py migrate

### Fixed

- Switch AI judge to gpt-5.1-codex-mini with medium reasoning effort
- git-cliff dash-prefixed options now use flags matcher instead of args

## [0.2.0] - 2026-02-05

### Added

- Compound bash statement support: for/while loops, if/else, case statements, compound commands `{ ...; }`, function definitions are now parsed and each inner command is evaluated

### Fixed

- Eliminate flaky AI judge script execution tests

## [0.1.14] - 2026-02-04

### Added

- Lenient AI judge mode (`--ask-ai-lenient`/`--lenient`): prefers allow for normal development tasks

### Fixed

- Increase AI judge timeout to 30s

## [0.1.13] - 2026-02-04

### Added

- AI judge now evaluates Python script file executions (not just inline `-c` code)

### Fixed

- Stop truncating hook audit logs
- Use `pull_policy: always` for GitLab CI runner compatibility

## [0.1.12] - 2026-02-04

### Added

- Extract Python code from additional execution forms (heredocs, here-strings, stdin pipelines, Django shell)

### Fixed

- Consistent `longline:` prefix on all AI judge decision reasons

## [0.1.11] - 2026-02-04

### Fixed

- Tighten git/just allowlists to prevent overly permissive matching
- Remove duplicate test IDs across golden test files

## [0.1.10] - 2026-02-04

### Changed

- Middle-ground policy for ln/cp/mv/tee: allow base commands, deny dangerous argument patterns

### Fixed

- Add bare `git` and `just` to allowlist so `-C` flag commands are not blocked by the base command

## [0.1.9] - 2026-02-02

### Added

- Multi-file rule loading: rules split into domain-specific YAML files (git, filesystem, secrets, network, docker, etc.) referenced by `rules.yaml`
- `files` subcommand to show loaded rule files and counts
- Package installation security rules (pip install, npm install, cargo install, etc.)

### Fixed

- All git rebase commands now require `ask` confirmation

## [0.1.8] - 2026-02-02

### Added

- Expanded allowlist for CI/CD tooling (gh, glab) with API mutation rules

### Fixed

- Secure allowlist matching: positional argument checking and path normalization to prevent path traversal bypasses

## [0.1.7] - 2026-02-02

### Added

- Django manage.py command safety rules (migrate, flush, loaddata, dbshell trigger ask; safe commands allowed)

## [0.1.6] - 2026-02-01

### Fixed

- Handle BrokenPipe in missing config integration test

## [0.1.5] - 2026-02-01

### Added

- GitHub Actions release workflow with tag sync

## [0.1.4] - 2026-02-01

### Fixed

- Return passthrough (`{}`) for non-Bash tools instead of explicit allow decision
- Restore filter-repo replacement rule in CI

## [0.1.3] - 2026-02-01

### Added

- GitLab CI pipeline
- Expanded allowlist: cd, sleep, just, glp, glab, git-cliff, and other common safe commands

### Changed

- Refactored parser and policy into directory modules with extracted submodules

## [0.1.2] - 2026-01-30

### Fixed

- Consistent changelog version format and section spacing

## [0.1.1] - 2026-01-30

### Added

- `none_of` flag matcher for inverse matching (e.g., allow unzip only without `-o`)
- `starts_with` prefix matching for combined flags (e.g., `-inplace` matching `-i`)
- Filesystem, git, and package manager destructive operation rules
- Versioning infrastructure: justfile, cargo-release, git-cliff

### Fixed

- AI judge now handles pipelines and returns structured reasons

## [0.1.0] - 2026-01-28

Initial release.

### Added

- Tree-sitter bash parser: simple commands, pipelines, lists, subshells, command substitutions
- Policy engine with YAML rules: command, pipeline, and redirect matchers
- Allowlist system with rules-override-allowlist ordering
- Hook protocol adapter (JSON stdin/stdout) for Claude Code PreToolUse
- JSONL audit logging
- `rules` and `check` subcommands with table output (comfy-table, NO_COLOR support)
- `--ask-on-deny` flag to downgrade deny to ask
- `--ask-ai` flag for AI evaluation of inline interpreter code
- 40+ default safety rules across 8 categories
- 307 golden test cases across 11 categories
- Command substitution detection in arguments
- Rules for find -delete, find -exec rm, xargs rm
- Secrets rules for .env, SSH keys, AWS credentials, kubeconfig

