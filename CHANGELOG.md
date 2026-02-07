# Changelog

All notable changes to this project will be documented in this file.

## [0.2.2] - 2026-02-07


### Added

- add log rotation with 10-file retention
- allowlist curl and add rules for unsafe flags
- allow bare --version and -V on any command


### Changed

- update SECURITY.md with resolved items and future work


### Fixed

- kill judge subprocesses on timeout
- log raw stdout/stderr on unparseable response

## [0.2.1] - 2026-02-07


### Added

- add git read-only commands check-ignore, symbolic-ref, show-ref
- add git-cliff base command with safety rules
- add just release to safe commands
- allow uv run python manage.py migrate
- add Docker allowlist and destructive operation rules
- add docker compose down --rmi and --remove-orphans rules


### Changed

- add design for fixing duplicate test execution
- add .worktrees/ to gitignore
- remove duplicate module declarations from main.rs
- add implementation plan for duplicate test fix
- release v0.2.1


### Fixed

- use gpt-5.1-codex-mini with medium reasoning effort
- use flags matcher for git-cliff dash-prefixed options

## [0.2.0] - 2026-02-05


### Added

- add support for compound bash statements


### Changed

- update documentation for recent features
- release v0.2.0


### Fixed

- eliminate flaky AI judge script execution tests

## [0.1.14] - 2026-02-04


### Added

- add lenient AI judge mode


### Changed

- release v0.1.14


### Fixed

- increase timeout to 30s

## [0.1.13] - 2026-02-04


### Added

- send Python script executions to AI judge


### Changed

- split ai_judge.rs into module directory
- release v0.1.13


### Fixed

- use pull_policy: always for GitLab runner compatibility
- stop truncating hook logs

## [0.1.12] - 2026-02-04


### Added

- extract Python code from more execution forms


### Changed

- remove superseded design and plan files
- release v0.1.12


### Fixed

- consistent 'longline:' prefix for AI judge reasons

## [0.1.11] - 2026-02-04


### Changed

- rename allowlist-bypass golden suites
- release v0.1.11


### Fixed

- tighten git/just allowlists
- remove duplicate test IDs across golden test files

## [0.1.10] - 2026-02-04


### Changed

- middle-ground policy for ln/cp/mv/tee
- add git -C flag tests to verify rules still fire
- release v0.1.10


### Fixed

- add bare git and just to allowlist for -C flag support

## [0.1.9] - 2026-02-02


### Added

- add comprehensive package installation security rules
- expand package installation rules with explicit coverage
- add ManifestConfig type for multi-file rule loading
- add PartialRulesConfig for individual rule files
- add is_manifest detection function
- implement manifest-based multi-file rule loading
- add load_rules_with_info to track source files
- export LoadedConfig and LoadedFileInfo from policy module
- add files subcommand to show loaded rule files
- create manifest and core-allowlist.yaml
- split rules into domain files


### Changed

- add design for splitting rules and tests into domain files
- add detailed implementation plan for splitting rules
- add test for missing included file error
- verify backwards compatibility with monolithic rules file
- add integration test for files subcommand
- record baseline rule counts before splitting
- add integration test verifying manifest produces same decisions
- update CLAUDE.md with new rules structure
- split large golden test files by domain
- merge allowlist-bypass-git.yaml into git.yaml
- update allowlist-bypass-filesystem tests to expect ask for dangerous commands
- release v0.1.9


### Fixed

- require ask for ALL git rebase commands

## [0.1.8] - 2026-02-02


### Added

- expand allowlist for CI/CD tooling and add API mutation rules


### Changed

- lock allowlist path matching design after security review
- release v0.1.8


### Fixed

- secure allowlist matching with positional args and path normalization

## [0.1.7] - 2026-02-02


### Added

- add Django manage.py command safety rules


### Changed

- add allowlist path matching design exploration
- add subdirectory-only constraint and security analysis
- add constraint to only normalize path-like arguments
- release v0.1.7

## [0.1.6] - 2026-02-01


### Changed

- release v0.1.6


### Fixed

- handle BrokenPipe in missing config test

## [0.1.5] - 2026-02-01


### Changed

- update module names and test case count
- fix rule example structure and add missing modules
- release v0.1.5

## [0.1.4] - 2026-02-01


### Changed

- add release command to CLAUDE.md
- release v0.1.4


### Fixed

- restore filter-repo replacement rule in CI
- return passthrough for non-Bash tools instead of allow decision

## [0.1.3] - 2026-02-01


### Added

- add cd to allowlist for compound commands
- add GitLab CI pipeline and README for public release
- add dev tool allowlist entries for sleep, just, glp, glab, git-cliff
- expand allowlist with common safe commands


### Changed

- ignore .claude directory and remove settings.json
- add module refactoring design plan
- add module refactoring implementation plan
- convert parser to directory module
- extract parser helper functions
- extract parser convert functions
- convert policy to directory module
- extract policy config types
- extract policy matching functions
- extract policy allowlist logic
- release v0.1.3


### Fixed

- use docker tag for CI runners
- install rustfmt and clippy in CI before_script
- disable cargo-husky hook installation in CI

## [0.1.2] - 2026-01-30


### Changed

- release v0.1.2


### Fixed

- consistent changelog version format and section spacing
- add style commits to changelog and regenerate

## [0.1.1] - 2026-01-30


### Added

- add none_of flag matcher for inverse flag matching
- add starts_with prefix matching for combined flags
- add filesystem destructive operation rules
- add git destructive operation rules
- add package manager security rules
- add version field to log entries
- add justfile for dev commands and release workflow
- add cargo-release configuration
- add git-cliff configuration for changelog generation


### Changed

- add allowlist bypass security audit tests
- fix npm run/start expectations (dev tasks are allowed)
- update safe-commands expectations for new security rules
- add sed -n print lines test to ensure read-only sed is allowed
- add versioning design plan
- add versioning implementation plan
- update plan and design to reflect cargo-release hook limitations
- remove install.sh (replaced by justfile)
- add license, repository, and publish=false to Cargo.toml
- add CHANGELOG.md for v0.1.0
- release v0.1.1


### Fixed

- AI judge now handles pipelines and returns reasons
- add --no-confirm and --force flags to justfile release

## [0.1.0] - 2026-01-28


### Added

- scaffold longline project with dependencies
- add normalized AST model types and flatten function
- add hook protocol types with serialization tests
- add policy engine rule types and YAML loading
- implement tree-sitter bash parser with CST-to-model conversion
- implement JSONL decision logger
- implement policy engine rule evaluation with matchers
- implement CLI adapter with stdin/stdout hook protocol
- add default safety rules file with 40+ rules across 8 categories
- add end-to-end integration tests for binary hook protocol
- add golden test framework with initial test cases across 6 categories
- expand golden test corpus to 307 cases across 11 categories
- add cp/mv/tee/rm secrets rules and expand safe command allowlist
- add golden tests for secrets rules and new allowlist commands
- add git-commit-amend rule to catch history rewriting
- wire --ask-on-deny flag to downgrade deny decisions to ask
- add rules subcommand for config inspection
- add check subcommand for command testing
- add comfy-table and yansi deps, create output module skeleton
- implement rules table output with comfy-table
- add check table, allowlist display, NO_COLOR support, and test updates
- add install script for binary and default rules
- remove interpreters from bare allowlist, add safe patterns
- add --ask-ai CLI flag (wiring pending)
- add ai_judge module with config, trigger detection, and prompt
- wire --ask-ai flag into hook evaluation flow
- support explicit allow in HookOutput serialization
- emit explicit allow decisions to bypass CC permissions
- populate allowlist match info in PolicyResult reason
- add git hooks via cargo-husky for fmt, clippy, and test
- detect command substitutions embedded in command arguments
- flatten embedded command substitutions for policy evaluation
- add rules for find -delete, find -exec rm, xargs rm
- remove find and xargs from bare allowlist


### Changed

- add project brief and design documents for longline
- add MVP implementation plan
- final cleanup and lint fixes
- add CLAUDE.md with project guidance for Claude Code
- add rules override and secrets hardening plans
- split allowlist into always-safe and conditionally-safe groups
- update git golden tests for allowlist classification
- add golden tests for expanded build tool safe invocations
- add golden tests for non-allowlisted build tool commands
- remove superseded design doc
- add design for diagnostic and override modes
- add allowlist classification plan
- restructure CLI for subcommand support
- apply cargo fmt
- move claude permissions to settings.json and gitignore settings.local
- apply cargo fmt formatting
- add git hooks design plan
- apply cargo fmt to ai_judge and output modules
- add design plans for diagnostics, table formatting, and ai-judge
- add bypass attempt golden tests for security audit
- add command substitution golden tests
- add integration tests for explicit allow and security bypasses
- add log-derived regression and real-world find/xargs tests


### Fixed

- evaluate rules before allowlist so rules can override safe commands
- update git golden tests for rules-override-allowlist behavior
- update secrets golden tests for rules-override-allowlist behavior
- use f.pad() in Display impls to respect format width specifiers
- re-add find and xargs to bare allowlist
- do not install rules by default in install script

