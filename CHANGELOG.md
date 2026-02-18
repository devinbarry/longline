# Changelog

All notable changes to this project will be documented in this file.

## [0.5.1] - 2026-02-18


### Added

- tighten git push safety rules and add force-with-lease coverage
- add typed filter system for rules subcommand
- add load_global_config and merge_overlay_config
- load global config overlay from ~/.config/longline/longline.yaml
- add --safety-level CLI flag
- show global config in files/rules/check output


### Changed

- release v0.4.3
- add typed filter system design for longline rules
- add typed filter system implementation plan
- add integration tests for typed filter system
- release v0.4.4
- add golden tests for all gh/glab remote-write commands
- release v0.4.5
- add design for policy gap fixes (21 red TDD tests)
- integrate review feedback into policy gap fixes design
- add missing red tests for subshell redirects and uv subcommand gating
- add implementation plan for policy gap fixes (12 tasks)
- remove normalize_arg change from plan, add review analysis
- add normalize_command_name() helper for basename extraction
- add collect_descendant_substitutions() helper for parser
- add inject_redirects_into_leaves() utility for compound redirects
- release v0.5.0
- update documentation for v0.5.0 release
- rewrite changelog with human-readable release notes
- design for global machine-wide config overlay
- implementation plan for global config overlay
- rename RuleSource::Global to BuiltIn, add Global for overlay


### Fixed

- reclassify trust levels for git and cli-tool allowlists
- correct uv pip test to regression guard, update design doc counts
- reject unknown fields in RulesConfig for fail-closed config parsing
- add time wrapper and basename normalization for absolute paths and pipelines
- add redirect rules for stdin secret exposure and system path writes
- recurse into string and concatenation nodes to find embedded command substitutions
- collect pipeline rules from command substitutions in embedded_substitutions
- extract inner commands from find -exec and xargs for policy evaluation
- propagate redirects from compound statements to inner SimpleCommand leaves
- add subcommand-based wrapper support and uv run delegation
- propagate substitutions from bare assignments and compound redirect targets

## [0.4.2] - 2026-02-14


### Added

- send Python script executions to AI judge
- add lenient AI judge mode
- add support for compound bash statements
- add git read-only commands check-ignore, symbolic-ref, show-ref
- add git-cliff base command with safety rules
- add just release to safe commands
- allow uv run python manage.py migrate
- add Docker allowlist and destructive operation rules
- add docker compose down --rmi and --remove-orphans rules
- add log rotation with 10-file retention
- allowlist curl and add rules for unsafe flags
- allow bare --version and -V on any command
- add ProjectConfig type for per-project overrides
- add project root discovery via .git or .claude directory
- add project config loading from .claude/longline.yaml
- add merge function for project config into global config
- wire per-project config into hook mode
- reject unknown fields in project config with exit code 2
- add trust level tiered allowlists
- show trust tier breakdown in files subcommand
- add embedded_rules module with compile-time rule embedding
- add load_embedded_rules() for loading rules from compiled-in defaults
- fall back to embedded rules when no config file found
- add 'longline init' subcommand to extract embedded rules
- embed default rules into binary and rename manifest to rules
- add --dir global CLI flag for project config discovery
- add RuleSource enum to track global vs project origin
- tag merged project rules and allowlists with RuleSource::Project
- wire project config discovery into rules, check, and files subcommands
- add SOURCE column with cyan color for project items in table output
- show project config path banner in rules and check output
- add shasum, network diagnostics, ip/arp/route read-only, and longline to core allowlist
- add longline-init ask rule to system rules
- add brew read-only subcommands to package-managers allowlist
- add brew mutation rules (upgrade/uninstall/update/tap/services/link/cleanup)
- scaffold wrappers module with types and wrapper table
- implement unwrap_transparent with unit tests
- implement extract_inner_commands with chaining and depth limit
- add wrapper commands to core allowlist
- integrate wrapper unwrapping into policy evaluation
- add npx allowlist for common JS dev tools
- add pnpm allowlist for direct tool invocations
- add bunx and yarn dlx/exec allowlists for JS dev tools
- add pnpm exec and yarn exec allowlists for safe dev tools


### Changed

- split ai_judge.rs into module directory
- release v0.1.13
- release v0.1.14
- update documentation for recent features
- release v0.2.0
- add design for fixing duplicate test execution
- add .worktrees/ to gitignore
- remove duplicate module declarations from main.rs
- add implementation plan for duplicate test fix
- release v0.2.1
- update SECURITY.md with resolved items and future work
- release v0.2.2
- add per-project config design
- add per-project config implementation plan
- add integration tests for per-project config
- clarify merge order in merge_project_config doc comment
- migrate all allowlist files to tagged trust format
- remove bare string backwards-compat from AllowlistEntry
- add integration tests for trust_level
- add implementation plan for trust_level tiered allowlists
- release v0.3.0
- add design for embedded rules and manifest rename
- add implementation plan for embedded rules
- rename manifest to rules manifest throughout codebase
- update CLAUDE.md and justfile for rules.yaml rename and embedded defaults
- release v0.3.1
- add design and implementation plan for project config discovery
- add safe command allowlist additions design
- add allowlist additions and transparent wrappers design docs
- add safe commands implementation plan
- add golden tests for network diagnostic commands
- add golden tests for shasum and longline commands
- add golden tests for brew read-only and mutation commands
- add transparent wrappers implementation plan
- add golden tests for transparent wrapper commands
- release v0.4.0
- clean up changelog with contextual descriptions
- add JS dev tool allowlisting design
- add JS dev tool allowlisting implementation plan
- remove blanket npx-run rule
- add command-wrapper bypass tests for all runners
- rename safe-commands-node.yaml and duplicate for split
- split node golden tests into safe and dangerous files
- release v0.4.1
- add design doc for documentation cleanup and maintenance
- add implementation plan for documentation cleanup
- rewrite README for embedded defaults and fix manifest.yaml references
- rewrite SECURITY.md to focus on security model and current limitations
- update CLAUDE.md test count, fix CI docs filter, remove designs dir
- release v0.4.2


### Fixed

- use pull_policy: always for GitLab runner compatibility
- stop truncating hook logs
- increase timeout to 30s
- eliminate flaky AI judge script execution tests
- use gpt-5.1-codex-mini with medium reasoning effort
- use flags matcher for git-cliff dash-prefixed options
- kill judge subprocesses on timeout
- log raw stdout/stderr on unparseable response
- detect git worktrees in project root discovery
- address code review findings for trust_level feature
- error on TTY stdin instead of silently blocking in check subcommand
- remove blanket pnpm exec and yarn exec allowlist entries
- remove blanket poetry run, pdm run, and rye run allowlist entries
- remove command-wrapper tools from allowlists
- add ci group and skip merge commits in git-cliff config
- correct golden test count to 1500+ in README
- remove residual 'manifest' terminology from README
- auto-push commits and tags in release recipe

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
- use if-not-present pull policy to avoid Docker Hub timeouts
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
- add --allow-dirty to cargo publish
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
- add GitHub Actions release workflow and tag sync
- add workflow_dispatch trigger for manual testing
- skip publish steps on manual workflow_dispatch
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

