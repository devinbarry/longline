# Changelog

All notable changes to this project will be documented in this file.

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


### Fixed

- AI judge now handles pipelines and returns reasons
- add --no-confirm and --force flags to justfile release
## [v0.1.0] - 2026-01-28


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
- final cleanup and lint fixes
- add CLAUDE.md with project guidance for Claude Code
- split allowlist into always-safe and conditionally-safe groups
- update git golden tests for allowlist classification
- add golden tests for expanded build tool safe invocations
- add golden tests for non-allowlisted build tool commands
- remove superseded design doc
- add design for diagnostic and override modes
- restructure CLI for subcommand support
- move claude permissions to settings.json and gitignore settings.local
- add git hooks design plan
- add longline hook to Claude Code settings
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
