//! Matching logic for policy rules.

use crate::parser::{self, Arg, SimpleCommand, Statement};
use std::borrow::Cow;

use super::config::{
    EnvMatcher, EnvValueClass, FlagsMatcher, GitConfigMatcher, GitConfigSource, Matcher,
    PipelineMatcher, RedirectMatcher, StringOrList,
};
use super::git_invocation::{GitConfigValue, GitInvocation, SubcommandResolution};
use super::value_safety::{is_safe_program_value, SafeProgramClass};

/// Extract basename from a command path for matching.
/// "/usr/bin/rm" -> "rm", "./script.sh" -> "script.sh", "rm" -> "rm"
pub fn normalize_command_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// The leading global value-flags (each consuming a following value token)
/// for a command family, keyed by basename. Used to skip `--flag VALUE`
/// global-option pairs when resolving the effective subcommand.
fn global_value_flags_for(cmd_name: &str, first_arg: Option<&str>) -> &'static [&'static str] {
    match cmd_name {
        "codex" => super::allowlist::CODEX_GLOBAL_VALUE_FLAGS,
        _ => crate::parser::wrappers::value_flags_for(cmd_name, first_arg),
    }
}

/// Resolve a command's *effective subcommand* — the first positional argv
/// token after skipping leading global value-flag pairs and boolean global
/// flags. Basename-normalizes the command name before family detection (so
/// `/usr/bin/git -C x checkout` resolves to `checkout`).
///
/// Returns [`SubcommandResolution::Ambiguous`] (⇒ match any pin) when a
/// recognized global value-flag's value token is an `UnsafeString`
/// (`git -C "$REPO" …`) or is dangling. Returns
/// [`SubcommandResolution::Absent`] (⇒ match no pin) when there is no
/// positional token at all.
///
/// Git delegates to [`GitInvocation`], the canonical structural scan shared
/// with allowlist matching and subcommand-boundary consumers. Other command
/// families retain their generic value-flag scan.
pub fn resolve_subcommand(cmd: &SimpleCommand) -> SubcommandResolution {
    let Some(name) = cmd.name.as_deref() else {
        return SubcommandResolution::Absent;
    };
    let cmd_name = normalize_command_name(name);
    if cmd_name == "git" {
        return GitInvocation::new(&cmd.argv).subcommand;
    }
    let first_arg = cmd.argv.first().map(|a| a.text.as_str());
    let value_flags = global_value_flags_for(cmd_name, first_arg);

    let mut i = 0;
    while i < cmd.argv.len() {
        let arg = &cmd.argv[i];

        // `--` ends option processing; the next token (if any) is the
        // first positional / subcommand.
        if arg.text == "--" {
            return match cmd.argv.get(i + 1) {
                Some(a) => SubcommandResolution::Resolved(a.text.clone()),
                None => SubcommandResolution::Absent,
            };
        }

        if value_flags.contains(&arg.text.as_str()) {
            match cmd.argv.get(i + 1) {
                // Unknowable value → cannot locate the subcommand.
                Some(v) if matches!(v.meta, crate::parser::ArgMeta::UnsafeString) => {
                    return SubcommandResolution::Ambiguous;
                }
                Some(_) => {
                    i += 2;
                    continue;
                }
                // Dangling value-flag at end of argv.
                None => return SubcommandResolution::Ambiguous,
            }
        }

        // Other leading boolean global flag (e.g. `git --paginate`): skip.
        if arg.text.starts_with('-') {
            i += 1;
            continue;
        }

        // First non-flag positional = the effective subcommand.
        return SubcommandResolution::Resolved(arg.text.clone());
    }

    SubcommandResolution::Absent
}

/// Index of the effective subcommand in `cmd.argv` — the first token after any
/// leading global value-flag pairs (git `-C <path>` / `-c <k=v>` / `--git-dir
/// <path>` …), boolean global flags (`--paginate`), and an optional `--`.
/// Returns 0 when `argv[0]` is already a positional (no leading globals).
///
/// CLAMPED to `cmd.argv.len()`. A recognized global value-flag as the LAST
/// token advances the cursor past the end (the `i += 2` is unconditional), so
/// without the clamp a dangling `git -C` would yield an out-of-range index — an
/// out-of-bounds slice in `argv_from_subcommand`, and an `argv.len() - index`
/// underflow at the `min_args` call site (debug panic). Generic across command
/// families: Git delegates to [`GitInvocation`], while codex and wrappers use
/// `global_value_flags_for`. Shared by `argv_from_subcommand` (slice) and the
/// `min_args` value-presence count, so both see argv the same way.
fn subcommand_start_index(cmd: &SimpleCommand) -> usize {
    let Some(name) = cmd.name.as_deref() else {
        return 0;
    };
    let cmd_name = normalize_command_name(name);
    if cmd_name == "git" {
        return GitInvocation::new(&cmd.argv).subcommand_index;
    }
    let first_arg = cmd.argv.first().map(|a| a.text.as_str());
    let value_flags = global_value_flags_for(cmd_name, first_arg);

    let mut i = 0;
    while i < cmd.argv.len() {
        let t = &cmd.argv[i].text;
        if t == "--" {
            i += 1; // end of options; the subcommand follows
            break;
        }
        if value_flags.contains(&t.as_str()) {
            i += 2; // skip the flag and its value token (unconditionally)
            continue;
        }
        if t.starts_with('-') {
            i += 1; // boolean global flag (e.g. `git --paginate`)
            continue;
        }
        break; // first positional = the effective subcommand
    }
    i.min(cmd.argv.len())
}

/// For a **subcommand-pinned** rule, flag matching must ignore the command's
/// leading global value-flag pairs (git `-C <path>` / `-c <k=v>` / …) and
/// boolean global flags — otherwise the global `-C` in the ubiquitous
/// `git -C <path> branch …` is wrongly counted as the branch force-copy `-C`
/// flag. Returns `cmd.argv` from the effective subcommand onward.
///
/// Strips global value-flag pairs UNCONDITIONALLY (including `UnsafeString`
/// values like `git -C "$REPO" …`) — unlike the allowlist's `effective_argv`,
/// which retains them for fail-closed safety. That retention is correct for
/// allowlist matching but wrong here: a global flag's value is never the
/// subcommand's own flag, so for flag scanning we always skip it.
fn argv_from_subcommand<'a>(cmd: &'a SimpleCommand) -> Cow<'a, [Arg]> {
    let start = subcommand_start_index(cmd);
    if start == 0 {
        Cow::Borrowed(&cmd.argv)
    } else {
        Cow::Owned(cmd.argv[start..].to_vec())
    }
}

fn arg_matches_flag(arg: &str, flag: &str) -> bool {
    if arg == flag {
        return true;
    }

    // Support long flags with inline values, e.g. --output=FILE
    if flag.starts_with("--") {
        let with_value_prefix = format!("{flag}=");
        return arg.starts_with(&with_value_prefix);
    }

    // Support combined short flags, e.g. -xvf contains -x, -v, -f
    // This intentionally treats any single-letter short flag as present if its
    // letter appears anywhere in a single-dash token.
    if flag.starts_with('-') && !flag.starts_with("--") && flag.len() == 2 {
        let Some(needle) = flag.chars().nth(1) else {
            return false;
        };
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 2 {
            return arg[1..].chars().any(|c| c == needle);
        }
    }

    false
}

/// Check if a FlagsMatcher's constraints are satisfied by the given argv.
/// Returns true if all active constraints pass. Empty constraint fields are skipped.
fn flags_match(flags_matcher: &FlagsMatcher, argv: &[Arg]) -> bool {
    // any_of: at least one of these flags must be present
    if !flags_matcher.any_of.is_empty() {
        let has_any = flags_matcher
            .any_of
            .iter()
            .any(|f| argv.iter().any(|a| arg_matches_flag(a.as_ref(), f)));
        if !has_any {
            return false;
        }
    }
    // all_of: all of these flags must be present
    if !flags_matcher.all_of.is_empty() {
        let has_all = flags_matcher
            .all_of
            .iter()
            .all(|f| argv.iter().any(|a| arg_matches_flag(a.as_ref(), f)));
        if !has_all {
            return false;
        }
    }
    // none_of: none of these flags may be present
    if !flags_matcher.none_of.is_empty() {
        let has_any_excluded = flags_matcher
            .none_of
            .iter()
            .any(|f| argv.iter().any(|a| arg_matches_flag(a.as_ref(), f)));
        if has_any_excluded {
            return false;
        }
    }
    // starts_with: at least one arg must start with one of these prefixes
    if !flags_matcher.starts_with.is_empty() {
        let has_prefix = flags_matcher
            .starts_with
            .iter()
            .any(|prefix| argv.iter().any(|a| a.as_ref().starts_with(prefix.as_str())));
        if !has_prefix {
            return false;
        }
    }
    true
}

fn env_name_matches(pattern: &str, name: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        glob_match::glob_match(&pattern.to_lowercase(), &name.to_lowercase())
    } else {
        glob_match::glob_match(pattern, name)
    }
}

fn safe_program_class(value_class: EnvValueClass) -> SafeProgramClass {
    match value_class {
        EnvValueClass::ShellNoop => SafeProgramClass::ShellNoop,
    }
}

/// Check whether at least one matched env-var assignment remains dangerous
/// after evaluating exceptions against that same assignment.
fn env_matches(env_matcher: &EnvMatcher, assignments: &[crate::parser::Assignment]) -> bool {
    if env_matcher.any_of.is_empty() {
        return true;
    }

    assignments.iter().any(|assignment| {
        let is_candidate = env_matcher.any_of.iter().any(|pattern| {
            env_name_matches(pattern, &assignment.name, env_matcher.case_insensitive)
        });
        if !is_candidate {
            return false;
        }

        let is_exempt = env_matcher.except.iter().any(|exception| {
            exception.names.iter().any(|pattern| {
                env_name_matches(pattern, &assignment.name, exception.name_case_insensitive)
            }) && is_safe_program_value(
                safe_program_class(exception.value_class),
                &assignment.value,
                assignment.value_meta,
            )
        });

        !is_exempt
    })
}

fn git_config_matches(git_config: &GitConfigMatcher, cmd: &SimpleCommand) -> bool {
    let Some(command_name) = cmd.name.as_deref() else {
        return false;
    };
    if !git_config
        .command
        .matches(normalize_command_name(command_name))
    {
        return false;
    }

    match git_config.source {
        GitConfigSource::CliC => GitInvocation::new(&cmd.argv).globals.iter().any(|global| {
            let Some(config_override) = global.config_override() else {
                return false;
            };
            let Some(key) = config_override.key.as_deref() else {
                return false;
            };
            let key_matches = git_config.keys.iter().any(|candidate| {
                if git_config.key_case_insensitive {
                    candidate.eq_ignore_ascii_case(key)
                } else {
                    candidate == key
                }
            });
            if !key_matches {
                return false;
            }

            let is_exempt = match config_override.value {
                GitConfigValue::Explicit(value) => is_safe_program_value(
                    safe_program_class(git_config.except_value_class),
                    value.as_ref(),
                    config_override.value_meta,
                ),
                GitConfigValue::ImplicitEmpty | GitConfigValue::Unknown => false,
            };
            !is_exempt
        }),
    }
}

/// Check if a rule's matcher matches a given SimpleCommand.
/// Pipeline matchers are handled separately in `evaluate` and are skipped here.
pub fn matches_rule(matcher: &Matcher, cmd: &SimpleCommand) -> bool {
    match matcher {
        Matcher::GitConfig { git_config } => git_config_matches(git_config, cmd),
        Matcher::Command {
            command,
            flags,
            args,
            env,
        } => {
            let cmd_name = match &cmd.name {
                Some(n) => n.as_str(),
                None => return false,
            };
            if !command.matches(normalize_command_name(cmd_name)) {
                return false;
            }
            // A rule with a `subcommand` pin matches its `flags` against the
            // argv from the effective subcommand onward — so the command's
            // leading global value-flags (`git -C <path>`) are NOT counted as
            // the subcommand's flags. This keeps safe `git -C <path> branch …`
            // / `… switch …` out of the force gates (the global `-C` must not
            // read as the branch/switch force-create `-C`). Non-pinned rules
            // keep raw-argv flag matching (the `-c` RCE deny rules need it).
            let has_subcommand_pin = args.as_ref().is_some_and(|a| !a.subcommand.is_empty());
            if let Some(ref flags_matcher) = flags {
                let flag_argv = if has_subcommand_pin {
                    argv_from_subcommand(cmd)
                } else {
                    Cow::Borrowed(cmd.argv.as_slice())
                };
                if !flags_match(flags_matcher, &flag_argv) {
                    return false;
                }
            }
            // Check args with glob matching
            if let Some(args_matcher) = args {
                if let Some(min) = args_matcher.min_args {
                    // Count argv from the EFFECTIVE subcommand onward, so leading
                    // git globals (`git -C <path> config <key>`, `--git-dir=…`)
                    // don't inflate the read-vs-write count and over-deny bare
                    // config READS. `subcommand_start_index` is clamped, and
                    // `saturating_sub` is belt-and-suspenders: this check runs
                    // before the `all_of:["config"]` constraint below, so a bare
                    // `git -C` (dangling value-flag) reaches here with start ==
                    // argv.len().
                    let effective_len = cmd.argv.len().saturating_sub(subcommand_start_index(cmd));
                    if effective_len < min {
                        return false;
                    }
                }
                // Positive subcommand pin: the effective subcommand must be one
                // of the listed names.
                if !args_matcher.subcommand.is_empty() {
                    match resolve_subcommand(cmd) {
                        SubcommandResolution::Resolved(sub) => {
                            let sub_cmp = if args_matcher.case_insensitive {
                                sub.to_lowercase()
                            } else {
                                sub
                            };
                            let matched = args_matcher.subcommand.iter().any(|p| {
                                if args_matcher.case_insensitive {
                                    p.to_lowercase() == sub_cmp
                                } else {
                                    p == &sub_cmp
                                }
                            });
                            if !matched {
                                return false;
                            }
                        }
                        // Ambiguous ($VAR global, e.g. `git -C "$REPO" …`):
                        // gate-biased over-ask — match any pin, but ONLY when
                        // the rule has another discriminator that also matched
                        // (a `flags` constraint, already checked above, or an
                        // `args` any_of/all_of/none_of checked below). A rule
                        // whose ONLY constraint is the subcommand pin (e.g.
                        // `git-rebase`) must NOT fire on an unresolvable
                        // subcommand: doing so would attach a destructive
                        // reason to a safe `git -C "$REPO" status`. Such
                        // commands still ask via the normal not-allowlisted
                        // path, with a clear message.
                        SubcommandResolution::Ambiguous => {
                            let has_other_discriminator = flags.is_some()
                                || !args_matcher.any_of.is_empty()
                                || !args_matcher.all_of.is_empty()
                                || !args_matcher.none_of.is_empty();
                            if !has_other_discriminator {
                                return false;
                            }
                        }
                        // No subcommand at all (`git --version`) → nothing to gate.
                        SubcommandResolution::Absent => return false,
                    }
                }
                let arg_match = |pattern: &str, arg: &str| -> bool {
                    if args_matcher.case_insensitive {
                        glob_match::glob_match(&pattern.to_lowercase(), &arg.to_lowercase())
                    } else {
                        glob_match::glob_match(pattern, arg)
                    }
                };
                if !args_matcher.any_of.is_empty() {
                    let has_any = args_matcher
                        .any_of
                        .iter()
                        .any(|pattern| cmd.argv.iter().any(|a| arg_match(pattern, a.as_ref())));
                    if !has_any {
                        return false;
                    }
                }
                if !args_matcher.all_of.is_empty() {
                    let has_all = args_matcher
                        .all_of
                        .iter()
                        .all(|pattern| cmd.argv.iter().any(|a| arg_match(pattern, a.as_ref())));
                    if !has_all {
                        return false;
                    }
                }
                if !args_matcher.none_of.is_empty() {
                    let has_excluded = args_matcher
                        .none_of
                        .iter()
                        .any(|pattern| cmd.argv.iter().any(|a| arg_match(pattern, a.as_ref())));
                    if has_excluded {
                        return false;
                    }
                }
                if !args_matcher.argv_first_not.is_empty() {
                    if let Some(first) = cmd.argv.first() {
                        // Literal exact-match against argv[0] only (the
                        // git subcommand position).
                        let first_text = if args_matcher.case_insensitive {
                            first.text.to_lowercase()
                        } else {
                            first.text.clone()
                        };
                        let excluded = args_matcher.argv_first_not.iter().any(|p| {
                            if args_matcher.case_insensitive {
                                p.to_lowercase() == first_text
                            } else {
                                p == &first_text
                            }
                        });
                        if excluded {
                            return false;
                        }
                    }
                }
            }
            if let Some(env_matcher) = env {
                if !env_matches(env_matcher, &cmd.assignments) {
                    return false;
                }
            }
            true
        }
        Matcher::Redirect { redirect } => matches_redirect(redirect, cmd),
        Matcher::Pipeline { .. } => {
            // Pipeline matching is handled at the statement level in evaluate()
            false
        }
    }
}

/// Check if a pipeline matcher's stages appear as a subsequence in the pipeline's stages.
pub fn matches_pipeline(matcher: &PipelineMatcher, pipe: &parser::Pipeline) -> bool {
    if matcher.stages.is_empty() {
        return false;
    }

    let mut matcher_idx = 0;
    for stage in &pipe.stages {
        if matcher_idx >= matcher.stages.len() {
            break;
        }
        if let Statement::SimpleCommand(cmd) = stage {
            if let Some(ref name) = cmd.name {
                let basename = normalize_command_name(name);
                if matcher.stages[matcher_idx].command.matches(basename)
                    && matcher.stages[matcher_idx]
                        .flags
                        .as_ref()
                        .is_none_or(|f| flags_match(f, &cmd.argv))
                {
                    matcher_idx += 1;
                } else if let Some(inner) = crate::parser::wrappers::unwrap_transparent(cmd) {
                    if let Some(ref inner_name) = inner.name {
                        let inner_basename = normalize_command_name(inner_name);
                        if matcher.stages[matcher_idx].command.matches(inner_basename)
                            && matcher.stages[matcher_idx]
                                .flags
                                .as_ref()
                                .is_none_or(|f| flags_match(f, &inner.argv))
                        {
                            matcher_idx += 1;
                        }
                    }
                }
            }
        }
    }
    matcher_idx == matcher.stages.len()
}

/// Check if any of the command's redirects match the redirect matcher.
pub fn matches_redirect(redirect_matcher: &RedirectMatcher, cmd: &SimpleCommand) -> bool {
    cmd.redirects.iter().any(|redir| {
        // Check op if specified
        let op_matches = match &redirect_matcher.op {
            Some(op_matcher) => op_matcher.matches(&redir.op.to_string()),
            None => true,
        };
        // Check target with glob matching if specified
        let target_matches = match &redirect_matcher.target {
            Some(target_matcher) => match target_matcher {
                StringOrList::Single(pattern) => glob_match::glob_match(pattern, &redir.target),
                StringOrList::List { any_of } => any_of
                    .iter()
                    .any(|p| glob_match::glob_match(p, &redir.target)),
            },
            None => true,
        };
        op_matches && target_matches
    })
}

#[cfg(test)]
mod tests {
    use super::arg_matches_flag;
    use super::env_matches;
    use super::matches_pipeline;
    use super::{matches_rule, resolve_subcommand, SubcommandResolution};
    use crate::parser::{Arg, ArgMeta, Assignment};
    use crate::policy::config::{
        ArgsMatcher, EnvException, EnvMatcher, EnvValueClass, FlagsMatcher, GitConfigMatcher,
        GitConfigSource, Matcher, PipelineMatcher, StageMatcher, StringOrList,
    };

    fn parse_cmd(s: &str) -> crate::parser::SimpleCommand {
        match crate::parser::parse(s).unwrap() {
            crate::parser::Statement::SimpleCommand(c) => c,
            other => panic!("expected SimpleCommand, got {other:?}"),
        }
    }

    fn resolved(s: &str) -> SubcommandResolution {
        SubcommandResolution::Resolved(s.to_string())
    }

    fn command_matcher(flags: Option<FlagsMatcher>, args: ArgsMatcher) -> Matcher {
        Matcher::Command {
            command: StringOrList::Single("git".to_string()),
            flags,
            args: Some(args),
            env: None,
        }
    }

    fn args_matcher(subcommand: &[&str]) -> ArgsMatcher {
        ArgsMatcher {
            any_of: vec![],
            all_of: vec![],
            none_of: vec![],
            argv_first_not: vec![],
            subcommand: subcommand
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            case_insensitive: false,
            min_args: None,
        }
    }

    fn editor_env_matcher() -> EnvMatcher {
        EnvMatcher {
            any_of: [
                "GIT_SSH_COMMAND",
                "GIT_EDITOR",
                "GIT_SEQUENCE_EDITOR",
                "EDITOR",
                "VISUAL",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            case_insensitive: true,
            except: vec![EnvException {
                names: ["GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "EDITOR", "VISUAL"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                name_case_insensitive: false,
                value_class: EnvValueClass::ShellNoop,
            }],
        }
    }

    fn editor_git_config_matcher() -> Matcher {
        Matcher::GitConfig {
            git_config: GitConfigMatcher {
                command: StringOrList::Single("git".to_string()),
                source: GitConfigSource::CliC,
                keys: vec!["core.editor".to_string(), "sequence.editor".to_string()],
                key_case_insensitive: true,
                except_value_class: EnvValueClass::ShellNoop,
            },
        }
    }

    fn cmd_with_config_operand(text: &str, meta: ArgMeta) -> crate::parser::SimpleCommand {
        crate::parser::SimpleCommand {
            name: Some("git".to_string()),
            argv: vec![
                Arg::plain("-c"),
                Arg {
                    text: text.to_string(),
                    meta,
                },
                Arg::plain("status"),
            ],
            assignments: vec![],
            redirects: vec![],
            embedded_substitutions: vec![],
        }
    }

    #[test]
    fn git_config_matcher_exempts_only_exact_explicit_static_shell_noop() {
        let matcher = editor_git_config_matcher();
        for meta in [ArgMeta::PlainWord, ArgMeta::RawString, ArgMeta::SafeString] {
            assert!(!matches_rule(
                &matcher,
                &cmd_with_config_operand("core.editor=true", meta)
            ));
        }

        assert!(matches_rule(
            &matcher,
            &cmd_with_config_operand("core.editor=true", ArgMeta::UnsafeString)
        ));
        for operand in [
            "core.editor",
            "core.editor=vim",
            "core.editor=/usr/bin/true",
            "core.editor=TRUE",
            "core.editor= true",
            "core.editor=true ",
        ] {
            assert!(
                matches_rule(
                    &matcher,
                    &cmd_with_config_operand(operand, ArgMeta::PlainWord)
                ),
                "{operand:?}"
            );
        }
    }

    #[test]
    fn git_config_matcher_keys_are_case_insensitive_but_values_are_not() {
        let matcher = editor_git_config_matcher();
        assert!(!matches_rule(
            &matcher,
            &parse_cmd("git -c CORE.EDITOR=true status")
        ));
        assert!(matches_rule(
            &matcher,
            &parse_cmd("git -c CORE.EDITOR=TRUE status")
        ));
        assert!(!matches_rule(
            &matcher,
            &parse_cmd("git -c unrelated.editor=vim status")
        ));
    }

    #[test]
    fn git_config_matcher_evaluates_repeated_targets_independently() {
        let matcher = editor_git_config_matcher();
        for command in [
            "git -c core.editor=true -c core.editor=vim status",
            "git -c core.editor=vim -c core.editor=true status",
        ] {
            assert!(matches_rule(&matcher, &parse_cmd(command)), "{command}");
        }
        assert!(!matches_rule(
            &matcher,
            &parse_cmd("git -c core.editor=true -c sequence.editor=true status")
        ));
        assert!(!matches_rule(
            &matcher,
            &parse_cmd("git -c core.editor=true -c alias.run=!evil status")
        ));
    }

    #[test]
    fn git_config_matcher_consumes_only_canonical_cli_config_globals() {
        let matcher = editor_git_config_matcher();
        assert!(!matches_rule(
            &matcher,
            &parse_cmd("notgit -c core.editor=vim status")
        ));
        assert!(matches_rule(
            &matcher,
            &parse_cmd("/usr/bin/git -c core.editor=vim status")
        ));
        for command in [
            "git --config-env=core.editor=EDITOR status",
            "git config core.editor true",
            "git config core.editor vim",
            "git status core.editor=vim",
            "git grep core.editor=vim",
            "git -- -c core.editor=vim status",
            "git -ccore.editor=vim status",
            "git -c \"core.$KEY=vim\" status",
        ] {
            assert!(!matches_rule(&matcher, &parse_cmd(command)), "{command}");
        }
    }

    #[test]
    fn git_config_matcher_keeps_static_key_from_unsafe_value_provenance() {
        let matcher = editor_git_config_matcher();
        assert!(matches_rule(
            &matcher,
            &parse_cmd("git -c core.editor=\"$EDITOR\" status")
        ));
    }

    fn assignment(name: &str, value: &str, value_meta: ArgMeta) -> Assignment {
        Assignment {
            name: name.to_string(),
            value: value.to_string(),
            value_meta,
        }
    }

    #[test]
    fn env_exception_accepts_exact_static_shell_noop_provenance_only() {
        let matcher = editor_env_matcher();
        for meta in [ArgMeta::PlainWord, ArgMeta::RawString, ArgMeta::SafeString] {
            assert!(
                !env_matches(&matcher, &[assignment("GIT_EDITOR", "true", meta)]),
                "static exact `true` should be exempt for {meta:?}"
            );
        }

        for (value, meta) in [
            ("true", ArgMeta::UnsafeString),
            ("vim", ArgMeta::PlainWord),
            ("TRUE", ArgMeta::PlainWord),
            ("/bin/true", ArgMeta::PlainWord),
        ] {
            assert!(
                env_matches(&matcher, &[assignment("GIT_EDITOR", value, meta)]),
                "unsafe editor value {value:?} with {meta:?} must remain dangerous"
            );
        }
    }

    #[test]
    fn env_exception_filters_only_its_same_candidate() {
        let matcher = editor_env_matcher();
        let safe_editor = assignment("GIT_EDITOR", "true", ArgMeta::PlainWord);
        let unsafe_ssh = assignment("GIT_SSH_COMMAND", "evil", ArgMeta::PlainWord);
        let unsafe_editor = assignment("GIT_EDITOR", "vim", ArgMeta::PlainWord);

        assert!(!env_matches(&matcher, std::slice::from_ref(&safe_editor)));
        assert!(env_matches(&matcher, std::slice::from_ref(&unsafe_editor)));

        for assignments in [
            vec![safe_editor.clone(), unsafe_ssh.clone()],
            vec![unsafe_ssh.clone(), safe_editor.clone()],
            vec![safe_editor.clone(), unsafe_editor.clone()],
            vec![unsafe_editor.clone(), safe_editor.clone()],
        ] {
            assert!(
                env_matches(&matcher, &assignments),
                "a safe assignment must not hide a dangerous sibling or duplicate: {assignments:?}"
            );
        }
    }

    #[test]
    fn each_configured_editor_variable_can_be_exempt_independently() {
        let matcher = editor_env_matcher();
        for name in ["GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "EDITOR", "VISUAL"] {
            assert!(
                !env_matches(&matcher, &[assignment(name, "true", ArgMeta::PlainWord)]),
                "{name} should be independently exempt"
            );
        }

        let all_safe = ["GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "EDITOR", "VISUAL"]
            .into_iter()
            .map(|name| assignment(name, "true", ArgMeta::SafeString))
            .collect::<Vec<_>>();
        assert!(
            !env_matches(&matcher, &all_safe),
            "a rule must not match when all matched candidates are exempt"
        );
    }

    #[test]
    fn parent_and_exception_name_case_controls_are_independent() {
        let matcher = editor_env_matcher();
        assert!(env_matches(
            &matcher,
            &[assignment("git_editor", "true", ArgMeta::PlainWord)]
        ));

        let mut parent_case_sensitive = editor_env_matcher();
        parent_case_sensitive.case_insensitive = false;
        assert!(!env_matches(
            &parent_case_sensitive,
            &[assignment("git_editor", "vim", ArgMeta::PlainWord)]
        ));

        let mut exception_case_insensitive = editor_env_matcher();
        exception_case_insensitive.except[0].name_case_insensitive = true;
        assert!(!env_matches(
            &exception_case_insensitive,
            &[assignment("git_editor", "true", ArgMeta::PlainWord)]
        ));
    }

    #[test]
    fn env_matcher_preserves_empty_and_legacy_semantics() {
        let unrelated = assignment("PATH", "/bin", ArgMeta::PlainWord);
        let empty = EnvMatcher {
            any_of: vec![],
            case_insensitive: false,
            except: vec![],
        };
        assert!(env_matches(&empty, std::slice::from_ref(&unrelated)));
        assert!(env_matches(&empty, &[]));

        let legacy = EnvMatcher {
            any_of: vec!["GIT_EDITOR".to_string()],
            case_insensitive: false,
            except: vec![],
        };
        assert!(!env_matches(&legacy, std::slice::from_ref(&unrelated)));
        assert!(env_matches(
            &legacy,
            &[assignment("GIT_EDITOR", "true", ArgMeta::PlainWord)]
        ));
        assert!(env_matches(
            &legacy,
            &[assignment("GIT_EDITOR", "vim", ArgMeta::UnsafeString)]
        ));
    }

    #[test]
    fn test_resolve_subcommand_plain() {
        assert_eq!(
            resolve_subcommand(&parse_cmd("git checkout --force")),
            resolved("checkout")
        );
        assert_eq!(
            resolve_subcommand(&parse_cmd("git push origin main")),
            resolved("push")
        );
    }

    #[test]
    fn test_resolve_subcommand_skips_git_globals() {
        // `-C <path>` and `-c <key=val>` value pairs are skipped.
        assert_eq!(
            resolve_subcommand(&parse_cmd("git -C /repo checkout --force")),
            resolved("checkout")
        );
        assert_eq!(
            resolve_subcommand(&parse_cmd("git -c user.name=x commit --amend")),
            resolved("commit")
        );
        assert_eq!(
            resolve_subcommand(&parse_cmd("git --git-dir /tmp/.git status")),
            resolved("status")
        );
        assert_eq!(
            resolve_subcommand(&parse_cmd("git --git-dir=/tmp/.git status")),
            resolved("status")
        );
        assert_eq!(
            resolve_subcommand(&parse_cmd(
                "git --paginate -C /repo -c user.name=x --work-tree=/repo status"
            )),
            resolved("status")
        );
    }

    #[test]
    fn test_resolve_subcommand_basename_normalized() {
        // Absolute-path git still has its globals stripped (basename detection).
        assert_eq!(
            resolve_subcommand(&parse_cmd("/usr/bin/git -C /repo checkout --force")),
            resolved("checkout")
        );
    }

    #[test]
    fn test_resolve_subcommand_skips_boolean_globals() {
        // `--paginate` / `--no-pager` are boolean globals (not value-flags).
        assert_eq!(
            resolve_subcommand(&parse_cmd("git --paginate log")),
            resolved("log")
        );
    }

    #[test]
    fn test_resolve_subcommand_ambiguous_on_unsafe_global() {
        // `-C "$REPO"` value is an UnsafeString -> cannot locate the subcommand.
        assert_eq!(
            resolve_subcommand(&parse_cmd("git -C \"$REPO\" checkout --force")),
            SubcommandResolution::Ambiguous
        );
        // Command substitution value is equally unknowable.
        assert_eq!(
            resolve_subcommand(&parse_cmd("git -C \"$(pwd)\" checkout --force")),
            SubcommandResolution::Ambiguous
        );
        assert_eq!(
            resolve_subcommand(&parse_cmd("git -ccore.editor=true status")),
            SubcommandResolution::Ambiguous
        );
        assert_eq!(
            resolve_subcommand(&parse_cmd("git --git-dirx=/repo status")),
            SubcommandResolution::Ambiguous
        );
    }

    #[test]
    fn test_resolve_subcommand_absent() {
        // No positional subcommand -> Absent (matches no pin).
        assert_eq!(
            resolve_subcommand(&parse_cmd("git --version")),
            SubcommandResolution::Absent
        );
        assert_eq!(
            resolve_subcommand(&parse_cmd("git -h")),
            SubcommandResolution::Absent
        );
    }

    #[test]
    fn test_resolve_subcommand_non_git() {
        // Generic: resolves the first positional for any command family.
        assert_eq!(
            resolve_subcommand(&parse_cmd("docker rm -f x")),
            resolved("rm")
        );
        assert_eq!(
            resolve_subcommand(&parse_cmd("codex --profile p exec foo")),
            resolved("exec")
        );
    }

    #[test]
    fn test_argv_from_subcommand_strips_leading_globals() {
        use super::argv_from_subcommand;
        let texts = |cmd: &str| -> Vec<String> {
            argv_from_subcommand(&parse_cmd(cmd))
                .iter()
                .map(|a| a.text.clone())
                .collect()
        };
        // Leading `-C <path>` global is stripped so the global -C is not seen
        // as the branch force-copy -C; the branch's own -C survives.
        assert_eq!(
            texts("git -C /repo branch --list"),
            vec!["branch", "--list"]
        );
        assert_eq!(
            texts("git -C /repo branch -C old new"),
            vec!["branch", "-C", "old", "new"]
        );
        // UnsafeString global value is stripped too (unlike effective_argv).
        assert_eq!(
            texts("git -C \"$REPO\" branch --list"),
            vec!["branch", "--list"]
        );
        // Boolean global flags are skipped.
        assert_eq!(texts("git --paginate log"), vec!["log"]);
        // No leading globals → returned unchanged.
        assert_eq!(texts("git checkout --force"), vec!["checkout", "--force"]);
    }

    #[test]
    fn test_subcommand_start_index() {
        use super::subcommand_start_index;
        let idx = |cmd: &str| subcommand_start_index(&parse_cmd(cmd));
        // No leading globals: the subcommand is argv[0].
        assert_eq!(idx("git config core.hooksPath"), 0);
        assert_eq!(idx("git config core.hooksPath /tmp/x"), 0);
        // Space-form global value pair (`-C <path>`) is stripped (2 tokens).
        assert_eq!(idx("git -C /repo config core.hooksPath"), 2);
        // Joined `=value` form of the `--git-dir` value-flag: not matched as a
        // value-flag token as-is, so skipped as one boolean-style token.
        assert_eq!(idx("git --git-dir=/r/.git config core.hooksPath"), 1);
        // UnsafeString global value (`-C "$REPO"`) is stripped unconditionally.
        assert_eq!(idx("git -C \"$REPO\" config core.hooksPath"), 2);
        // `--` ends option processing; the subcommand follows.
        assert_eq!(idx("git -- config core.hooksPath"), 1);
        // Dangling trailing value-flag: cursor jumps past the end but is CLAMPED
        // to argv.len() — guards the min_args underflow (argv=["-C"], len 1).
        assert_eq!(idx("git -C"), 1);
        assert_eq!(idx("git -c"), 1);
        assert_eq!(idx("git -ccore.editor=true status"), 1);
        assert_eq!(
            idx("git --paginate -C /repo -c benign.key=value --work-tree=/repo status"),
            6
        );
        // Non-git command: no git globals, first positional at index 0.
        assert_eq!(idx("docker rm -f x"), 0);
    }

    #[test]
    fn test_git_ambiguous_subcommand_does_not_match_a_pin_by_itself() {
        let matcher = command_matcher(None, args_matcher(&["status"]));
        for source in [
            "git -ccore.editor=true status",
            "git -C \"$REPO\" status",
            "git --unknown status",
        ] {
            assert!(!matches_rule(&matcher, &parse_cmd(source)), "{source}");
        }
    }

    #[test]
    fn test_git_pinned_flags_start_at_canonical_subcommand_boundary() {
        let matcher = command_matcher(
            Some(FlagsMatcher {
                any_of: vec!["-C".to_string()],
                all_of: vec![],
                none_of: vec![],
                starts_with: vec![],
            }),
            args_matcher(&["branch"]),
        );

        assert!(!matches_rule(
            &matcher,
            &parse_cmd("git -C /repo branch --list")
        ));
        assert!(matches_rule(
            &matcher,
            &parse_cmd("git -C /repo branch -C old new")
        ));
        assert!(!matches_rule(
            &matcher,
            &parse_cmd("git -C \"$REPO\" branch --list")
        ));
    }

    #[test]
    fn test_git_min_args_uses_canonical_clamped_boundary() {
        let mut args = args_matcher(&[]);
        args.all_of = vec!["config".to_string()];
        args.min_args = Some(3);
        let matcher = command_matcher(None, args);

        for source in [
            "git -C /repo config core.editor",
            "git --git-dir=/repo/.git config core.editor",
            "git -C \"$REPO\" config core.editor",
            "git -C",
        ] {
            assert!(!matches_rule(&matcher, &parse_cmd(source)), "{source}");
        }
        assert!(matches_rule(
            &matcher,
            &parse_cmd("git -C /repo config core.editor true")
        ));
    }

    fn make_pipeline(commands: &[&str]) -> crate::parser::Pipeline {
        crate::parser::Pipeline {
            stages: commands
                .iter()
                .map(|c| {
                    let parsed = crate::parser::parse(c).unwrap();
                    match parsed {
                        crate::parser::Statement::Pipeline(p) => {
                            p.stages.into_iter().next().unwrap()
                        }
                        other => other,
                    }
                })
                .collect(),
            negated: false,
        }
    }

    #[test]
    fn test_arg_matches_flag_exact_match() {
        assert!(arg_matches_flag("-f", "-f"));
        assert!(arg_matches_flag("--force", "--force"));
        assert!(!arg_matches_flag("--forceful", "--force"));
    }

    #[test]
    fn test_arg_matches_flag_long_with_equals() {
        assert!(arg_matches_flag("--output=out.txt", "--output"));
        assert!(arg_matches_flag("--prune=now", "--prune"));
        assert!(!arg_matches_flag("--output", "--output-file"));
    }

    #[test]
    fn test_arg_matches_flag_combined_short() {
        assert!(arg_matches_flag("-xffd", "-f"));
        assert!(arg_matches_flag("-ffd", "-f"));
        assert!(arg_matches_flag("-fd", "-f"));
        assert!(arg_matches_flag("-fd", "-d"));
        assert!(!arg_matches_flag("-n", "-f"));
    }

    #[test]
    fn test_pipeline_stage_none_of_excludes_when_flag_present() {
        let matcher = PipelineMatcher {
            stages: vec![
                StageMatcher {
                    command: StringOrList::List {
                        any_of: vec!["curl".into(), "wget".into()],
                    },
                    flags: None,
                },
                StageMatcher {
                    command: StringOrList::List {
                        any_of: vec!["python".into(), "python3".into()],
                    },
                    flags: Some(FlagsMatcher {
                        none_of: vec!["-m".into(), "-c".into()],
                        any_of: vec![],
                        all_of: vec![],
                        starts_with: vec![],
                    }),
                },
            ],
        };
        let pipe = make_pipeline(&["curl http://example.com", "python3 -m json.tool"]);
        assert!(
            !matches_pipeline(&matcher, &pipe),
            "Should NOT match: python3 has -m flag which is in none_of"
        );
    }

    #[test]
    fn test_pipeline_stage_none_of_matches_when_flag_absent() {
        let matcher = PipelineMatcher {
            stages: vec![
                StageMatcher {
                    command: StringOrList::List {
                        any_of: vec!["curl".into(), "wget".into()],
                    },
                    flags: None,
                },
                StageMatcher {
                    command: StringOrList::List {
                        any_of: vec!["python".into(), "python3".into()],
                    },
                    flags: Some(FlagsMatcher {
                        none_of: vec!["-m".into(), "-c".into()],
                        any_of: vec![],
                        all_of: vec![],
                        starts_with: vec![],
                    }),
                },
            ],
        };
        let pipe = make_pipeline(&["curl http://example.com", "python3"]);
        assert!(
            matches_pipeline(&matcher, &pipe),
            "Should match: bare python3 has no excluded flags"
        );
    }

    #[test]
    fn test_pipeline_stage_any_of_matches_when_flag_present() {
        let matcher = PipelineMatcher {
            stages: vec![
                StageMatcher {
                    command: StringOrList::List {
                        any_of: vec!["curl".into(), "wget".into()],
                    },
                    flags: None,
                },
                StageMatcher {
                    command: StringOrList::List {
                        any_of: vec!["python".into(), "python3".into()],
                    },
                    flags: Some(FlagsMatcher {
                        any_of: vec!["-c".into(), "-e".into()],
                        none_of: vec![],
                        all_of: vec![],
                        starts_with: vec![],
                    }),
                },
            ],
        };
        let pipe = make_pipeline(&["curl http://example.com", "python3 -c 'print(1)'"]);
        assert!(
            matches_pipeline(&matcher, &pipe),
            "Should match: python3 has -c flag"
        );
    }

    #[test]
    fn test_pipeline_stage_any_of_no_match_when_flag_absent() {
        let matcher = PipelineMatcher {
            stages: vec![
                StageMatcher {
                    command: StringOrList::List {
                        any_of: vec!["curl".into(), "wget".into()],
                    },
                    flags: None,
                },
                StageMatcher {
                    command: StringOrList::List {
                        any_of: vec!["python".into(), "python3".into()],
                    },
                    flags: Some(FlagsMatcher {
                        any_of: vec!["-c".into(), "-e".into()],
                        none_of: vec![],
                        all_of: vec![],
                        starts_with: vec![],
                    }),
                },
            ],
        };
        let pipe = make_pipeline(&["curl http://example.com", "python3 -m json.tool"]);
        assert!(
            !matches_pipeline(&matcher, &pipe),
            "Should NOT match: python3 has -m not -c/-e"
        );
    }

    #[test]
    fn test_pipeline_stage_flags_on_first_stage() {
        let matcher = PipelineMatcher {
            stages: vec![
                StageMatcher {
                    command: StringOrList::Single("curl".into()),
                    flags: Some(FlagsMatcher {
                        any_of: vec!["-s".into()],
                        none_of: vec![],
                        all_of: vec![],
                        starts_with: vec![],
                    }),
                },
                StageMatcher {
                    command: StringOrList::Single("python3".into()),
                    flags: None,
                },
            ],
        };
        let pipe = make_pipeline(&["curl -s http://example.com", "python3"]);
        assert!(matches_pipeline(&matcher, &pipe));

        let pipe_no_s = make_pipeline(&["curl http://example.com", "python3"]);
        assert!(!matches_pipeline(&matcher, &pipe_no_s));
    }

    #[test]
    fn test_pipeline_no_flags_backward_compatible() {
        let matcher = PipelineMatcher {
            stages: vec![
                StageMatcher {
                    command: StringOrList::List {
                        any_of: vec!["curl".into(), "wget".into()],
                    },
                    flags: None,
                },
                StageMatcher {
                    command: StringOrList::List {
                        any_of: vec!["sh".into(), "bash".into()],
                    },
                    flags: None,
                },
            ],
        };
        let pipe = make_pipeline(&["curl http://example.com", "bash"]);
        assert!(matches_pipeline(&matcher, &pipe));
    }

    // --- flags_match unit tests ---

    fn fm(
        any_of: &[&str],
        all_of: &[&str],
        none_of: &[&str],
        starts_with: &[&str],
    ) -> FlagsMatcher {
        FlagsMatcher {
            any_of: any_of.iter().map(|s| s.to_string()).collect(),
            all_of: all_of.iter().map(|s| s.to_string()).collect(),
            none_of: none_of.iter().map(|s| s.to_string()).collect(),
            starts_with: starts_with.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn argv(args: &[&str]) -> Vec<Arg> {
        args.iter().map(|s| Arg::plain(*s)).collect()
    }

    #[test]
    fn test_flags_match_empty_matcher() {
        // All fields empty → always matches
        assert!(super::flags_match(
            &fm(&[], &[], &[], &[]),
            &argv(&["--anything"])
        ));
        assert!(super::flags_match(&fm(&[], &[], &[], &[]), &argv(&[])));
    }

    #[test]
    fn test_flags_match_any_of_present() {
        let m = fm(&["-f", "-v"], &[], &[], &[]);
        assert!(super::flags_match(&m, &argv(&["cmd", "-f"])));
        assert!(super::flags_match(&m, &argv(&["cmd", "-v"])));
        assert!(super::flags_match(&m, &argv(&["cmd", "-f", "-v"])));
    }

    #[test]
    fn test_flags_match_any_of_absent() {
        let m = fm(&["-f", "-v"], &[], &[], &[]);
        assert!(!super::flags_match(&m, &argv(&["cmd", "-x"])));
        assert!(!super::flags_match(&m, &argv(&["cmd"])));
    }

    #[test]
    fn test_flags_match_all_of_present() {
        let m = fm(&[], &["-f", "-v"], &[], &[]);
        assert!(super::flags_match(&m, &argv(&["cmd", "-f", "-v"])));
        assert!(super::flags_match(&m, &argv(&["cmd", "-v", "-f", "-x"])));
    }

    #[test]
    fn test_flags_match_all_of_partial() {
        let m = fm(&[], &["-f", "-v"], &[], &[]);
        assert!(!super::flags_match(&m, &argv(&["cmd", "-f"])));
        assert!(!super::flags_match(&m, &argv(&["cmd", "-v"])));
    }

    #[test]
    fn test_flags_match_all_of_absent() {
        let m = fm(&[], &["-f", "-v"], &[], &[]);
        assert!(!super::flags_match(&m, &argv(&["cmd", "-x"])));
    }

    #[test]
    fn test_flags_match_none_of_absent() {
        let m = fm(&[], &[], &["-f", "-v"], &[]);
        assert!(super::flags_match(&m, &argv(&["cmd", "-x"])));
        assert!(super::flags_match(&m, &argv(&["cmd"])));
    }

    #[test]
    fn test_flags_match_none_of_present() {
        let m = fm(&[], &[], &["-f", "-v"], &[]);
        assert!(!super::flags_match(&m, &argv(&["cmd", "-f"])));
        assert!(!super::flags_match(&m, &argv(&["cmd", "-v"])));
        assert!(!super::flags_match(&m, &argv(&["cmd", "-f", "-v"])));
    }

    #[test]
    fn test_flags_match_starts_with_present() {
        let m = fm(&[], &[], &[], &["-x"]);
        assert!(super::flags_match(&m, &argv(&["cmd", "-xvf"])));
        assert!(super::flags_match(&m, &argv(&["cmd", "-x"])));
    }

    #[test]
    fn test_flags_match_starts_with_absent() {
        let m = fm(&[], &[], &[], &["-x"]);
        assert!(!super::flags_match(&m, &argv(&["cmd", "-v"])));
        assert!(!super::flags_match(&m, &argv(&["cmd"])));
    }

    #[test]
    fn test_flags_match_combined_constraints() {
        // any_of requires -c or -e, none_of excludes --dry-run
        let m = fm(&["-c", "-e"], &[], &["--dry-run"], &[]);
        // Has -c, no --dry-run → match
        assert!(super::flags_match(&m, &argv(&["cmd", "-c", "arg"])));
        // Has -c AND --dry-run → no match (none_of fails)
        assert!(!super::flags_match(&m, &argv(&["cmd", "-c", "--dry-run"])));
        // Has --dry-run but no -c/-e → no match (any_of fails)
        assert!(!super::flags_match(&m, &argv(&["cmd", "--dry-run"])));
        // Has neither → no match (any_of fails)
        assert!(!super::flags_match(&m, &argv(&["cmd", "-x"])));
    }
}
