//! Matching logic for policy rules.

use crate::parser::{self, Arg, SimpleCommand, Statement};
use std::borrow::Cow;

use super::config::{
    EnvMatcher, FlagsMatcher, Matcher, PipelineMatcher, RedirectMatcher, StringOrList,
};

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
        "git" => super::allowlist::GIT_GLOBAL_VALUE_FLAGS,
        "codex" => super::allowlist::CODEX_GLOBAL_VALUE_FLAGS,
        _ => crate::parser::wrappers::value_flags_for(cmd_name, first_arg),
    }
}

/// Outcome of resolving a command's effective subcommand for the
/// `ArgsMatcher::subcommand` pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubcommandResolution {
    /// The effective subcommand was found.
    Resolved(String),
    /// A subcommand exists but is unknowable — a global value-flag's value is
    /// a shell expansion/substitution (`git -C "$REPO" …`) or is dangling, so
    /// we cannot locate the subcommand. Gate-biased: MATCHES ANY pinned
    /// subcommand (over-ask is safe; missing a real `--force` is the failure).
    Ambiguous,
    /// There is no positional subcommand at all (`git --version`, `git -h`,
    /// bare `git`). MATCHES NO pin — there is nothing to gate.
    Absent,
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
/// This is intentionally a dedicated raw-argv scan and NOT a reuse of
/// `effective_argv().find(...)`: that helper *retains* an `UnsafeString`
/// value pair, so `.find(!starts_with('-'))` would return the `$REPO` token
/// rather than signalling ambiguity, silently missing the gate.
pub fn resolve_subcommand(cmd: &SimpleCommand) -> SubcommandResolution {
    let Some(name) = cmd.name.as_deref() else {
        return SubcommandResolution::Absent;
    };
    let cmd_name = normalize_command_name(name);
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
    let Some(name) = cmd.name.as_deref() else {
        return Cow::Borrowed(&cmd.argv);
    };
    let cmd_name = normalize_command_name(name);
    let first_arg = cmd.argv.first().map(|a| a.text.as_str());
    let value_flags = global_value_flags_for(cmd_name, first_arg);

    let mut i = 0;
    while i < cmd.argv.len() {
        let t = &cmd.argv[i].text;
        if t == "--" {
            // End of options; the subcommand follows.
            i += 1;
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

    let start = i.min(cmd.argv.len());
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

/// Check if an EnvMatcher's any_of patterns match any env-var assignment
/// on the command (i.e. `VAR=val cmd ...`). Returns true on match.
fn env_matches(env_matcher: &EnvMatcher, assignments: &[crate::parser::Assignment]) -> bool {
    if env_matcher.any_of.is_empty() {
        return true;
    }
    env_matcher.any_of.iter().any(|pattern| {
        assignments.iter().any(|a| {
            if env_matcher.case_insensitive {
                glob_match::glob_match(&pattern.to_lowercase(), &a.name.to_lowercase())
            } else {
                glob_match::glob_match(pattern, &a.name)
            }
        })
    })
}

/// Check if a rule's matcher matches a given SimpleCommand.
/// Pipeline matchers are handled separately in `evaluate` and are skipped here.
pub fn matches_rule(matcher: &Matcher, cmd: &SimpleCommand) -> bool {
    match matcher {
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
                    if cmd.argv.len() < min {
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
    use super::matches_pipeline;
    use super::{resolve_subcommand, SubcommandResolution};
    use crate::parser::Arg;
    use crate::policy::config::{FlagsMatcher, PipelineMatcher, StageMatcher, StringOrList};

    fn parse_cmd(s: &str) -> crate::parser::SimpleCommand {
        match crate::parser::parse(s).unwrap() {
            crate::parser::Statement::SimpleCommand(c) => c,
            other => panic!("expected SimpleCommand, got {other:?}"),
        }
    }

    fn resolved(s: &str) -> SubcommandResolution {
        SubcommandResolution::Resolved(s.to_string())
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
