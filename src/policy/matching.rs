//! Matching logic for policy rules.

use crate::parser::{self, SimpleCommand, Statement};

use super::config::{Matcher, PipelineMatcher, RedirectMatcher, StringOrList};

/// Extract basename from a command path for matching.
/// "/usr/bin/rm" -> "rm", "./script.sh" -> "script.sh", "rm" -> "rm"
pub fn normalize_command_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
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

/// Check if a rule's matcher matches a given SimpleCommand.
/// Pipeline matchers are handled separately in `evaluate` and are skipped here.
pub fn matches_rule(matcher: &Matcher, cmd: &SimpleCommand) -> bool {
    match matcher {
        Matcher::Command {
            command,
            flags,
            args,
        } => {
            let cmd_name = match &cmd.name {
                Some(n) => n.as_str(),
                None => return false,
            };
            if !command.matches(normalize_command_name(cmd_name)) {
                return false;
            }
            // Check flags
            if let Some(flags_matcher) = flags {
                if !flags_matcher.any_of.is_empty() {
                    let has_any = flags_matcher
                        .any_of
                        .iter()
                        .any(|f| cmd.argv.iter().any(|a| arg_matches_flag(a, f)));
                    if !has_any {
                        return false;
                    }
                }
                if !flags_matcher.all_of.is_empty() {
                    let has_all = flags_matcher
                        .all_of
                        .iter()
                        .all(|f| cmd.argv.iter().any(|a| arg_matches_flag(a, f)));
                    if !has_all {
                        return false;
                    }
                }
                // none_of: rule matches only if NONE of these flags are present
                if !flags_matcher.none_of.is_empty() {
                    let has_any_excluded = flags_matcher
                        .none_of
                        .iter()
                        .any(|f| cmd.argv.iter().any(|a| arg_matches_flag(a, f)));
                    if has_any_excluded {
                        return false;
                    }
                }
                // starts_with: rule matches if any arg starts with any of these prefixes
                // Useful for combined flags like -xf matching "-x"
                if !flags_matcher.starts_with.is_empty() {
                    let has_prefix = flags_matcher
                        .starts_with
                        .iter()
                        .any(|prefix| cmd.argv.iter().any(|a| a.starts_with(prefix)));
                    if !has_prefix {
                        return false;
                    }
                }
            }
            // Check args with glob matching
            if let Some(args_matcher) = args {
                if !args_matcher.any_of.is_empty() {
                    let has_any = args_matcher
                        .any_of
                        .iter()
                        .any(|pattern| cmd.argv.iter().any(|a| glob_match::glob_match(pattern, a)));
                    if !has_any {
                        return false;
                    }
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
                    && stage_flags_match(&matcher.stages[matcher_idx], cmd)
                {
                    matcher_idx += 1;
                } else if let Some(inner) = crate::parser::wrappers::unwrap_transparent(cmd) {
                    if let Some(ref inner_name) = inner.name {
                        let inner_basename = normalize_command_name(inner_name);
                        if matcher.stages[matcher_idx].command.matches(inner_basename)
                            && stage_flags_match(&matcher.stages[matcher_idx], &inner)
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

/// Check if a stage matcher's flags constraints are satisfied by a command.
fn stage_flags_match(stage: &super::config::StageMatcher, cmd: &SimpleCommand) -> bool {
    let Some(ref flags_matcher) = stage.flags else {
        return true; // No flags constraint means any flags are fine
    };

    // any_of: at least one of these flags must be present
    if !flags_matcher.any_of.is_empty() {
        let has_any = flags_matcher
            .any_of
            .iter()
            .any(|f| cmd.argv.iter().any(|a| arg_matches_flag(a, f)));
        if !has_any {
            return false;
        }
    }

    // all_of: all of these flags must be present
    if !flags_matcher.all_of.is_empty() {
        let has_all = flags_matcher
            .all_of
            .iter()
            .all(|f| cmd.argv.iter().any(|a| arg_matches_flag(a, f)));
        if !has_all {
            return false;
        }
    }

    // none_of: none of these flags may be present
    if !flags_matcher.none_of.is_empty() {
        let has_any_excluded = flags_matcher
            .none_of
            .iter()
            .any(|f| cmd.argv.iter().any(|a| arg_matches_flag(a, f)));
        if has_any_excluded {
            return false;
        }
    }

    // starts_with: at least one arg must start with one of these prefixes
    if !flags_matcher.starts_with.is_empty() {
        let has_prefix = flags_matcher
            .starts_with
            .iter()
            .any(|prefix| cmd.argv.iter().any(|a| a.starts_with(prefix)));
        if !has_prefix {
            return false;
        }
    }

    true
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
}
