//! Matching logic for policy rules.

use crate::parser::{self, SimpleCommand, Statement};

use super::config::{Matcher, PipelineMatcher, RedirectMatcher, StringOrList};

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
            if !command.matches(cmd_name) {
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
                if matcher.stages[matcher_idx].command.matches(name) {
                    matcher_idx += 1;
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
