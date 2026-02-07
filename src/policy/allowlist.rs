//! Allowlist matching logic.

use crate::parser::{SimpleCommand, Statement};

use super::config::RulesConfig;
use std::borrow::Cow;

/// Check if a leaf node is allowlisted (or is a bare version check).
pub fn is_allowlisted(config: &RulesConfig, leaf: &Statement) -> bool {
    match leaf {
        Statement::SimpleCommand(cmd) => {
            find_allowlist_match(config, cmd).is_some() || is_version_check(cmd)
        }
        Statement::Empty => true, // Empty statements (e.g., comments) are always safe
        _ => false,
    }
}

/// Check if a command is a bare version check (e.g., `foo --version` or `foo -V`).
pub(super) fn is_version_check(cmd: &SimpleCommand) -> bool {
    cmd.argv.len() == 1 && (cmd.argv[0] == "--version" || cmd.argv[0] == "-V")
}

/// Git supports global options like `-C <path>` that appear before the subcommand.
/// Strip those so allowlist entries like `git status` still match `git -C /tmp status`.
fn strip_git_global_c_flag(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut i = 0;
    let mut in_global_opts = true;

    while i < argv.len() {
        let arg = &argv[i];

        if in_global_opts {
            if arg == "--" {
                // End of options marker; everything after is command args.
                in_global_opts = false;
                out.push(arg.clone());
                i += 1;
                continue;
            }

            if arg == "-C" {
                // Skip `-C` and its path argument (if present).
                i += 1;
                if i < argv.len() {
                    i += 1;
                }
                continue;
            }

            // First non-flag token is the git subcommand; stop treating subsequent args as global opts.
            if !arg.starts_with('-') {
                in_global_opts = false;
            }
        }

        out.push(arg.clone());
        i += 1;
    }

    out
}

/// Normalize a path-like argument for matching.
/// Returns the basename if:
/// - The argument contains a `/` (is path-like)
/// - The path is relative (no leading `/`)
/// - The path has no traversal (`..` components)
///
/// Otherwise returns the original argument unchanged.
fn normalize_arg(arg: &str) -> &str {
    // Only normalize if it contains a path separator
    if !arg.contains('/') {
        return arg;
    }

    // Don't normalize absolute paths
    if arg.starts_with('/') {
        return arg;
    }

    // Don't normalize paths with traversal
    if arg.split('/').any(|component| component == "..") {
        return arg;
    }

    // Extract basename - the part after the last /
    arg.rsplit('/').next().unwrap_or(arg)
}

/// Check if required args match as an ordered prefix of argv.
/// Uses path normalization for safe relative paths.
fn args_match_prefix(required_args: &[&str], argv: &[String]) -> bool {
    if required_args.len() > argv.len() {
        return false;
    }

    required_args.iter().zip(argv.iter()).all(|(req, actual)| {
        let normalized = normalize_arg(actual);
        *req == normalized
    })
}

/// Find the matching allowlist entry for a SimpleCommand.
/// Entries like "git status" match command name + required args.
/// Bare entries like "ls" match any invocation of that command.
/// Returns the matching entry string, or None if no match.
pub fn find_allowlist_match<'a>(config: &'a RulesConfig, cmd: &SimpleCommand) -> Option<&'a str> {
    let cmd_name = match &cmd.name {
        Some(n) => n.as_str(),
        None => return None,
    };

    let argv: Cow<[String]> = if cmd_name == "git" && cmd.argv.iter().any(|a| a == "-C") {
        Cow::Owned(strip_git_global_c_flag(&cmd.argv))
    } else {
        Cow::Borrowed(&cmd.argv)
    };

    for entry in &config.allowlists.commands {
        let parts: Vec<&str> = entry.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        if parts[0] != cmd_name {
            continue;
        }
        if parts.len() == 1 {
            // Bare command name matches any invocation
            return Some(entry);
        }
        // Multi-word entry: required args must match as ordered prefix
        let required_args = &parts[1..];
        if args_match_prefix(required_args, argv.as_ref()) {
            return Some(entry);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_git_cmd(argv: Vec<&str>) -> SimpleCommand {
        SimpleCommand {
            name: Some("git".to_string()),
            argv: argv.into_iter().map(|s| s.to_string()).collect(),
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        }
    }

    // ================================================================
    // normalize_arg tests
    // ================================================================

    #[test]
    fn test_normalize_arg_no_slash_unchanged() {
        // Args without / should not be normalized
        assert_eq!(normalize_arg("manage.py"), "manage.py");
        assert_eq!(normalize_arg("check"), "check");
        assert_eq!(normalize_arg("myapp.tests"), "myapp.tests");
    }

    #[test]
    fn test_normalize_arg_relative_path_returns_basename() {
        // Safe relative paths should normalize to basename
        assert_eq!(normalize_arg("./manage.py"), "manage.py");
        assert_eq!(normalize_arg("server/manage.py"), "manage.py");
        assert_eq!(normalize_arg("apps/core/manage.py"), "manage.py");
    }

    #[test]
    fn test_normalize_arg_absolute_path_unchanged() {
        // Absolute paths should NOT be normalized
        assert_eq!(normalize_arg("/tmp/manage.py"), "/tmp/manage.py");
        assert_eq!(
            normalize_arg("/home/user/project/manage.py"),
            "/home/user/project/manage.py"
        );
    }

    #[test]
    fn test_normalize_arg_traversal_unchanged() {
        // Paths with .. should NOT be normalized
        assert_eq!(normalize_arg("../manage.py"), "../manage.py");
        assert_eq!(normalize_arg("../../manage.py"), "../../manage.py");
        assert_eq!(normalize_arg("foo/../manage.py"), "foo/../manage.py");
    }

    #[test]
    fn test_normalize_arg_dot_only_returns_empty() {
        // Edge case: ./ alone - basename is empty string
        // This should return empty or the original - either way it won't match "manage.py"
        let result = normalize_arg("./");
        assert!(result.is_empty() || result == "./");
    }

    // ================================================================
    // args_match_prefix tests
    // ================================================================

    #[test]
    fn test_args_match_prefix_exact_match() {
        let required = &["manage.py", "check"];
        let argv = vec!["manage.py".to_string(), "check".to_string()];
        assert!(args_match_prefix(required, &argv));
    }

    #[test]
    fn test_args_match_prefix_with_extra_trailing_args() {
        // Extra args at end should be OK
        let required = &["manage.py", "check"];
        let argv = vec![
            "manage.py".to_string(),
            "check".to_string(),
            "--deploy".to_string(),
        ];
        assert!(args_match_prefix(required, &argv));
    }

    #[test]
    fn test_args_match_prefix_wrong_first_arg_fails() {
        // evil.py in first position should NOT match
        let required = &["manage.py", "check"];
        let argv = vec![
            "evil.py".to_string(),
            "manage.py".to_string(),
            "check".to_string(),
        ];
        assert!(!args_match_prefix(required, &argv));
    }

    #[test]
    fn test_args_match_prefix_out_of_order_fails() {
        // Args in wrong order should NOT match
        let required = &["manage.py", "check"];
        let argv = vec!["check".to_string(), "manage.py".to_string()];
        assert!(!args_match_prefix(required, &argv));
    }

    #[test]
    fn test_args_match_prefix_with_path_normalization() {
        // ./manage.py should match manage.py after normalization
        let required = &["manage.py", "check"];
        let argv = vec!["./manage.py".to_string(), "check".to_string()];
        assert!(args_match_prefix(required, &argv));
    }

    #[test]
    fn test_args_match_prefix_subdir_path_normalization() {
        // server/manage.py should match manage.py after normalization
        let required = &["manage.py", "check"];
        let argv = vec!["server/manage.py".to_string(), "check".to_string()];
        assert!(args_match_prefix(required, &argv));
    }

    #[test]
    fn test_args_match_prefix_absolute_path_no_normalization() {
        // /tmp/manage.py should NOT be normalized, so won't match
        let required = &["manage.py", "check"];
        let argv = vec!["/tmp/manage.py".to_string(), "check".to_string()];
        assert!(!args_match_prefix(required, &argv));
    }

    #[test]
    fn test_args_match_prefix_traversal_no_normalization() {
        // ../manage.py should NOT be normalized, so won't match
        let required = &["manage.py", "check"];
        let argv = vec!["../manage.py".to_string(), "check".to_string()];
        assert!(!args_match_prefix(required, &argv));
    }

    #[test]
    fn test_args_match_prefix_not_enough_args() {
        // Fewer args than required should fail
        let required = &["manage.py", "check"];
        let argv = vec!["manage.py".to_string()];
        assert!(!args_match_prefix(required, &argv));
    }

    #[test]
    fn test_args_match_prefix_empty_required() {
        // Empty required args should match anything
        let required: &[&str] = &[];
        let argv = vec!["anything".to_string()];
        assert!(args_match_prefix(required, &argv));
    }

    // ================================================================
    // strip_git_global_c_flag tests
    // ================================================================

    #[test]
    fn test_strip_git_global_c_flag_basic() {
        let argv = vec!["-C".to_string(), "/tmp".to_string(), "status".to_string()];
        assert_eq!(strip_git_global_c_flag(&argv), vec!["status".to_string()]);
    }

    #[test]
    fn test_strip_git_global_c_flag_multiple() {
        let argv = vec![
            "-C".to_string(),
            "/tmp".to_string(),
            "-C".to_string(),
            "/other".to_string(),
            "status".to_string(),
        ];
        assert_eq!(strip_git_global_c_flag(&argv), vec!["status".to_string()]);
    }

    #[test]
    fn test_find_allowlist_match_git_c_status_matches_git_status() {
        let config = RulesConfig {
            version: 1,
            default_decision: crate::types::Decision::Ask,
            safety_level: crate::policy::SafetyLevel::High,
            allowlists: crate::policy::Allowlists {
                commands: vec!["git status".to_string()],
                paths: vec![],
            },
            rules: vec![],
        };

        let cmd = test_git_cmd(vec!["-C", "/tmp", "status"]);
        assert_eq!(find_allowlist_match(&config, &cmd), Some("git status"));
    }

    #[test]
    fn test_find_allowlist_match_git_c_clean_does_not_match_git_clean_allowlist() {
        let config = RulesConfig {
            version: 1,
            default_decision: crate::types::Decision::Ask,
            safety_level: crate::policy::SafetyLevel::High,
            allowlists: crate::policy::Allowlists {
                commands: vec!["git status".to_string()],
                paths: vec![],
            },
            rules: vec![],
        };

        let cmd = test_git_cmd(vec!["-C", "/tmp", "clean", "-f"]);
        assert_eq!(find_allowlist_match(&config, &cmd), None);
    }
}
