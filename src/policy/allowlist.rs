//! Allowlist matching logic.

use crate::parser::{SimpleCommand, Statement};

use super::config::RulesConfig;

/// Check if a leaf node is allowlisted.
pub fn is_allowlisted(config: &RulesConfig, leaf: &Statement) -> bool {
    match leaf {
        Statement::SimpleCommand(cmd) => find_allowlist_match(config, cmd).is_some(),
        _ => false,
    }
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
        if args_match_prefix(required_args, &cmd.argv) {
            return Some(entry);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
