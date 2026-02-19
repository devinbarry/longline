//! Allowlist matching logic.

use crate::parser::{SimpleCommand, Statement};

use super::config::{AllowlistEntry, RulesConfig};
use super::matching::normalize_command_name;
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

/// Find the first allowlist entry matching the command.
/// If `check_trust` is true, skip entries requiring a higher trust level than configured.
fn find_matching_entry<'a>(
    config: &'a RulesConfig,
    cmd: &SimpleCommand,
    check_trust: bool,
) -> Option<&'a AllowlistEntry> {
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
        if check_trust && entry.trust > config.trust_level {
            continue;
        }

        let parts: Vec<&str> = entry.command.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        if parts[0] != normalize_command_name(cmd_name) {
            continue;
        }
        if parts.len() == 1 {
            return Some(entry);
        }
        let required_args = &parts[1..];
        if args_match_prefix(required_args, argv.as_ref()) {
            return Some(entry);
        }
    }
    None
}

/// Find the matching allowlist entry for a SimpleCommand.
/// Entries like "git status" match command name + required args.
/// Bare entries like "ls" match any invocation of that command.
/// Entries with a trust level above the config's trust_level are skipped.
/// Returns the matching command string, or None if no match.
pub fn find_allowlist_match<'a>(config: &'a RulesConfig, cmd: &SimpleCommand) -> Option<&'a str> {
    find_matching_entry(config, cmd, true).map(|entry| entry.command.as_str())
}

/// Search all allowlist entries (ignoring trust level) for a matching command.
/// Returns the entry's reason if the command matches an entry that has a reason.
/// Used as a fallback when a command was trust-filtered out of the allowlist.
pub fn find_allowlist_reason(config: &RulesConfig, cmd: &SimpleCommand) -> Option<String> {
    find_matching_entry(config, cmd, false).and_then(|entry| entry.reason.clone())
}

/// Check if an extra_leaf (unwrapped inner command) is covered by a compound
/// allowlist entry on one of the original leaves.
///
/// For example, if the original leaf is `uv run yamllint .gitlab-ci.yml` and
/// the allowlist entry is `"uv run yamllint"`, then the extra_leaf `yamllint`
/// is covered because "yamllint" appears in the entry's prefix args.
///
/// Bare entries like `"timeout"` (no prefix args) never cover extra_leaves.
pub fn is_covered_by_wrapper_entry(
    config: &RulesConfig,
    original_leaves: &[&Statement],
    extra_leaf: &Statement,
) -> bool {
    let extra_cmd_name = match extra_leaf {
        Statement::SimpleCommand(cmd) => cmd.name.as_deref(),
        _ => return false,
    };
    let extra_cmd_name = match extra_cmd_name {
        Some(name) => name,
        None => return false,
    };

    for leaf in original_leaves {
        if let Statement::SimpleCommand(cmd) = leaf {
            if let Some(entry_str) = find_allowlist_match(config, cmd) {
                let parts: Vec<&str> = entry_str.split_whitespace().collect();
                if parts.len() > 1 && parts.last() == Some(&extra_cmd_name) {
                    return true;
                }
            }
        }
    }
    false
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
            trust_level: crate::policy::TrustLevel::default(),
            allowlists: crate::policy::Allowlists {
                commands: vec![crate::policy::AllowlistEntry {
                    command: "git status".to_string(),
                    trust: crate::policy::TrustLevel::Standard,
                    reason: None,
                    source: crate::policy::RuleSource::default(),
                }],
                paths: vec![],
            },
            rules: vec![],
        };

        let cmd = test_git_cmd(vec!["-C", "/tmp", "status"]);
        assert_eq!(find_allowlist_match(&config, &cmd), Some("git status"));
    }

    #[test]
    fn test_find_allowlist_match_respects_trust_level() {
        let config_minimal = RulesConfig {
            version: 1,
            default_decision: crate::types::Decision::Ask,
            safety_level: crate::policy::SafetyLevel::High,
            trust_level: crate::policy::TrustLevel::Minimal,
            allowlists: crate::policy::Allowlists {
                commands: vec![
                    crate::policy::AllowlistEntry {
                        command: "ls".to_string(),
                        trust: crate::policy::TrustLevel::Minimal,
                        reason: None,
                        source: crate::policy::RuleSource::default(),
                    },
                    crate::policy::AllowlistEntry {
                        command: "go build".to_string(),
                        trust: crate::policy::TrustLevel::Standard,
                        reason: None,
                        source: crate::policy::RuleSource::default(),
                    },
                    crate::policy::AllowlistEntry {
                        command: "docker run".to_string(),
                        trust: crate::policy::TrustLevel::Full,
                        reason: None,
                        source: crate::policy::RuleSource::default(),
                    },
                ],
                paths: vec![],
            },
            rules: vec![],
        };

        // Minimal trust: only minimal entries match
        let ls_cmd = SimpleCommand {
            name: Some("ls".to_string()),
            argv: vec![],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        };
        assert_eq!(
            find_allowlist_match(&config_minimal, &ls_cmd),
            Some("ls"),
            "Minimal-trust entry should match at Minimal trust level"
        );

        let go_cmd = SimpleCommand {
            name: Some("go".to_string()),
            argv: vec!["build".to_string()],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        };
        assert_eq!(
            find_allowlist_match(&config_minimal, &go_cmd),
            None,
            "Standard-trust entry should be skipped at Minimal trust level"
        );

        let docker_cmd = SimpleCommand {
            name: Some("docker".to_string()),
            argv: vec!["run".to_string()],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        };
        assert_eq!(
            find_allowlist_match(&config_minimal, &docker_cmd),
            None,
            "Full-trust entry should be skipped at Minimal trust level"
        );

        // Standard trust: minimal and standard match, full is skipped
        let config_standard = RulesConfig {
            trust_level: crate::policy::TrustLevel::Standard,
            ..config_minimal
        };
        assert_eq!(
            find_allowlist_match(&config_standard, &go_cmd),
            Some("go build"),
            "Standard-trust entry should match at Standard trust level"
        );
        assert_eq!(
            find_allowlist_match(&config_standard, &docker_cmd),
            None,
            "Full-trust entry should be skipped at Standard trust level"
        );
    }

    #[test]
    fn test_find_allowlist_reason_returns_reason_for_trust_filtered_entry() {
        let config = RulesConfig {
            version: 1,
            default_decision: crate::types::Decision::Ask,
            safety_level: crate::policy::SafetyLevel::High,
            trust_level: crate::policy::TrustLevel::Standard,
            allowlists: crate::policy::Allowlists {
                commands: vec![crate::policy::AllowlistEntry {
                    command: "git push".to_string(),
                    trust: crate::policy::TrustLevel::Full,
                    reason: Some("Pushes local commits to a remote repository".to_string()),
                    source: crate::policy::RuleSource::default(),
                }],
                paths: vec![],
            },
            rules: vec![],
        };

        let cmd = test_git_cmd(vec!["push", "origin", "main"]);

        // find_allowlist_match should return None (trust-filtered)
        assert_eq!(find_allowlist_match(&config, &cmd), None);

        // find_allowlist_reason should return the reason
        assert_eq!(
            find_allowlist_reason(&config, &cmd),
            Some("Pushes local commits to a remote repository".to_string()),
        );
    }

    #[test]
    fn test_find_allowlist_reason_returns_none_for_unrecognized_command() {
        let config = RulesConfig {
            version: 1,
            default_decision: crate::types::Decision::Ask,
            safety_level: crate::policy::SafetyLevel::High,
            trust_level: crate::policy::TrustLevel::Standard,
            allowlists: crate::policy::Allowlists {
                commands: vec![crate::policy::AllowlistEntry {
                    command: "git push".to_string(),
                    trust: crate::policy::TrustLevel::Full,
                    reason: Some("Pushes local commits to a remote repository".to_string()),
                    source: crate::policy::RuleSource::default(),
                }],
                paths: vec![],
            },
            rules: vec![],
        };

        let cmd = SimpleCommand {
            name: Some("unknown-tool".to_string()),
            argv: vec![],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        };

        assert_eq!(find_allowlist_reason(&config, &cmd), None);
    }

    #[test]
    fn test_find_allowlist_reason_returns_none_when_no_reason_field() {
        let config = RulesConfig {
            version: 1,
            default_decision: crate::types::Decision::Ask,
            safety_level: crate::policy::SafetyLevel::High,
            trust_level: crate::policy::TrustLevel::Standard,
            allowlists: crate::policy::Allowlists {
                commands: vec![crate::policy::AllowlistEntry {
                    command: "git push".to_string(),
                    trust: crate::policy::TrustLevel::Full,
                    reason: None,
                    source: crate::policy::RuleSource::default(),
                }],
                paths: vec![],
            },
            rules: vec![],
        };

        let cmd = test_git_cmd(vec!["push"]);
        assert_eq!(find_allowlist_reason(&config, &cmd), None);
    }

    #[test]
    fn test_find_allowlist_match_git_c_clean_does_not_match_git_clean_allowlist() {
        let config = RulesConfig {
            version: 1,
            default_decision: crate::types::Decision::Ask,
            safety_level: crate::policy::SafetyLevel::High,
            trust_level: crate::policy::TrustLevel::default(),
            allowlists: crate::policy::Allowlists {
                commands: vec![crate::policy::AllowlistEntry {
                    command: "git status".to_string(),
                    trust: crate::policy::TrustLevel::Standard,
                    reason: None,
                    source: crate::policy::RuleSource::default(),
                }],
                paths: vec![],
            },
            rules: vec![],
        };

        let cmd = test_git_cmd(vec!["-C", "/tmp", "clean", "-f"]);
        assert_eq!(find_allowlist_match(&config, &cmd), None);
    }

    #[test]
    fn test_is_covered_by_wrapper_entry_compound_entry() {
        use crate::parser::Statement;

        let config = RulesConfig {
            version: 1,
            default_decision: crate::types::Decision::Ask,
            safety_level: crate::policy::SafetyLevel::High,
            trust_level: crate::policy::TrustLevel::Standard,
            allowlists: crate::policy::Allowlists {
                commands: vec![crate::policy::AllowlistEntry {
                    command: "uv run yamllint".to_string(),
                    trust: crate::policy::TrustLevel::Standard,
                    reason: None,
                    source: crate::policy::RuleSource::default(),
                }],
                paths: vec![],
            },
            rules: vec![],
        };

        let original_leaf = Statement::SimpleCommand(SimpleCommand {
            name: Some("uv".to_string()),
            argv: vec![
                "run".to_string(),
                "yamllint".to_string(),
                ".gitlab-ci.yml".to_string(),
            ],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        });

        let extra_leaf_covered = Statement::SimpleCommand(SimpleCommand {
            name: Some("yamllint".to_string()),
            argv: vec![".gitlab-ci.yml".to_string()],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        });

        let extra_leaf_not_covered = Statement::SimpleCommand(SimpleCommand {
            name: Some("dangeroustool".to_string()),
            argv: vec![],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        });

        let leaves = vec![&original_leaf];

        assert!(
            is_covered_by_wrapper_entry(&config, &leaves, &extra_leaf_covered),
            "yamllint should be covered by 'uv run yamllint' entry"
        );
        assert!(
            !is_covered_by_wrapper_entry(&config, &leaves, &extra_leaf_not_covered),
            "dangeroustool should NOT be covered"
        );
    }

    #[test]
    fn test_is_covered_by_wrapper_entry_bare_entry_no_coverage() {
        use crate::parser::Statement;

        let config = RulesConfig {
            version: 1,
            default_decision: crate::types::Decision::Ask,
            safety_level: crate::policy::SafetyLevel::High,
            trust_level: crate::policy::TrustLevel::Standard,
            allowlists: crate::policy::Allowlists {
                commands: vec![crate::policy::AllowlistEntry {
                    command: "timeout".to_string(),
                    trust: crate::policy::TrustLevel::Standard,
                    reason: None,
                    source: crate::policy::RuleSource::default(),
                }],
                paths: vec![],
            },
            rules: vec![],
        };

        let original_leaf = Statement::SimpleCommand(SimpleCommand {
            name: Some("timeout".to_string()),
            argv: vec!["10".to_string(), "unknown_command".to_string()],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        });

        let extra_leaf = Statement::SimpleCommand(SimpleCommand {
            name: Some("unknown_command".to_string()),
            argv: vec![],
            redirects: vec![],
            assignments: vec![],
            embedded_substitutions: vec![],
        });

        let leaves = vec![&original_leaf];

        assert!(
            !is_covered_by_wrapper_entry(&config, &leaves, &extra_leaf),
            "Bare 'timeout' entry should NOT cover unknown_command"
        );
    }
}
