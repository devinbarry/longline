mod support;
use support::claude::{run_claude_glob_hook, run_claude_grep_hook, ClaudeRunResultExt};

// ── Grep: normal paths (allow) ──────────────────────────────────────

#[test]
fn test_grep_project_dir_allows() {
    let result = run_claude_grep_hook("TODO", Some("src/"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_grep_no_path_allows() {
    let result = run_claude_grep_hook("function", None);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_grep_absolute_path_allows() {
    let result = run_claude_grep_hook("error", Some("/home/user/project/src/main.rs"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

// ── Grep: sensitive paths (ask) ─────────────────────────────────────

#[test]
fn test_grep_ssh_dir_asks() {
    let result = run_claude_grep_hook("PRIVATE", Some("/home/user/.ssh/id_rsa"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_grep_aws_dir_asks() {
    let result = run_claude_grep_hook("secret", Some("/home/user/.aws/credentials"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_grep_gnupg_dir_asks() {
    let result = run_claude_grep_hook("key", Some("/home/user/.gnupg/secring.gpg"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_grep_etc_shadow_asks() {
    let result = run_claude_grep_hook("root", Some("/etc/shadow"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

// ── Glob: normal paths (allow) ──────────────────────────────────────

#[test]
fn test_glob_project_dir_allows() {
    let result = run_claude_glob_hook("**/*.rs", Some("src/"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_glob_no_path_allows() {
    let result = run_claude_glob_hook("*.yaml", None);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_glob_absolute_path_allows() {
    let result = run_claude_glob_hook("*.log", Some("/var/log"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

// ── Glob: sensitive paths (ask) ─────────────────────────────────────

#[test]
fn test_glob_ssh_dir_asks() {
    let result = run_claude_glob_hook("*", Some("/home/user/.ssh/"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_glob_aws_dir_asks() {
    let result = run_claude_glob_hook("*", Some("/home/user/.aws/"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_glob_gnupg_dir_asks() {
    let result = run_claude_glob_hook("*.gpg", Some("/home/user/.gnupg/"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_glob_etc_shadow_asks() {
    let result = run_claude_glob_hook("shadow", Some("/etc/shadow"));
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}
