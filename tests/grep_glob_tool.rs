mod common;
use common::{run_hook_glob, run_hook_grep};

// ── Grep: normal paths (allow) ──────────────────────────────────────

#[test]
fn test_grep_project_dir_allows() {
    let result = run_hook_grep("TODO", Some("src/"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_grep_no_path_allows() {
    let result = run_hook_grep("function", None);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_grep_absolute_path_allows() {
    let result = run_hook_grep("error", Some("/home/user/project/src/main.rs"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ── Grep: sensitive paths (ask) ─────────────────────────────────────

#[test]
fn test_grep_ssh_dir_asks() {
    let result = run_hook_grep("PRIVATE", Some("/home/user/.ssh/id_rsa"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_grep_aws_dir_asks() {
    let result = run_hook_grep("secret", Some("/home/user/.aws/credentials"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_grep_gnupg_dir_asks() {
    let result = run_hook_grep("key", Some("/home/user/.gnupg/secring.gpg"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_grep_etc_shadow_asks() {
    let result = run_hook_grep("root", Some("/etc/shadow"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

// ── Glob: normal paths (allow) ──────────────────────────────────────

#[test]
fn test_glob_project_dir_allows() {
    let result = run_hook_glob("**/*.rs", Some("src/"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_glob_no_path_allows() {
    let result = run_hook_glob("*.yaml", None);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_glob_absolute_path_allows() {
    let result = run_hook_glob("*.log", Some("/var/log"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ── Glob: sensitive paths (ask) ─────────────────────────────────────

#[test]
fn test_glob_ssh_dir_asks() {
    let result = run_hook_glob("*", Some("/home/user/.ssh/"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_glob_aws_dir_asks() {
    let result = run_hook_glob("*", Some("/home/user/.aws/"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_glob_gnupg_dir_asks() {
    let result = run_hook_glob("*.gpg", Some("/home/user/.gnupg/"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_glob_etc_shadow_asks() {
    let result = run_hook_glob("shadow", Some("/etc/shadow"));
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}
