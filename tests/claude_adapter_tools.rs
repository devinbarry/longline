mod support;
use support::claude::{
    run_claude_glob_hook, run_claude_grep_hook, run_claude_read_hook, ClaudeRunResultExt,
};

// ── Normal files: should allow ──────────────────────────────────────

#[test]
fn test_read_project_source_file_allows() {
    let result = run_claude_read_hook("/home/user/project/src/main.rs");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_read_relative_path_allows() {
    let result = run_claude_read_hook("src/lib.rs");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_read_readme_allows() {
    let result = run_claude_read_hook("README.md");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_read_etc_passwd_allows() {
    let result = run_claude_read_hook("/etc/passwd");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_read_tmp_file_allows() {
    let result = run_claude_read_hook("/tmp/output.log");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_read_dotfile_allows() {
    let result = run_claude_read_hook("/home/user/.bashrc");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_read_package_json_allows() {
    let result = run_claude_read_hook("package.json");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

// ── SSH credential store: should ask ────────────────────────────────

#[test]
fn test_read_ssh_private_key_asks() {
    let result = run_claude_read_hook("/home/user/.ssh/id_rsa");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_read_ssh_ed25519_asks() {
    let result = run_claude_read_hook("/home/user/.ssh/id_ed25519");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_read_ssh_config_asks() {
    let result = run_claude_read_hook("/home/user/.ssh/config");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_read_ssh_authorized_keys_asks() {
    let result = run_claude_read_hook("/home/user/.ssh/authorized_keys");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

// ── AWS credential store: should ask ────────────────────────────────

#[test]
fn test_read_aws_credentials_asks() {
    let result = run_claude_read_hook("/home/user/.aws/credentials");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_read_aws_config_asks() {
    let result = run_claude_read_hook("/home/user/.aws/config");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

// ── GnuPG credential store: should ask ──────────────────────────────

#[test]
fn test_read_gnupg_private_key_asks() {
    let result = run_claude_read_hook("/home/user/.gnupg/secring.gpg");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_read_gnupg_trustdb_asks() {
    let result = run_claude_read_hook("/home/user/.gnupg/trustdb.gpg");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

// ── /etc/shadow: should ask ─────────────────────────────────────────

#[test]
fn test_read_etc_shadow_asks() {
    let result = run_claude_read_hook("/etc/shadow");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

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
