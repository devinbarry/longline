mod common;
use common::run_hook_read;

// ── Normal files: should allow ──────────────────────────────────────

#[test]
fn test_read_project_source_file_allows() {
    let result = run_hook_read("/home/user/project/src/main.rs");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_read_relative_path_allows() {
    let result = run_hook_read("src/lib.rs");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_read_readme_allows() {
    let result = run_hook_read("README.md");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_read_etc_passwd_allows() {
    let result = run_hook_read("/etc/passwd");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_read_tmp_file_allows() {
    let result = run_hook_read("/tmp/output.log");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_read_dotfile_allows() {
    let result = run_hook_read("/home/user/.bashrc");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_read_package_json_allows() {
    let result = run_hook_read("package.json");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ── SSH credential store: should ask ────────────────────────────────

#[test]
fn test_read_ssh_private_key_asks() {
    let result = run_hook_read("/home/user/.ssh/id_rsa");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_read_ssh_ed25519_asks() {
    let result = run_hook_read("/home/user/.ssh/id_ed25519");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_read_ssh_config_asks() {
    let result = run_hook_read("/home/user/.ssh/config");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_read_ssh_authorized_keys_asks() {
    let result = run_hook_read("/home/user/.ssh/authorized_keys");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

// ── AWS credential store: should ask ────────────────────────────────

#[test]
fn test_read_aws_credentials_asks() {
    let result = run_hook_read("/home/user/.aws/credentials");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_read_aws_config_asks() {
    let result = run_hook_read("/home/user/.aws/config");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

// ── GnuPG credential store: should ask ──────────────────────────────

#[test]
fn test_read_gnupg_private_key_asks() {
    let result = run_hook_read("/home/user/.gnupg/secring.gpg");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_read_gnupg_trustdb_asks() {
    let result = run_hook_read("/home/user/.gnupg/trustdb.gpg");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

// ── /etc/shadow: should ask ─────────────────────────────────────────

#[test]
fn test_read_etc_shadow_asks() {
    let result = run_hook_read("/etc/shadow");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}
