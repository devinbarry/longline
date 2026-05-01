mod support;
use std::process::{Command, Stdio};
use support::bin::longline_bin;
use support::cli::{run_subcommand, run_subcommand_with_home};
use support::paths::rules_path;

#[test]
fn test_e2e_rules_shows_table() {
    let result = run_subcommand(&["rules", "--config", &rules_path()]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("DECISION"),
        "Should have header: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("rm-recursive-root"),
        "Should list rules: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("Allowlist:"),
        "Should show allowlist: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("Safety level:"),
        "Should show safety level: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_filter_deny() {
    let result = run_subcommand(&["rules", "--config", &rules_path(), "--filter", "deny"]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("deny"),
        "Should have deny rules: {}",
        result.stdout
    );
    assert!(
        !result.stdout.contains("\nask "),
        "Should not have ask rules in filtered output"
    );
}

#[test]
fn test_e2e_rules_filter_level() {
    let result = run_subcommand(&["rules", "--config", &rules_path(), "--level", "critical"]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("critical"),
        "Should have critical rules: {}",
        result.stdout
    );
    let table_part = result.stdout.split("Safety level:").next().unwrap_or("");
    assert!(
        !table_part.contains("high"),
        "Should not have high-level rules in table: {}",
        table_part
    );
    assert!(
        !table_part.contains("strict"),
        "Should not have strict-level rules in table: {}",
        table_part
    );
}

#[test]
fn test_e2e_rules_group_by_decision() {
    let result = run_subcommand(&["rules", "--config", &rules_path(), "--group-by", "decision"]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("DENY"),
        "Should have deny group header: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("ASK"),
        "Should have ask group header: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_shows_trust_level() {
    let result = run_subcommand(&["rules", "--config", &rules_path()]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("Trust level:"),
        "Should show trust level: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_with_dir_shows_project_rules() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("longline.yaml"),
        r#"
rules:
  - id: project-test-rule
    level: high
    match:
      command: sometool
    decision: ask
    reason: "Project test rule"
"#,
    )
    .unwrap();

    let result = run_subcommand(&[
        "rules",
        "--config",
        &rules_path(),
        "--dir",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("project-test-rule"),
        "Should show project rule: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_auto_discovers_project_from_cwd() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("longline.yaml"),
        r#"
rules:
  - id: cwd-test-rule
    level: high
    match:
      command: mytool
    decision: deny
    reason: "CWD discovery test"
"#,
    )
    .unwrap();

    let home = support::config::static_test_home()
        .to_string_lossy()
        .to_string();
    let child = Command::new(longline_bin())
        .args(["rules", "--config", &rules_path()])
        .env("HOME", &home)
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    let output = child.wait_with_output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert_eq!(code, 0);
    assert!(
        stdout.contains("cwd-test-rule"),
        "Should auto-discover project config from cwd: {}",
        stdout
    );
}

#[test]
fn test_e2e_rules_shows_source_column() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("longline.yaml"),
        r#"
rules:
  - id: source-test-rule
    level: high
    match:
      command: sometool
    decision: ask
    reason: "Source test"
"#,
    )
    .unwrap();

    let result = run_subcommand(&[
        "rules",
        "--config",
        &rules_path(),
        "--dir",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("SOURCE"),
        "Should have SOURCE header column: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("project"),
        "Should show 'project' source for project rules: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_shows_project_banner() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("longline.yaml"),
        "rules:\n  - id: banner-test\n    level: high\n    match:\n      command: foo\n    decision: ask\n    reason: test\n",
    ).unwrap();

    let result = run_subcommand(&[
        "rules",
        "--config",
        &rules_path(),
        "--dir",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("Project config:"),
        "Should show project config banner: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_no_banner_without_project_config() {
    let result = run_subcommand(&["rules", "--config", &rules_path(), "--dir", "/tmp"]);
    assert_eq!(result.exit_code, 0);
    assert!(
        !result.stdout.contains("Project config:"),
        "Should NOT show project config banner when no project config: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_filter_trust_full() {
    let result = run_subcommand(&["rules", "--config", &rules_path(), "--filter", "trust:full"]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("ALLOWLISTED COMMANDS"),
        "Should show allowlist table: {}",
        result.stdout
    );
    for line in result.stdout.lines() {
        if line.contains("minimal") && !line.contains("Trust level") {
            panic!("Should not contain minimal trust entries: {}", line);
        }
        if line.contains("standard") && !line.contains("Trust level") {
            panic!("Should not contain standard trust entries: {}", line);
        }
    }
}

#[test]
fn test_e2e_rules_filter_trust_minimal() {
    let result = run_subcommand(&[
        "rules",
        "--config",
        &rules_path(),
        "--filter",
        "trust:minimal",
    ]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("ALLOWLISTED COMMANDS"),
        "Should show allowlist table: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_filter_decision_colon_syntax() {
    let result = run_subcommand(&[
        "rules",
        "--config",
        &rules_path(),
        "--filter",
        "decision:deny",
    ]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("deny"),
        "Should have deny rules: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_filter_bare_deny_backwards_compat() {
    let result = run_subcommand(&["rules", "--config", &rules_path(), "--filter", "deny"]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("deny"),
        "Should have deny rules: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_filter_multiple() {
    let result = run_subcommand(&[
        "rules",
        "--config",
        &rules_path(),
        "--filter",
        "deny",
        "--filter",
        "source:builtin",
    ]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("deny"),
        "Should have deny rules: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_rules_filter_invalid() {
    let result = run_subcommand(&["rules", "--config", &rules_path(), "--filter", "trust:mega"]);
    assert_ne!(result.exit_code, 0);
    assert!(
        result.stderr.contains("trust") || result.stderr.contains("invalid"),
        "Should show error for invalid filter: {}",
        result.stderr
    );
}

#[test]
fn test_e2e_rules_shows_global_config() {
    let home = tempfile::TempDir::new().unwrap();
    let config_dir = home.path().join(".config").join("longline");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("ai-judge.yaml"),
        "command: /definitely-not-a-real-ai-judge-command-12345\ntimeout: 1\n",
    )
    .unwrap();
    std::fs::write(
        config_dir.join("longline.yaml"),
        "override_trust_level: full\n",
    )
    .unwrap();

    let home_str = home.path().to_string_lossy().to_string();
    let result = run_subcommand_with_home(&["rules"], &home_str);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("Global config:"),
        "Should show global config banner: {}",
        result.stdout
    );
}
