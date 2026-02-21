mod common;
use common::{longline_bin, rules_path, run_subcommand, run_subcommand_with_home};
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
fn test_e2e_check_from_file() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp");
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("test-commands-subcmd.txt");
    std::fs::write(&file, "ls -la\nrm -rf /\nchmod 777 /tmp/f\n").unwrap();

    let result = run_subcommand(&["check", "--config", &rules_path(), file.to_str().unwrap()]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("DECISION"),
        "Should have header: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("allow"),
        "Should have allow: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("deny"),
        "Should have deny: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("ask"),
        "Should have ask: {}",
        result.stdout
    );

    let _ = std::fs::remove_file(&file);
}

#[test]
fn test_e2e_check_filter_deny() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp");
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("test-commands-filter-subcmd.txt");
    std::fs::write(&file, "ls -la\nrm -rf /\nchmod 777 /tmp/f\n").unwrap();

    let result = run_subcommand(&[
        "check",
        "--config",
        &rules_path(),
        "--filter",
        "deny",
        file.to_str().unwrap(),
    ]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("deny"),
        "Should have deny: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("rm -rf /"),
        "Should contain denied command: {}",
        result.stdout
    );
    assert!(
        !result.stdout.contains("ls -la"),
        "Should not contain allowed command: {}",
        result.stdout
    );
    assert!(
        !result.stdout.contains("chmod 777"),
        "Should not contain ask command: {}",
        result.stdout
    );

    let _ = std::fs::remove_file(&file);
}

#[test]
fn test_e2e_check_skips_comments_and_blanks() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp");
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("test-commands-comments-subcmd.txt");
    std::fs::write(&file, "# this is a comment\n\nls -la\n").unwrap();

    let result = run_subcommand(&["check", "--config", &rules_path(), file.to_str().unwrap()]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("ls -la"),
        "Should contain the ls command: {}",
        result.stdout
    );
    assert!(
        !result.stdout.contains("comment"),
        "Should not contain comment text: {}",
        result.stdout
    );
    let cmd_count = result.stdout.matches("ls -la").count();
    assert_eq!(
        cmd_count, 1,
        "Should have exactly 1 result, got {}: {}",
        cmd_count, result.stdout
    );

    let _ = std::fs::remove_file(&file);
}

#[test]
fn test_e2e_files_shows_totals() {
    let result = run_subcommand(&["files", "--config", &rules_path()]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("Safety level:"),
        "Should show safety level: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("Total:"),
        "Should show totals: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("allowlist entries"),
        "Should mention allowlist: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("rules"),
        "Should mention rules: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_files_shows_trust_level() {
    let result = run_subcommand(&["files", "--config", &rules_path()]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("Trust level:"),
        "Should show trust level: {}",
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
fn test_e2e_files_shows_embedded_source() {
    let dir = tempfile::TempDir::new().unwrap();
    let home = dir.path().to_string_lossy().to_string();

    let result = run_subcommand_with_home(&["files"], &home);
    assert_eq!(
        result.exit_code, 0,
        "files with embedded rules should succeed"
    );
    assert!(
        result.stdout.contains("embedded"),
        "Should indicate embedded source: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("Total:"),
        "Should show totals: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_init_creates_files() {
    let dir = tempfile::TempDir::new().unwrap();
    let home = dir.path().to_string_lossy().to_string();

    let result = run_subcommand_with_home(&["init"], &home);
    assert_eq!(
        result.exit_code, 0,
        "init should succeed: stderr={}",
        result.stderr
    );

    let config_dir = dir.path().join(".config").join("longline");
    assert!(
        config_dir.join("rules.yaml").exists(),
        "rules.yaml should exist"
    );
    assert!(config_dir.join("core-allowlist.yaml").exists());
    assert!(config_dir.join("git.yaml").exists());

    let content = std::fs::read_to_string(config_dir.join("rules.yaml")).unwrap();
    assert!(content.contains("include:"), "Should be a rules manifest");
}

#[test]
fn test_e2e_init_refuses_if_exists() {
    let dir = tempfile::TempDir::new().unwrap();
    let home = dir.path().to_string_lossy().to_string();

    let result1 = run_subcommand_with_home(&["init"], &home);
    assert_eq!(result1.exit_code, 0);

    let result2 = run_subcommand_with_home(&["init"], &home);
    assert_eq!(
        result2.exit_code, 1,
        "Second init should fail: stderr={}",
        result2.stderr
    );
    assert!(
        result2.stderr.contains("already exists"),
        "Should mention already exists: {}",
        result2.stderr
    );
}

#[test]
fn test_e2e_init_force_overwrites() {
    let dir = tempfile::TempDir::new().unwrap();
    let home = dir.path().to_string_lossy().to_string();

    let result1 = run_subcommand_with_home(&["init"], &home);
    assert_eq!(result1.exit_code, 0);

    let result2 = run_subcommand_with_home(&["init", "--force"], &home);
    assert_eq!(result2.exit_code, 0, "Force init should succeed");
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
fn test_e2e_check_with_dir_uses_project_rules() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("longline.yaml"),
        r#"
rules:
  - id: project-ask-on-push
    level: high
    match:
      command: git
      args:
        any_of: ["push"]
    decision: ask
    reason: "Requires approval before pushing"
"#,
    )
    .unwrap();

    let cmd_file = dir.path().join("cmds.txt");
    std::fs::write(&cmd_file, "git push origin main\n").unwrap();

    let result = run_subcommand(&[
        "check",
        "--config",
        &rules_path(),
        "--dir",
        dir.path().to_str().unwrap(),
        cmd_file.to_str().unwrap(),
    ]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("project-ask-on-push"),
        "Should match project rule: {}",
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

    let home = common::static_test_home().to_string_lossy().to_string();
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
fn test_e2e_files_with_dir_shows_project_config() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("longline.yaml"),
        r#"
rules:
  - id: files-test-rule
    level: high
    match:
      command: mytool
    decision: ask
    reason: "Files test"
"#,
    )
    .unwrap();

    let result = run_subcommand(&[
        "files",
        "--config",
        &rules_path(),
        "--dir",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("Project config:"),
        "Should show project config info: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("rules: 1"),
        "Should show project rule count: {}",
        result.stdout
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
fn test_e2e_files_shows_global_config() {
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
        "override_safety_level: strict\ndisable_rules:\n  - chmod-777\n",
    )
    .unwrap();

    let home_str = home.path().to_string_lossy().to_string();
    let result = run_subcommand_with_home(&["files"], &home_str);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("Global config:"),
        "Should show global config banner: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("override_safety_level: strict"),
        "Should show safety level override: {}",
        result.stdout
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

#[test]
fn test_e2e_files_no_global_config_no_banner() {
    let home = tempfile::TempDir::new().unwrap();
    let config_dir = home.path().join(".config").join("longline");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("ai-judge.yaml"),
        "command: /definitely-not-a-real-ai-judge-command-12345\ntimeout: 1\n",
    )
    .unwrap();
    // No longline.yaml

    let home_str = home.path().to_string_lossy().to_string();
    let result = run_subcommand_with_home(&["files"], &home_str);
    assert_eq!(result.exit_code, 0);
    assert!(
        !result.stdout.contains("Global config:"),
        "Should NOT show global config banner when no file: {}",
        result.stdout
    );
}
