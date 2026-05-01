mod support;
use support::cli::{run_subcommand, run_subcommand_with_home};
use support::paths::rules_path;

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
