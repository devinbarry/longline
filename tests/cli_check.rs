mod support;
use std::path::PathBuf;
use support::cli::{run_subcommand, run_subcommand_with_home};
use support::paths::rules_path;

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
fn test_e2e_check_labels_opaque_ask() {
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("cmds.txt");
    std::fs::write(
        &file,
        "bash tests/scripts/test_check_annotated_tags.sh; echo \"exit=$?\"\n",
    )
    .unwrap();

    let result = run_subcommand(&["check", "--config", &rules_path(), file.to_str().unwrap()]);
    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.contains("(opaque)"),
        "Should label opaque policy asks: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_check_profile_accepts_inline_command() {
    let home = tempfile::TempDir::new().unwrap();
    let config_dir = home.path().join(".config").join("longline");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("longline.yaml"),
        r#"
profiles:
  strict-smoke:
    safety_level: strict
    rules:
      - id: strict-smoke-test-rule
        level: high
        match:
          command: strict-smoke-command
        decision: ask
        reason: strict smoke profile rule
"#,
    )
    .unwrap();

    let home_str = home.path().to_string_lossy().to_string();
    let result = run_subcommand_with_home(
        &["check", "--profile", "strict-smoke", "strict-smoke-command"],
        &home_str,
    );

    assert_eq!(result.exit_code, 0, "stderr={}", result.stderr);
    assert!(
        result.stdout.contains("strict-smoke-command"),
        "stdout should include inline command: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("strict-smoke-test-rule"),
        "stdout should include profile rule id: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("ask"),
        "stdout should include ask decision: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_check_missing_txt_file_still_fails() {
    let result = run_subcommand(&["check", "definitely-missing-longline-file.txt"]);
    assert_eq!(result.exit_code, 1);
    assert!(
        result
            .stderr
            .contains("Failed to read definitely-missing-longline-file.txt"),
        "stderr should preserve missing-file error: {}",
        result.stderr
    );
}
