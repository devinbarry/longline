mod support;
use support::cli::run_subcommand_with_home;

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
