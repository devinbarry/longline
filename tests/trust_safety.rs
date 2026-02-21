mod common;
use common::{run_hook, run_hook_with_flags};

#[test]
fn test_e2e_trust_level_minimal_restricts_allowlist() {
    let result = run_hook_with_flags(
        "Bash",
        "git push origin main",
        &["--trust-level", "minimal"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_e2e_trust_level_minimal_allows_readonly() {
    let result = run_hook_with_flags("Bash", "ls -la", &["--trust-level", "minimal"]);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_e2e_trust_level_full_allows_full_tier() {
    let result = run_hook_with_flags("Bash", "git gc", &["--trust-level", "full"]);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_e2e_trust_level_full_allows_git_push() {
    let result = run_hook_with_flags(
        "Bash",
        "git push origin feature-branch",
        &["--trust-level", "full"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_e2e_trust_level_full_still_asks_force_push() {
    let result = run_hook_with_flags(
        "Bash",
        "git push --force origin feature-branch",
        &["--trust-level", "full"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_e2e_trust_level_full_still_asks_force_with_lease() {
    let result = run_hook_with_flags(
        "Bash",
        "git push --force-with-lease origin feature-branch",
        &["--trust-level", "full"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_e2e_trust_level_standard_asks_git_push() {
    let result = run_hook("Bash", "git push origin main");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_e2e_safety_level_flag_overrides_config() {
    // chmod 777 is a "high" level rule - should be skipped at critical safety level
    let result = run_hook_with_flags("Bash", "chmod 777 /tmp/f", &["--safety-level", "critical"]);
    assert_eq!(result.exit_code, 0);
    result.assert_reason_not_contains("chmod-777");
}
