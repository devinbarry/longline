//! Integration tests for bare variable assignment handling.
//!
//! These test cases are derived from real commands observed in longline logs
//! that were incorrectly getting "ask" decisions due to bare assignments
//! not being recognized as safe.

mod common;
use common::run_hook;

// ---------------------------------------------------------------------------
// Simple bare assignments with safe substitutions
// ---------------------------------------------------------------------------

#[test]
fn test_bare_assign_date() {
    let result = run_hook("Bash", "VAR=$(date)");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_bare_assign_pwd() {
    let result = run_hook("Bash", "DIR=$(pwd)");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_bare_assign_plain_value() {
    let result = run_hook("Bash", "VAR=hello");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ---------------------------------------------------------------------------
// Real-world: test migration analysis script (from logs)
// Uses variable assignments with command substitutions in pipelines,
// then chained with comm comparisons using process substitution.
// ---------------------------------------------------------------------------

#[test]
fn test_real_world_test_migration_analysis() {
    // Simplified version of the real log entry: variable assignment with
    // git show piped through grep/sed/sort, then used in comm comparison
    let cmd = r#"OLD=$(git show HEAD:file.rs | grep -E '^\s*fn test_' | sed 's/.*fn //' | sed 's/(.*//' | sort) && echo "$OLD" | wc -l"#;
    let result = run_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ---------------------------------------------------------------------------
// Real-world: temp dir setup with mkdir (from logs)
// TMPDIR=$(mktemp -d) && mkdir -p "$TMPDIR/.git"
// ---------------------------------------------------------------------------

#[test]
fn test_real_world_tmpdir_setup() {
    let cmd = r#"TMPDIR=$(mktemp -d) && mkdir -p "$TMPDIR/.git""#;
    let result = run_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ---------------------------------------------------------------------------
// Real-world: for loop collecting results into variable (from logs)
// ---------------------------------------------------------------------------

#[test]
fn test_real_world_for_loop_with_grep() {
    let cmd = r#"for f in tests/hook_protocol.rs tests/subcommands.rs; do grep -E '^\s*fn test_' "$f" 2>/dev/null | sed 's/.*fn //' | sed 's/(.*//'; done | sort"#;
    let result = run_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ---------------------------------------------------------------------------
// Real-world: multiple variable assignments chained (from logs)
// ---------------------------------------------------------------------------

#[test]
fn test_real_world_multiple_assignments_chained() {
    let cmd = r#"OLD_TESTS=$(git show HEAD:tests/file.rs | grep -E '^\s*fn test_' | sed 's/.*fn //' | sed 's/(.*//' | sort) && NEW_TESTS=$(grep -rn 'fn test_' tests/ | sed 's/.*fn //' | sed 's/(.*//' | sort) && echo "Old:" && echo "$OLD_TESTS" | wc -l && echo "New:" && echo "$NEW_TESTS" | wc -l"#;
    let result = run_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ---------------------------------------------------------------------------
// Real-world: temp dir with heredoc config (from logs)
// ---------------------------------------------------------------------------

#[test]
fn test_real_world_tmpdir_with_heredoc() {
    let cmd = "TMPDIR=$(mktemp -d) && mkdir -p \"$TMPDIR/.git\" \"$TMPDIR/.claude\" && cat > \"$TMPDIR/.claude/config.yaml\" << 'EOF'\nkey: value\nEOF";
    let result = run_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ---------------------------------------------------------------------------
// Safety: dangerous substitutions in bare assignments must still deny
// ---------------------------------------------------------------------------

#[test]
fn test_bare_assign_dangerous_rm() {
    let result = run_hook("Bash", "VAR=$(rm -rf /)");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("deny");
}

#[test]
fn test_bare_assign_dangerous_cat_env() {
    let result = run_hook("Bash", "SECRET=$(cat .env)");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("deny");
}

#[test]
fn test_bare_assign_dangerous_cat_ssh_key() {
    let result = run_hook("Bash", "KEY=$(cat ~/.ssh/id_rsa)");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("deny");
}

// ---------------------------------------------------------------------------
// Safety: unknown commands in bare assignments should still ask
// ---------------------------------------------------------------------------

#[test]
fn test_bare_assign_unknown_command() {
    let result = run_hook("Bash", "VAR=$(unknown_tool)");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}
