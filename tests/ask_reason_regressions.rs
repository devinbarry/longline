use longline::domain::Decision;
use longline::parser;
use longline::policy;
use std::path::PathBuf;

fn rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("rules")
        .join("rules.yaml")
}

fn evaluate(command: &str) -> longline::domain::PolicyResult {
    let config = policy::load_rules(&rules_path()).expect("load rules");
    let stmt = parser::parse(command).expect("parse command");
    policy::evaluate(&config, &stmt)
}

fn assert_ask_reason(command: &str, rule_id: &str, reason: &str) {
    let result = evaluate(command);
    assert_eq!(result.decision, Decision::Ask, "{command}");
    assert_eq!(result.rule_id.as_deref(), Some(rule_id), "{command}");
    assert_eq!(result.reason, reason, "{command}");
}

fn assert_allow(command: &str) {
    let result = evaluate(command);
    assert_eq!(result.decision, Decision::Allow, "{command}: {result:?}");
}

fn assert_ask_not_default(command: &str) {
    let result = evaluate(command);
    assert_eq!(result.decision, Decision::Ask, "{command}");
    assert_ne!(
        result.reason, "No matching rule; using default decision",
        "{command}"
    );
}

fn assert_reason_not_default(command: &str) {
    let result = evaluate(command);
    assert_ne!(
        result.reason, "No matching rule; using default decision",
        "{command}: {result:?}"
    );
}

fn assert_not_rule(command: &str, rule_id: &str) {
    let result = evaluate(command);
    assert_ne!(result.rule_id.as_deref(), Some(rule_id), "{command}");
}

fn assert_ask_not_rule(command: &str, rule_id: &str) {
    let result = evaluate(command);
    assert_eq!(result.decision, Decision::Ask, "{command}: {result:?}");
    assert_ne!(result.rule_id.as_deref(), Some(rule_id), "{command}");
}

fn assert_deny_reason(command: &str, rule_id: &str, reason: &str) {
    let result = evaluate(command);
    assert_eq!(result.decision, Decision::Deny, "{command}: {result:?}");
    assert_eq!(result.rule_id.as_deref(), Some(rule_id), "{command}");
    assert_eq!(result.reason, reason, "{command}");
}

#[test]
fn yaml_safe_descriptive_ask_reasons() {
    assert_ask_reason(
        "rm src/afterhours/hook_handler.py",
        "rm-generic",
        "Deletes files or directories",
    );
    assert_ask_reason("kill -TERM 12345", "kill-process", "Terminates processes");
    assert_ask_reason("killall pytest", "kill-process", "Terminates processes");
    assert_ask_reason(
        "pkill -f pytest",
        "pkill-pattern",
        "Terminates processes matching a pattern",
    );
    assert_ask_reason(
        "chmod +x script.sh",
        "chmod-modify",
        "Changes file permissions",
    );
}

#[test]
fn rust_descriptive_ask_reasons() {
    assert_ask_reason(
        "tmux kill-session -t codex-review",
        "tmux-mutate",
        "Modifies tmux sessions or panes",
    );
    assert_ask_reason(
        "uv tool install --force .",
        "uv-tool-install",
        "Installs or replaces a uv tool",
    );
    assert_ask_reason(
        "uv version --bump patch",
        "uv-version-bump",
        "Modifies project version metadata",
    );
    assert_ask_reason(
        "uv remove pytz",
        "uv-remove",
        "Removes a project dependency",
    );
    assert_ask_reason(
        "python script.py",
        "python-exec",
        "Runs arbitrary Python code or scripts",
    );
    assert_ask_reason(
        "python -c 'print(1)'",
        "python-exec",
        "Runs arbitrary Python code or scripts",
    );
    assert_ask_reason(
        "node script.js",
        "node-exec",
        "Runs arbitrary JavaScript code or scripts",
    );
    assert_ask_reason(
        "source /tmp/codex-review-paths.env",
        "source-shell-file",
        "Loads shell code into the current shell",
    );
    assert_ask_reason(
        "wait",
        "shell-job-control",
        "Uses shell job-control or polling constructs",
    );
    assert_ask_reason(
        "just notebook",
        "just-unknown-recipe",
        "Runs a project recipe not in the allowlist",
    );
    assert_ask_reason(
        "./scripts/with-rpc-url.sh uv run python scripts/v060_migrate.py",
        "project-script-exec",
        "Runs a project-local script",
    );
}

#[test]
fn descriptive_rules_do_not_overmatch_existing_allows() {
    assert_allow("python --version");
    assert_allow("python -m pytest tests/");
    assert_allow("uv run pytest tests/");
    assert_allow("uv run ruff check src/");
    assert_allow("node --version");
    assert_allow("just --list");
    assert_allow("just check");
    assert_allow("tmux list-sessions");
    assert_allow("tmux capture-pane -t session -p");
    assert_allow("PATH=/tmp gh pr view 123");
    assert_allow("command gh pr view 123");
}

#[test]
fn gh_suspicious_wrapper_uses_executed_command_position() {
    assert_ask_reason(
        "exec -a gh gh api repos/foo",
        "gh-suspicious-wrapper",
        "GitHub CLI invocation uses an untrusted wrapper or environment shape",
    );
    assert_ask_reason(
        "exec -ca gh gh api repos/foo",
        "gh-suspicious-wrapper",
        "GitHub CLI invocation uses an untrusted wrapper or environment shape",
    );
    assert_ask_reason(
        "exec -la gh gh api repos/foo",
        "gh-suspicious-wrapper",
        "GitHub CLI invocation uses an untrusted wrapper or environment shape",
    );
    assert_ask_reason(
        "exec -cla gh gh api repos/foo",
        "gh-suspicious-wrapper",
        "GitHub CLI invocation uses an untrusted wrapper or environment shape",
    );
    assert_ask_reason(
        "exec -agh gh api repos/foo",
        "gh-suspicious-wrapper",
        "GitHub CLI invocation uses an untrusted wrapper or environment shape",
    );
    assert_ask_reason(
        "exec -agh gh release view v1",
        "gh-suspicious-wrapper",
        "GitHub CLI invocation uses an untrusted wrapper or environment shape",
    );
    assert_ask_reason(
        "exec -afoo gh api repos/foo",
        "gh-suspicious-wrapper",
        "GitHub CLI invocation uses an untrusted wrapper or environment shape",
    );
    assert_ask_reason(
        "exec -cafoo gh api repos/foo",
        "gh-suspicious-wrapper",
        "GitHub CLI invocation uses an untrusted wrapper or environment shape",
    );
    assert_ask_reason(
        "stdbuf -o gh gh api repos/foo",
        "gh-suspicious-wrapper",
        "GitHub CLI invocation uses an untrusted wrapper or environment shape",
    );

    assert_not_rule("exec echo gh api", "gh-suspicious-wrapper");
    assert_not_rule("stdbuf -oL echo gh api", "gh-suspicious-wrapper");
}

#[test]
fn existing_specific_ask_rules_are_not_shadowed() {
    assert_ask_reason(
        "chmod 777 /tmp/file",
        "chmod-777",
        "Setting world-writable permissions",
    );
    assert_ask_reason(
        "kill -9 12345",
        "kill-signal",
        "Forceful process termination",
    );
    assert_ask_reason(
        "find . -name '*.o' -exec rm {} \\;",
        "find-exec-rm",
        "find -exec with rm can delete files",
    );
    assert_ask_reason(
        "xargs rm -rf",
        "xargs-rm",
        "xargs executing rm on piped input",
    );
}

#[test]
fn current_recent_examples_no_longer_use_default_reason() {
    assert_ask_not_default("kill -TERM 25455 25457 25947");
    assert_ask_not_default("rm src/afterhours/hook_handler.py && ls src/afterhours/hook_handler/");
    assert_reason_not_default(
        "find docs -maxdepth 2 -type d -exec sh -c 'echo \"=== {} ===\"; ls \"{}\" | head -20' \\;",
    );
}

#[test]
fn find_xargs_shell_c_preserves_r7_boundaries() {
    for command in [
        "find . -exec sh -c 'gh api repos/foo' sh {} \\;",
        "xargs sh -c 'gh api repos/foo'",
        "find . -exec sh -c 'gh release view v1' sh {} \\;",
        "xargs sh -c 'gh release view v1'",
    ] {
        assert_ask_not_rule(command, "gh-readonly-classifier");
    }
}

#[test]
fn find_xargs_shell_c_surfaces_dangerous_inner_command() {
    for command in [
        "find . -exec sh -c 'rm -rf /' sh {} \\;",
        "xargs sh -c 'rm -rf /'",
        "timeout 1 find . -exec sh -c 'rm -rf /' sh {} \\;",
        "command find . -exec sh -c 'rm -rf /' sh {} \\;",
        "timeout 1 xargs sh -c 'rm -rf /'",
        "command xargs sh -c 'rm -rf /'",
        "find . -exec xargs sh -c 'rm -rf /' \\;",
        "find . -exec command xargs sh -c 'rm -rf /' \\;",
        "find . -exec timeout 1 xargs sh -c 'rm -rf /' \\;",
        "xargs find . -exec sh -c 'rm -rf /' sh {} \\;",
        "find . -exec sh -c 'xargs sh -c \"rm -rf /\"' \\;",
        "sh -c 'find . -exec xargs sh -c \"rm -rf /\" \\;'",
        "sh -c 'xargs find . -exec sh -c \"rm -rf /\" sh {} \\;'",
    ] {
        assert_deny_reason(
            command,
            "rm-recursive-root",
            "Recursive delete targeting root filesystem",
        );
    }
}

#[test]
fn redirected_shell_c_wrappers_deny_sensitive_writes_via_new_rule() {
    for command in [
        "bash -c 'cat README.md' > ~/.ssh/authorized_keys",
        "find . -exec sh -c 'cat README.md' sh {} \\; > ~/.ssh/authorized_keys",
        "xargs sh -c 'cat README.md' > ~/.ssh/authorized_keys",
    ] {
        assert_deny_reason(
            command,
            "redirect-write-ssh-authorized-keys",
            "Redirect write to SSH authorized_keys",
        );
    }
}

#[test]
fn shell_c_redirect_still_fires_on_non_sensitive_file_target() {
    // Catch-all preservation: any wrapper redirect to a non-sensitive
    // file target still ASKs via shell-c-redirect.
    assert_ask_reason(
        "bash -c 'echo hi' > /tmp/foo",
        "shell-c-redirect",
        "Shell command wrapper output is redirected",
    );
}

#[test]
fn opaque_shell_message_is_actionable() {
    let result = evaluate("bash tests/scripts/test_check_annotated_tags.sh; echo \"exit=$?\"");

    assert_eq!(result.decision, Decision::Ask);
    assert_eq!(result.rule_id, None);
    assert_eq!(
        result.reason,
        "Shell syntax is too complex to analyze safely"
    );
}

// ---------------------------------------------------------------------------
// Reason attribution: when an inner leaf (substitution / wrapper-extracted)
// causes the all-covered gate to flip to ask, the surfaced reason must name
// the *deciding* leaf rather than report the outer allowlisted command's
// description. The misleading-reason bug was reported on
// `afterhours say target "...\`_correlation.py\`..."` where the surfaced
// reason was "Local tmux session supervisor" (the afterhours allowlist
// description) even though the actual flip was caused by the unknown
// _correlation.py command-substitution leaf.
// ---------------------------------------------------------------------------

#[test]
fn substitution_leaf_reason_names_inner_command() {
    // mkdir is allowlisted with reason "Creates directories"; the embedded
    // $(unknown_cmd_xyz) is an unknown command-substitution leaf that flips
    // the decision to ask. The reason must name unknown_cmd_xyz, not surface
    // the outer mkdir reason.
    let result = evaluate("mkdir -p \"foo/$(unknown_cmd_xyz)/bar\"");
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        !result.reason.contains("Creates directories"),
        "reason must not surface outer allowlist description: {}",
        result.reason
    );
    assert!(
        result.reason.contains("unknown_cmd_xyz"),
        "reason must name the uncovered substitution leaf: {}",
        result.reason
    );
}

#[test]
fn substitution_leaf_reason_names_inner_command_backtick() {
    // Same shape as the original bug report: backticks inside a double-quoted
    // argument trigger command substitution and the inner unknown command
    // flips the decision.
    let result = evaluate("mkdir -p \"foo/`unknown_cmd_xyz`/bar\"");
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        !result.reason.contains("Creates directories"),
        "reason must not surface outer allowlist description: {}",
        result.reason
    );
    assert!(
        result.reason.contains("unknown_cmd_xyz"),
        "reason must name the uncovered substitution leaf: {}",
        result.reason
    );
}

#[test]
fn wrapper_extra_leaf_reason_names_inner_command() {
    // nohup is allowlisted with reason "Runs a command immune to hangup
    // signals" and is a transparent wrapper. The inner unknown_cmd_xyz is
    // unwrapped into extra_leaves and is uncovered. The reason must name the
    // inner command, not the wrapper's allowlist description.
    let result = evaluate("nohup unknown_cmd_xyz");
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        !result.reason.contains("immune to hangup signals"),
        "reason must not surface wrapper allowlist description: {}",
        result.reason
    );
    assert!(
        result.reason.contains("unknown_cmd_xyz"),
        "reason must name the uncovered inner leaf: {}",
        result.reason
    );
}

#[test]
fn bare_assignment_substitution_reason_names_inner_command() {
    // Bare assignment with embedded substitution: `VAR=$(unknown_cmd)`. The
    // original SimpleCommand leaf has cmd.name = None (bare assignment), so
    // the priority-walker would naively format "Unrecognized command" with
    // no name. The deciding leaf is actually the substitution; the walker
    // must skip the nameless original and surface the substitution leaf.
    // Flagged by Codex review of the initial fix.
    let result = evaluate("VAR=$(unknown_cmd_xyz)");
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        result.reason.contains("unknown_cmd_xyz"),
        "reason must name the inner substitution, not the nameless outer: {}",
        result.reason
    );
}

#[test]
fn find_exec_inner_unknown_uses_inner_command_prefix() {
    // find -exec extracts the inner via a different path than transparent
    // wrapper unwrap (nohup, env, …). Lock that the extras-bucket reason
    // still surfaces with "Unrecognized inner command:".
    let result = evaluate("find . -exec unknown_cmd_xyz {} \\;");
    assert_eq!(result.decision, Decision::Ask);
    assert_eq!(
        result.reason, "Unrecognized inner command: unknown_cmd_xyz",
        "find -exec inner uncovered should surface as inner command: {}",
        result.reason
    );
}

#[test]
fn process_substitution_in_redirect_target_names_inner() {
    // `cat > >(unknown_cmd_xyz)` puts the unknown inside a process-substitution
    // redirect target. The substitution leaf must be collected and the reason
    // must name it as a command substitution.
    let result = evaluate("cat > >(unknown_cmd_xyz)");
    assert_eq!(result.decision, Decision::Ask);
    assert_eq!(
        result.reason, "Unrecognized command substitution: unknown_cmd_xyz",
        "<() in redirect target should surface as command substitution: {}",
        result.reason
    );
}

#[test]
fn outer_and_inner_both_unknown_surfaces_outer_first() {
    // When BOTH an outer and an inner substitution are uncovered, the
    // priority-walker surfaces the outer (originals > extras > substitutions).
    // Locks the bucket-priority decision in. Codex review suggested this
    // explicit regression test.
    let result = evaluate("unknown_outer_xyz \"$(unknown_inner_xyz)\"");
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        result.reason.contains("unknown_outer_xyz"),
        "originals bucket has priority — outer must be surfaced: {}",
        result.reason
    );
    assert!(
        !result.reason.contains("unknown_inner_xyz"),
        "inner substitution must NOT bleed in when an outer is also uncovered: {}",
        result.reason
    );
}
