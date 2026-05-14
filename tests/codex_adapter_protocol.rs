mod support;

use serde_json::json;
use support::bin::run_longline;
use support::codex::CodexRunResultExt;
use support::config::TestEnv;

fn codex_input(event: &str, tool_name: &str, command: &str) -> String {
    json!({
        "hook_event_name": event,
        "tool_name": tool_name,
        "tool_input": {"command": command},
        "session_id": "test",
        "cwd": "/tmp"
    })
    .to_string()
}

fn codex_input_no_command(event: &str, tool_name: &str) -> String {
    json!({
        "hook_event_name": event,
        "tool_name": tool_name,
        "tool_input": {},
        "session_id": "test",
        "cwd": "/tmp"
    })
    .to_string()
}

fn run_codex(env: &TestEnv, input: &str) -> support::result::RunResult {
    run_longline(&["hook", "codex"], env.home_path(), Some(input))
}

#[test]
fn corrupt_rules_manifest_codex_fail_open() {
    let env = TestEnv::new().build();
    // Write a corrupt rules manifest at ~/.config/longline/rules.yaml
    let rules_dir = env.home_path().join(".config/longline");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("rules.yaml"), "this is: not [valid").unwrap();

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"}
    })
    .to_string();
    let result = run_longline(&["hook", "codex"], env.home_path(), Some(&input));

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(result.stdout, "");
    assert!(
        result.stderr.contains("rules.yaml"),
        "stderr should name rules.yaml, got: {}",
        result.stderr
    );
}

#[test]
fn corrupt_rules_manifest_claude_keeps_exit_2() {
    let env = TestEnv::new().build();
    let rules_dir = env.home_path().join(".config/longline");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("rules.yaml"), "this is: not [valid").unwrap();

    let input = json!({
        "tool_name": "Bash",
        "tool_input": {"command": "ls"}
    })
    .to_string();
    let result = run_longline(&["hook", "claude"], env.home_path(), Some(&input));

    assert_eq!(result.exit_code, 2);
}

#[test]
fn corrupt_rules_manifest_check_keeps_exit_2() {
    let env = TestEnv::new().build();
    let rules_dir = env.home_path().join(".config/longline");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("rules.yaml"), "this is: not [valid").unwrap();

    let result = run_longline(&["check"], env.home_path(), Some("ls"));
    assert_eq!(result.exit_code, 2);
}

// ---------- Layer 2: Bash happy paths ----------

#[test]
fn pre_tool_use_bash_safe_returns_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "ls"));
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

#[test]
fn pre_tool_use_bash_dangerous_returns_deny_json() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "rm -rf /"));
    assert_eq!(result.exit_code, 0);
    assert_eq!(
        result.codex_pre_tool_use_decision().as_deref(),
        Some("deny"),
        "stdout: {:?}",
        result.stdout
    );
    let reason = result.codex_pre_tool_use_reason().unwrap_or_default();
    assert!(
        !reason.is_empty(),
        "deny must include non-empty permissionDecisionReason; stdout: {:?}",
        result.stdout
    );
}

#[test]
fn pre_tool_use_bash_ambiguous_returns_no_decision() {
    let env = TestEnv::new().build();
    // python -c 'import os' triggers ask via the AI judge / interpreter rules
    let result = run_codex(
        &env,
        &codex_input("PreToolUse", "Bash", "python -c 'import os'"),
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
}

#[test]
fn permission_request_bash_safe_returns_allow_behavior() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PermissionRequest", "Bash", "ls"));
    assert_eq!(result.exit_code, 0);
    result.assert_codex_permission_request_behavior("allow");
}

#[test]
fn permission_request_bash_dangerous_returns_deny_behavior_with_message() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PermissionRequest", "Bash", "rm -rf /"));
    assert_eq!(result.exit_code, 0);
    result.assert_codex_permission_request_behavior("deny");
    let msg = result
        .codex_permission_request_message()
        .unwrap_or_default();
    assert!(
        !msg.is_empty(),
        "PermissionRequest deny should carry a message; stdout: {:?}",
        result.stdout
    );
}

#[test]
fn permission_request_bash_ambiguous_returns_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(
        &env,
        &codex_input("PermissionRequest", "Bash", "python -c 'import os'"),
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
}

// ---------- Layer 2: passthrough ----------

#[test]
fn pre_tool_use_apply_patch_passthrough_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input_no_command("PreToolUse", "apply_patch"));
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

#[test]
fn permission_request_mcp_tool_passthrough_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(
        &env,
        &codex_input_no_command("PermissionRequest", "mcp__filesystem__read_file"),
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

#[test]
fn post_tool_use_passthrough_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PostToolUse", "Bash", "ls"));
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

#[test]
fn session_start_passthrough_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, r#"{"hook_event_name":"SessionStart"}"#);
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

#[test]
fn unknown_event_passthrough_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, r#"{"hook_event_name":"FutureCodexEvent"}"#);
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

// ---------- Layer 2: malformed input ----------

#[test]
fn malformed_json_returns_no_decision_with_stderr() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, "{this is not json");
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert!(
        result.stderr.contains("longline:"),
        "stderr: {:?}",
        result.stderr
    );
}

#[test]
fn missing_event_name_returns_no_decision_with_stderr() {
    let env = TestEnv::new().build();
    let result = run_codex(
        &env,
        r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert!(
        result.stderr.contains("longline:"),
        "stderr: {:?}",
        result.stderr
    );
}

// ---------- Layer 2: fail-open observability (per source) ----------

#[test]
fn corrupt_global_config_codex_fail_open_writes_jsonl() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: not-a-real-level\n")
        .build();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "ls"));
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    result.assert_codex_no_decision();
    assert!(
        result.stderr.contains("longline:"),
        "stderr: {:?}",
        result.stderr
    );

    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["parse_ok"], false);
    assert_eq!(entry["decision"], "allow");
    assert!(entry["reason"].as_str().unwrap().contains("config"));
}

#[test]
fn corrupt_project_config_codex_fail_open_writes_jsonl() {
    let env = TestEnv::new()
        .with_project_config("override_safety_level: not-a-real-level\n")
        .build();
    let project_path = env.project_path().to_string_lossy().to_string();
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "session_id": "test",
        "cwd": project_path,
    })
    .to_string();
    let result = run_codex(&env, &input);
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    result.assert_codex_no_decision();

    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["parse_ok"], false);
    assert_eq!(entry["decision"], "allow");
}

#[test]
fn corrupt_rules_manifest_codex_fail_open_writes_jsonl() {
    let env = TestEnv::new().build();
    let rules_dir = env.home_path().join(".config/longline");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("rules.yaml"), "this is: not [valid").unwrap();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "ls"));
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    result.assert_codex_no_decision();
    assert!(
        result.stderr.contains("rules.yaml"),
        "stderr should name file path, got {:?}",
        result.stderr
    );

    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["parse_ok"], false);
    assert_eq!(entry["decision"], "allow");
    assert!(entry["reason"].as_str().unwrap().contains("rules manifest"));
}

// ---------- Layer 2: runtime field ----------

#[test]
fn codex_log_entry_includes_runtime_field() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "rm -rf /"));
    assert_eq!(result.exit_code, 0);
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("log file exists");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["tool"], "Bash");
    assert_eq!(entry["decision"], "deny");
}

// Spec §Audit Log Layout commits to standard `session_id` on fail-open
// rows whenever the input contained a parseable session_id. Round-3
// review caught that non-panic fail-open paths (config-finalize fail,
// malformed-input) were dropping it. These tests lock in that the
// session_id survives both paths.

#[test]
fn fail_open_global_config_preserves_session_id() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: not-a-real-level\n")
        .build();
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "session_id": "session-fail-open-global",
        "cwd": "/tmp"
    })
    .to_string();
    let result = run_codex(&env, &input);
    assert_eq!(result.exit_code, 0);
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["parse_ok"], false);
    assert_eq!(entry["session_id"], "session-fail-open-global");
}

// ---------- Task 11: phased panic guards + pre/post-resolution profile sentinels ----------
//
// The Codex adapter runs profile resolution inside a Phase-1 catch_unwind
// (around finalize_config). On any pre-resolution failure (panic, Err,
// unknown profile name, malformed input, bad rules manifest), the fail-open
// audit entry MUST carry profile="unresolved" -- the resolved name is
// unknown at that point. On the success path, the resolved profile name
// (e.g. "default", "strict") MUST flow through to the audit entry and
// MUST NOT be "unresolved".

#[test]
fn codex_unknown_profile_fails_open_with_unresolved() {
    // --profile ghost where no profile named "ghost" exists.
    // resolve_profile_name returns "ghost", then finalize_config rejects
    // it as unknown -> pre-resolution Err -> fail-open with "unresolved".
    let env = TestEnv::new().build();
    let result = run_longline(
        &["hook", "codex", "--profile", "ghost"],
        env.home_path(),
        Some(&codex_input("PreToolUse", "Bash", "ls")),
    );
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(result.stdout, "");
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(
        entry["profile"], "unresolved",
        "unknown profile must produce profile=unresolved; entry={entry}"
    );
}

#[test]
fn codex_malformed_input_fail_open_uses_unresolved() {
    // Pre-resolution failure: stdin is not valid JSON. The Malformed
    // branch in run_hook_input writes the fail-open audit entry with
    // profile="unresolved" because finalize_config never ran.
    let env = TestEnv::new().build();
    let result = run_codex(&env, "this is not valid json at all");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["profile"], "unresolved");
    assert_eq!(entry["parse_ok"], false);
}

#[test]
fn codex_bad_rules_manifest_fail_open_uses_unresolved() {
    // Pre-resolution failure: --config points at a corrupt rules manifest.
    // The cli.rs codex-hook fail-open path fires BEFORE finalize_config
    // can resolve a profile, so profile="unresolved".
    let env = TestEnv::new().build();
    let manifest = env.home_path().join("bad-rules.yaml");
    std::fs::write(&manifest, "{ this is not valid yaml at all !!! :::").unwrap();
    let manifest_str = manifest.to_string_lossy().to_string();
    let result = run_longline(
        &["--config", &manifest_str, "hook", "codex"],
        env.home_path(),
        Some(&codex_input("PreToolUse", "Bash", "ls")),
    );
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["profile"], "unresolved");
}

#[test]
fn codex_success_path_writes_resolved_profile_name() {
    // Post-resolution success: --profile strict resolves to a declared
    // profile. The audit entry must carry "strict", not "unresolved".
    let env = TestEnv::new()
        .with_global_config("profiles:\n  strict: {}\n")
        .build();
    // Use a Bash command that produces a deny -> guaranteed JSONL entry.
    let result = run_longline(
        &["hook", "codex", "--profile", "strict"],
        env.home_path(),
        Some(&codex_input("PreToolUse", "Bash", "rm -rf /")),
    );
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("audit log written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(
        entry["profile"], "strict",
        "resolved profile name must flow to audit entry; entry={entry}"
    );
    assert_ne!(entry["profile"], "unresolved");
}

#[test]
fn codex_global_duplicate_id_in_profile_fails_open_with_unresolved() {
    // Pre-resolution failure: a GLOBAL overlay declares profiles.strict
    // with duplicate rule ids. Because union.strict came from global,
    // any of the three global-touching validate_profiles calls in
    // finalize.rs ((1) and (2) with &union, (3) with &global_profiles)
    // catches the duplicate; whichever runs first wins. Fail-open
    // posture: exit 0, empty stdout, audit entry with profile="unresolved"
    // and a `reason` that names the duplicate id and profile.
    let global = r#"
profiles:
  strict:
    rules:
      - id: dup-id
        level: high
        match: { command: rm }
        decision: deny
        reason: "first"
      - id: dup-id
        level: high
        match: { command: rm }
        decision: deny
        reason: "second"
"#;
    let env = TestEnv::new().with_global_config(global).build();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "ls"));
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(result.stdout, "");
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["profile"], "unresolved");
    let reason = entry["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("config finalization failed"),
        "reason must name the finalization boundary; got: {reason}"
    );
    assert!(
        reason.contains("duplicate rule id"),
        "reason must name the duplicate-id check; got: {reason}"
    );
    assert!(
        reason.contains("strict") && reason.contains("dup-id"),
        "reason must name profile and id; got: {reason}"
    );
}

#[test]
fn codex_project_duplicate_id_in_profile_fails_open_with_unresolved() {
    // Pre-resolution failure: project overlay declares profiles.strict
    // with duplicate rule ids, but global declares profiles.strict: {}
    // (empty). union.strict resolves to the global empty entry (because
    // or_insert_with does not overwrite), so finalize.rs calls (1)-(3)
    // all pass; only call (4) validate_profiles(&project_profiles, None)
    // sees the duplicate-id project entry and errors. This forces the
    // test to exercise the per-overlay project validation path uniquely.
    // Removing the empty global entry would let the duplicate fire on
    // call (1) instead, making this test indistinguishable from the
    // global-side fixture.
    let global = "profiles:\n  strict: {}\n";
    let project = r#"
profiles:
  strict:
    rules:
      - id: dup-id
        level: high
        match: { command: rm }
        decision: deny
        reason: "first"
      - id: dup-id
        level: high
        match: { command: rm }
        decision: deny
        reason: "second"
"#;
    let env = TestEnv::new()
        .with_global_config(global)
        .with_project_config(project)
        .build();
    let project_path = env.project_path().to_string_lossy().to_string();
    let input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "session_id": "test",
        "cwd": project_path,
    })
    .to_string();
    let result = run_longline(&["hook", "codex"], env.home_path(), Some(&input));
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(result.stdout, "");
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["profile"], "unresolved");
    let reason = entry["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("config finalization failed"),
        "reason must name the finalization boundary; got: {reason}"
    );
    assert!(
        reason.contains("duplicate rule id"),
        "reason must name the duplicate-id check; got: {reason}"
    );
    assert!(
        reason.contains("strict") && reason.contains("dup-id"),
        "reason must name profile and id; got: {reason}"
    );
}

#[test]
fn test_codex_hook_profile_changes_outcome_and_audit_carries_profile() {
    let env = TestEnv::new()
        .with_global_config(
            r#"
profiles:
  strict:
    rules:
      - id: deny-myfictitioustool
        level: high
        match: { command: myfictitioustool }
        decision: deny
        reason: "strict denies myfictitioustool"
"#,
        )
        .build();

    let stdin = codex_input("PreToolUse", "Bash", "myfictitioustool --run");

    // Without profile: myfictitioustool is unrecognized -> ask -> empty stdout (no deny).
    let r_default = run_codex(&env, &stdin);
    assert_eq!(r_default.exit_code, 0);
    r_default.assert_codex_no_decision();

    // With --profile strict: the deny rule fires.
    let r_strict = run_longline(
        &["hook", "codex", "--profile", "strict"],
        env.home_path(),
        Some(&stdin),
    );
    assert_eq!(r_strict.exit_code, 0);
    assert_eq!(
        r_strict.codex_pre_tool_use_decision().as_deref(),
        Some("deny"),
        "strict profile must deny myfictitioustool; stdout: {:?}",
        r_strict.stdout
    );

    // Audit log must carry profile=strict and decision=deny.
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("codex audit log must exist");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(
        entry["profile"], "strict",
        "audit must carry profile=strict; entry={entry}"
    );
    assert_eq!(
        entry["decision"], "deny",
        "audit must carry decision=deny; entry={entry}"
    );
}

#[test]
fn fail_open_malformed_input_preserves_session_id() {
    let env = TestEnv::new().build();
    // Missing hook_event_name → Malformed action → fail-open with
    // best-effort session_id extraction from the parseable JSON.
    let input = json!({
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "session_id": "session-malformed-input",
        "cwd": "/tmp"
    })
    .to_string();
    let result = run_codex(&env, &input);
    assert_eq!(result.exit_code, 0);
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().rfind(|l| !l.is_empty()).unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["parse_ok"], false);
    assert_eq!(entry["session_id"], "session-malformed-input");
}
