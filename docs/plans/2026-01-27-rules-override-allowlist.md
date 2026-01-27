# Rules Override Allowlist - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the evaluation order so rules are checked before the allowlist. Currently `cat .env` returns `allow` because `cat` is on the bare allowlist and the allowlist check short-circuits before rules fire. After this change, rules always run first; the allowlist is only a fallback when no rule matches.

**Architecture:** Single function change in `evaluate_leaf` (policy.rs). No new types, no YAML format changes. Golden tests updated to reflect correct behavior.

**Tech Stack:** Rust (existing codebase)

---

## Task 1: Change evaluation order in `evaluate_leaf`

**Files:**
- Modify: `src/policy.rs:194-228`

**Step 1: Write a failing test proving the bug exists**

Add to the `#[cfg(test)]` block in `src/policy.rs`, after the existing tests:

```rust
#[test]
fn test_rules_override_allowlist() {
    // cat is on the allowlist, but cat .env should still be denied
    let yaml = r#"
version: 1
default_decision: ask
safety_level: high
allowlists:
  commands:
    - cat
    - head
    - tail
rules:
  - id: cat-env-file
    level: critical
    match:
      command:
        any_of: [cat, head, tail]
      args:
        any_of: [".env", ".env.local"]
    decision: deny
    reason: "Reading sensitive environment file"
"#;
    let config: RulesConfig = serde_yaml::from_str(yaml).unwrap();
    let stmt = parse("cat .env").unwrap();
    let result = evaluate(&config, &stmt);
    assert_eq!(result.decision, Decision::Deny, "Rules should override allowlist");
    assert_eq!(result.rule_id.as_deref(), Some("cat-env-file"));
}

#[test]
fn test_allowlist_still_works_when_no_rule_matches() {
    // cat README.md has no matching rule, so allowlist should apply
    let yaml = r#"
version: 1
default_decision: ask
safety_level: high
allowlists:
  commands:
    - cat
rules:
  - id: cat-env-file
    level: critical
    match:
      command: cat
      args:
        any_of: [".env"]
    decision: deny
    reason: "Reading sensitive environment file"
"#;
    let config: RulesConfig = serde_yaml::from_str(yaml).unwrap();
    let stmt = parse("cat README.md").unwrap();
    let result = evaluate(&config, &stmt);
    assert_eq!(result.decision, Decision::Allow, "Allowlist should work when no rule matches");
}
```

**Step 2: Run tests to confirm the first test fails**

Run: `cargo test test_rules_override_allowlist -- --nocapture`
Expected: FAIL -- currently returns `Allow` instead of `Deny`.

Run: `cargo test test_allowlist_still_works_when_no_rule_matches -- --nocapture`
Expected: PASS -- this behavior already works.

**Step 3: Fix `evaluate_leaf` to check rules first, allowlist second**

Replace the `evaluate_leaf` function (lines 194-228) with:

```rust
/// Evaluate a single leaf node (SimpleCommand or Opaque).
fn evaluate_leaf(config: &RulesConfig, leaf: &Statement) -> PolicyResult {
    match leaf {
        Statement::Opaque(_) => PolicyResult {
            decision: Decision::Ask,
            rule_id: None,
            reason: "Unrecognized command structure".to_string(),
        },
        Statement::SimpleCommand(cmd) => {
            // Check rules first -- rules always take priority
            let mut worst = PolicyResult::allow();
            for rule in &config.rules {
                if rule.level > config.safety_level {
                    continue;
                }
                if matches_rule(&rule.matcher, cmd) {
                    let result = PolicyResult {
                        decision: rule.decision,
                        rule_id: Some(rule.id.clone()),
                        reason: rule.reason.clone(),
                    };
                    if result.decision > worst.decision {
                        worst = result;
                    }
                }
            }

            // If a rule matched, return the rule result
            if worst.rule_id.is_some() {
                return worst;
            }

            // No rule matched -- check allowlist as fallback
            if is_command_allowlisted(config, cmd) {
                return PolicyResult::allow();
            }

            // Not allowlisted, no rule -- return allow (default_decision
            // handled by caller in evaluate())
            PolicyResult::allow()
        }
        _ => PolicyResult::allow(),
    }
}
```

**Step 4: Run the new tests to confirm they pass**

Run: `cargo test test_rules_override_allowlist test_allowlist_still_works -- --nocapture`
Expected: Both PASS.

**Step 5: Run the full unit test suite**

Run: `cargo test --lib`
Expected: The existing `test_evaluate_allowlisted_command` and `test_evaluate_ls_allowlisted` tests still pass (they use `git status` and `ls` which have no matching rules). Other unit tests unchanged.

**Step 6: Commit**

```
fix: evaluate rules before allowlist so rules can override safe commands
```

---

## Task 2: Update golden test expectations for secrets

**Files:**
- Modify: `tests/golden/secrets.yaml`

The following test cases currently expect `allow` because cat/head/tail are on the bare allowlist. After the fix, rules fire first.

**Step 1: Update `cat-env-file-allowlisted` (line 2-5)**

Change:
```yaml
  - id: cat-env-file-allowlisted
    command: "cat .env"
    expected:
      decision: allow
```
To:
```yaml
  - id: cat-env-file-denied
    command: "cat .env"
    expected:
      decision: deny
      rule_id: cat-env-file
```

**Step 2: Update `cat-env-allowlisted` (line 81-84)**

Change:
```yaml
  - id: cat-env-allowlisted
    command: "cat .env.local"
    expected:
      decision: allow
```
To:
```yaml
  - id: cat-env-local-denied
    command: "cat .env.local"
    expected:
      decision: deny
      rule_id: cat-env-file
```

**Step 3: Update `head-env-allowlisted` (line 85-88)**

Change:
```yaml
  - id: head-env-allowlisted
    command: "head .env"
    expected:
      decision: allow
```
To:
```yaml
  - id: head-env-denied
    command: "head .env"
    expected:
      decision: deny
      rule_id: cat-env-file
```

**Step 4: Update `tail-env-allowlisted` (line 89-92)**

Change:
```yaml
  - id: tail-env-allowlisted
    command: "tail .env"
    expected:
      decision: allow
```
To:
```yaml
  - id: tail-env-denied
    command: "tail .env"
    expected:
      decision: deny
      rule_id: cat-env-file
```

**Step 5: Update `cat-ssh-key-allowlisted` (line 108-111)**

Change:
```yaml
  - id: cat-ssh-key-allowlisted
    command: "cat ~/.ssh/id_rsa"
    expected:
      decision: allow
```
To:
```yaml
  - id: cat-ssh-key-denied
    command: "cat ~/.ssh/id_rsa"
    expected:
      decision: deny
      rule_id: cat-ssh-key
```

**Step 6: Run golden secrets tests**

Run: `cargo test golden_secrets`
Expected: PASS.

**Step 7: Commit**

```
fix: update secrets golden tests for rules-override-allowlist behavior
```

---

## Task 3: Update golden test expectations for git

**Files:**
- Modify: `tests/golden/git.yaml`

The `git branch -D feature-branch` test currently expects `allow` because `git branch` is on the multi-word allowlist. After the fix, the `git-branch-delete-force` rule fires first (it matches command `git` with args `branch` and flags `-D`).

**Step 1: Update `git-branch-D-allowlisted` (line 47-50)**

Change:
```yaml
  - id: git-branch-D-allowlisted
    command: "git branch -D feature-branch"
    expected:
      decision: allow
```
To:
```yaml
  - id: git-branch-D-ask
    command: "git branch -D feature-branch"
    expected:
      decision: ask
      rule_id: git-branch-delete-force
```

**Step 2: Run golden git tests**

Run: `cargo test golden_git`
Expected: PASS.

**Step 3: Commit**

```
fix: update git golden tests for rules-override-allowlist behavior
```

---

## Task 4: Run full test suite and verify

**Files:**
- None (verification only)

**Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass (unit, golden, integration).

**Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings.

**Step 3: Manual verification**

Run:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"cat .env"}}' | cargo run -- --config rules/default-rules.yaml
```
Expected: JSON with `"permissionDecision":"deny"` and rule_id `cat-env-file`.

Run:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"cat README.md"}}' | cargo run -- --config rules/default-rules.yaml
```
Expected: `{}` (allow -- cat is allowlisted, no rule matches).

Run:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | cargo run -- --config rules/default-rules.yaml
```
Expected: `{}` (allow -- ls is allowlisted, no rule matches).

**Step 4: Commit if any cleanup needed**

```
chore: verify rules-override-allowlist fix
```

---

## Summary

| Task | Component | Key Change |
|------|-----------|------------|
| 1 | policy.rs | Reorder evaluate_leaf: rules first, allowlist as fallback |
| 2 | secrets.yaml | 5 tests flip from allow to deny (cat/head/tail on secrets) |
| 3 | git.yaml | 1 test flips from allow to ask (git branch -D) |
| 4 | Verification | Full test suite, clippy, manual E2E |
