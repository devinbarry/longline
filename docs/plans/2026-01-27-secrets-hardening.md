# Secrets Hardening - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close security gaps where allowlisted commands (`cp`, `mv`, `tee`) can interact with secrets files without triggering rules, and add missing safe commands to the allowlist.

**Architecture:** Add 4 new rules to `rules/default-rules.yaml` (cp-secrets, mv-secrets, tee-secrets, rm-secrets), add missing safe commands to the allowlist, and add golden test cases. No code changes -- only YAML edits.

**Tech Stack:** YAML rules, golden test YAML files

---

## Task 1: Add secrets rules for cp, mv, tee, rm

**Files:**
- Modify: `rules/default-rules.yaml`

**Step 1: Add new rules after the existing `cat-kube-config` rule (after line 217)**

Insert these rules into the `# CRITICAL: Secrets exposure` section, right after `cat-kube-config`:

```yaml
  - id: cp-secrets
    level: critical
    match:
      command: cp
      args:
        any_of: [".env", ".env.local", ".env.production", ".env.staging",
                  ".env.development", ".envrc", "**/.env", "**/.env.local",
                  "~/.ssh/id_*", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
                  "~/.ssh/id_ecdsa", "id_rsa", "id_ed25519", "id_ecdsa",
                  "~/.aws/credentials", "~/.aws/config",
                  "~/.kube/config"]
    decision: ask
    reason: "Copying sensitive file"

  - id: mv-secrets
    level: critical
    match:
      command: mv
      args:
        any_of: [".env", ".env.local", ".env.production", ".env.staging",
                  ".env.development", ".envrc", "**/.env", "**/.env.local",
                  "~/.ssh/id_*", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
                  "~/.ssh/id_ecdsa", "id_rsa", "id_ed25519", "id_ecdsa",
                  "~/.aws/credentials", "~/.aws/config",
                  "~/.kube/config"]
    decision: ask
    reason: "Moving sensitive file"

  - id: tee-secrets
    level: critical
    match:
      command: tee
      args:
        any_of: [".env", ".env.local", ".env.production", ".env.staging",
                  ".env.development", ".envrc", "**/.env", "**/.env.local",
                  "~/.ssh/id_*", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
                  "~/.ssh/id_ecdsa",
                  "~/.aws/credentials", "~/.aws/config",
                  "~/.kube/config"]
    decision: deny
    reason: "Writing to sensitive file via tee"

  - id: rm-secrets
    level: critical
    match:
      command: rm
      args:
        any_of: [".env", ".env.local", ".env.production", ".env.staging",
                  ".env.development", ".envrc",
                  "~/.ssh/id_*", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
                  "~/.ssh/id_ecdsa", "~/.ssh/authorized_keys",
                  "~/.aws/credentials", "~/.aws/config",
                  "~/.kube/config"]
    decision: ask
    reason: "Deleting sensitive file"
```

Design notes:
- `cp` and `mv` get `ask` (not `deny`) because moving/copying secrets is sometimes legitimate dev work (backups, key rotation).
- `tee` gets `deny` because writing arbitrary content to secrets files is almost always wrong.
- `rm` gets `ask` because deleting secrets is dangerous but sometimes intentional.
- Uses the same arg patterns as the existing `cat-*` rules for consistency.

**Step 2: Run existing tests to make sure nothing breaks**

Run: `cargo test`
Expected: All tests pass. The new rules don't affect any existing test cases because existing `cp`/`mv` golden tests use non-secrets paths.

**Step 3: Commit**

```
feat: add cp/mv/tee/rm rules for secrets files
```

---

## Task 2: Add missing safe commands to the allowlist

**Files:**
- Modify: `rules/default-rules.yaml`

**Step 1: Add missing commands to the allowlists.commands section**

Add these after the existing `# Safe read-only commands` entries (after `readlink`, before `true`):

```yaml
    - stat
    - du
    - printf
    - md5sum
    - sha256sum
    - sha1sum
    - cksum
    - "["
```

Note: `[` must be quoted in YAML because it's a special character.

**Step 2: Run existing tests**

Run: `cargo test`
Expected: All tests pass. These are additions to the allowlist, not changes.

**Step 3: Commit**

```
feat: add stat, du, printf, checksum commands to allowlist
```

---

## Task 3: Add golden tests for new secrets rules

**Files:**
- Modify: `tests/golden/secrets.yaml`

**Step 1: Add test cases at the end of the file**

Append to `tests/golden/secrets.yaml`:

```yaml
  # cp secrets
  - id: cp-env-ask
    command: "cp .env /tmp/backup.env"
    expected:
      decision: ask
      rule_id: cp-secrets
  - id: cp-env-local-ask
    command: "cp .env.local .env.local.bak"
    expected:
      decision: ask
      rule_id: cp-secrets
  - id: cp-ssh-key-ask
    command: "cp ~/.ssh/id_rsa /tmp/key"
    expected:
      decision: ask
      rule_id: cp-secrets
  - id: cp-aws-creds-ask
    command: "cp ~/.aws/credentials /tmp/creds"
    expected:
      decision: ask
      rule_id: cp-secrets
  - id: cp-safe-file-allow
    command: "cp README.md /tmp/readme.bak"
    expected:
      decision: allow
  # mv secrets
  - id: mv-env-ask
    command: "mv .env .env.old"
    expected:
      decision: ask
      rule_id: mv-secrets
  - id: mv-ssh-key-ask
    command: "mv ~/.ssh/id_rsa ~/.ssh/id_rsa.bak"
    expected:
      decision: ask
      rule_id: mv-secrets
  - id: mv-safe-file-allow
    command: "mv old.txt new.txt"
    expected:
      decision: allow
  # tee secrets
  - id: tee-env-deny
    command: "tee .env"
    expected:
      decision: deny
      rule_id: tee-secrets
  - id: tee-ssh-key-deny
    command: "tee ~/.ssh/id_rsa"
    expected:
      decision: deny
      rule_id: tee-secrets
  - id: tee-kube-config-deny
    command: "tee ~/.kube/config"
    expected:
      decision: deny
      rule_id: tee-secrets
  - id: tee-safe-file-allow
    command: "tee /tmp/output.txt"
    expected:
      decision: allow
  # rm secrets
  - id: rm-env-ask
    command: "rm .env"
    expected:
      decision: ask
      rule_id: rm-secrets
  - id: rm-ssh-key-ask
    command: "rm ~/.ssh/id_rsa"
    expected:
      decision: ask
      rule_id: rm-secrets
  - id: rm-aws-creds-ask
    command: "rm ~/.aws/credentials"
    expected:
      decision: ask
      rule_id: rm-secrets
  - id: rm-safe-file-ask
    command: "rm file.txt"
    expected:
      decision: ask
```

Note: `rm file.txt` expects `ask` because `rm` is NOT on the allowlist (it's intentionally excluded), so it falls to the default decision.

**Step 2: Run golden secrets tests**

Run: `cargo test golden_secrets`
Expected: PASS.

**Step 3: Commit**

```
feat: add golden tests for cp/mv/tee/rm secrets rules
```

---

## Task 4: Add golden tests for new allowlist commands

**Files:**
- Modify: `tests/golden/safe-commands.yaml`

**Step 1: Add test cases at the end of the file**

Append to `tests/golden/safe-commands.yaml`:

```yaml
  - id: stat-safe
    command: "stat file.txt"
    expected:
      decision: allow
  - id: du-safe
    command: "du -sh src/"
    expected:
      decision: allow
  - id: printf-safe
    command: "printf '%s\n' hello"
    expected:
      decision: allow
  - id: md5sum-safe
    command: "md5sum file.txt"
    expected:
      decision: allow
  - id: sha256sum-safe
    command: "sha256sum file.txt"
    expected:
      decision: allow
  - id: sha1sum-safe
    command: "sha1sum file.txt"
    expected:
      decision: allow
  - id: cksum-safe
    command: "cksum file.txt"
    expected:
      decision: allow
  - id: bracket-test-safe
    command: "[ -f file.txt ]"
    expected:
      decision: allow
```

**Step 2: Run golden safe-commands tests**

Run: `cargo test golden_safe_commands`
Expected: PASS.

**Step 3: Commit**

```
feat: add golden tests for new allowlist commands
```

---

## Task 5: Full verification

**Files:**
- None (verification only)

**Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass.

**Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings.

**Step 3: Manual verification**

Run:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"cp .env /tmp/x"}}' | cargo run -- --config rules/default-rules.yaml
```
Expected: JSON with `"permissionDecision":"ask"` and rule_id `cp-secrets`.

Run:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"tee .env"}}' | cargo run -- --config rules/default-rules.yaml
```
Expected: JSON with `"permissionDecision":"deny"` and rule_id `tee-secrets`.

Run:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"cp README.md /tmp/x"}}' | cargo run -- --config rules/default-rules.yaml
```
Expected: `{}` (allow -- cp is allowlisted, no secrets rule match).

Run:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"stat file.txt"}}' | cargo run -- --config rules/default-rules.yaml
```
Expected: `{}` (allow -- stat is now allowlisted).

**Step 4: Commit if any cleanup needed**

```
chore: verify secrets hardening
```

---

## Summary

| Task | Component | Key Change |
|------|-----------|------------|
| 1 | default-rules.yaml | 4 new rules: cp-secrets, mv-secrets, tee-secrets, rm-secrets |
| 2 | default-rules.yaml | 8 new allowlist entries: stat, du, printf, checksums, [ |
| 3 | secrets.yaml | 18 new golden test cases for cp/mv/tee/rm with secrets |
| 4 | safe-commands.yaml | 8 new golden test cases for new allowlist commands |
| 5 | Verification | Full test suite, clippy, manual E2E |
