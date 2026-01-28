# AI Judge Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove interpreters from the bare allowlist and add an `--ask-ai` flag that delegates inline code evaluation to `codex exec`.

**Architecture:** Phase 1 hardens the YAML rules (no Rust changes). Phase 2 adds `ai_judge.rs` module that shells out to `codex exec` when `--ask-ai` is passed and the command is an interpreter with inline code (`-c`/`-e`). The AI judge can only return `allow` or `ask` — never `deny`.

**Tech Stack:** Rust, clap, serde_yaml, std::process::Command, std::sync::mpsc (for timeout)

**Design doc:** `docs/plans/2026-01-28-ai-judge-design.md`

---

## Phase 1: Interpreter Allowlist Hardening

### Task 1: Update golden tests for interpreter decision changes

Before changing the rules, update the golden tests to reflect the new expected behavior. This ensures tests fail first (TDD).

**Files:**
- Modify: `tests/golden/safe-commands.yaml:46-49` (python-safe)
- Modify: `tests/golden/safe-commands.yaml:182-185` (node-safe)
- Modify: `tests/golden/safe-commands.yaml:194-197` (ruby-safe)

**Step 1: Change python-safe expected decision**

In `tests/golden/safe-commands.yaml`, change:
```yaml
  - id: python-safe
    command: "python3 script.py"
    expected:
      decision: allow
```
to:
```yaml
  - id: python-script-ask
    command: "python3 script.py"
    expected:
      decision: ask
```

**Step 2: Change node-safe expected decision**

Change:
```yaml
  - id: node-safe
    command: "node -e 'console.log(1)'"
    expected:
      decision: allow
```
to:
```yaml
  - id: node-inline-ask
    command: "node -e 'console.log(1)'"
    expected:
      decision: ask
```

**Step 3: Change ruby-safe expected decision**

Change:
```yaml
  - id: ruby-safe
    command: "ruby script.rb"
    expected:
      decision: allow
```
to:
```yaml
  - id: ruby-script-ask
    command: "ruby script.rb"
    expected:
      decision: ask
```

**Step 4: Run tests to verify they FAIL**

Run: `cargo test golden_safe_commands -- --nocapture`
Expected: FAIL — rules still have these on the allowlist.

---

### Task 2: Create interpreters golden test file

New golden tests covering all interpreter scenarios after the rules change.

**Files:**
- Create: `tests/golden/interpreters.yaml`
- Modify: `tests/golden_tests.rs`

**Step 1: Create the golden test file**

Create `tests/golden/interpreters.yaml`:
```yaml
tests:
  # ── Python: version checks (allowed via allowlist) ─────────────
  - id: python-version-long
    command: "python --version"
    expected:
      decision: allow
  - id: python3-version-long
    command: "python3 --version"
    expected:
      decision: allow
  - id: python-version-short
    command: "python -V"
    expected:
      decision: allow
  - id: python3-version-short
    command: "python3 -V"
    expected:
      decision: allow

  # ── Python: safe modules (allowed via allowlist) ───────────────
  - id: python-m-json-tool
    command: "python -m json.tool input.json"
    expected:
      decision: allow
  - id: python3-m-json-tool
    command: "python3 -m json.tool input.json"
    expected:
      decision: allow
  - id: python-m-py-compile
    command: "python -m py_compile script.py"
    expected:
      decision: allow
  - id: python3-m-compileall
    command: "python3 -m compileall src/"
    expected:
      decision: allow

  # ── Python: inline code (should ask) ───────────────────────────
  - id: python-inline-code
    command: "python -c 'print(1)'"
    expected:
      decision: ask
  - id: python3-inline-code
    command: "python3 -c 'import json; print(json.dumps({}))'"
    expected:
      decision: ask

  # ── Python: script execution (should ask) ──────────────────────
  - id: python-script-exec
    command: "python3 script.py"
    expected:
      decision: ask
  - id: python-script-with-args
    command: "python3 script.py --arg value"
    expected:
      decision: ask

  # ── Python: unsafe modules (should ask) ────────────────────────
  - id: python-m-http-server
    command: "python3 -m http.server 8080"
    expected:
      decision: ask
  - id: python-m-pip
    command: "python3 -m pip install requests"
    expected:
      decision: ask

  # ── Node: version checks (allowed) ────────────────────────────
  - id: node-version-long
    command: "node --version"
    expected:
      decision: allow
  - id: node-version-short
    command: "node -v"
    expected:
      decision: allow

  # ── Node: inline code (should ask) ────────────────────────────
  - id: node-inline-code
    command: "node -e 'console.log(1)'"
    expected:
      decision: ask

  # ── Node: script execution (should ask) ───────────────────────
  - id: node-script
    command: "node script.js"
    expected:
      decision: ask

  # ── Ruby: version checks (allowed) ────────────────────────────
  - id: ruby-version-long
    command: "ruby --version"
    expected:
      decision: allow
  - id: ruby-version-short
    command: "ruby -v"
    expected:
      decision: allow

  # ── Ruby: inline code (should ask) ────────────────────────────
  - id: ruby-inline-code
    command: "ruby -e 'puts 1'"
    expected:
      decision: ask

  # ── Ruby: script execution (should ask) ───────────────────────
  - id: ruby-script
    command: "ruby script.rb"
    expected:
      decision: ask

  # ── uv: safe tool invocations (allowed) ───────────────────────
  - id: uv-run-pytest
    command: "uv run pytest tests/"
    expected:
      decision: allow
  - id: uv-run-mypy
    command: "uv run mypy src/"
    expected:
      decision: allow
  - id: uv-run-ruff
    command: "uv run ruff check src/"
    expected:
      decision: allow
  - id: uv-run-black
    command: "uv run black src/"
    expected:
      decision: allow
  - id: uv-run-isort
    command: "uv run isort src/"
    expected:
      decision: allow
  - id: uv-run-flake8
    command: "uv run flake8 src/"
    expected:
      decision: allow
  - id: uv-run-pylint
    command: "uv run pylint src/"
    expected:
      decision: allow

  # ── uv: python invocations (should ask) ───────────────────────
  - id: uv-run-python
    command: "uv run python script.py"
    expected:
      decision: ask
  - id: uv-run-python-inline
    command: "uv run python -c 'print(1)'"
    expected:
      decision: ask
  - id: uv-run-python3
    command: "uv run python3 -c 'import os; os.system(\"ls\")'"
    expected:
      decision: ask
```

**Step 2: Register the golden test**

Add to `tests/golden_tests.rs` after the last test function (after line 148):
```rust
#[test]
fn golden_interpreters() {
    run_golden_suite("interpreters.yaml");
}
```

**Step 3: Run the new test to verify it FAILS**

Run: `cargo test golden_interpreters -- --nocapture`
Expected: FAIL — rules haven't been updated yet.

---

### Task 3: Update rules YAML — remove interpreters from allowlist

**Files:**
- Modify: `rules/default-rules.yaml:50-53` (remove python, python3, node, ruby)

**Step 1: Remove bare interpreter entries from allowlist**

In `rules/default-rules.yaml`, remove these four lines from the `allowlists.commands` section:
```yaml
    - node
    - python
    - python3
    - ruby
```

Keep `npx`, `java`, `javac`, `rustc` — those are not general-purpose inline interpreters.

---

### Task 4: Add safe interpreter patterns to allowlist

**Files:**
- Modify: `rules/default-rules.yaml` (allowlists.commands section)

**Step 1: Add version check and safe module allowlist entries**

Add these entries to the `allowlists.commands` section, in a new block after the `# ── Always safe: dev tools` section:
```yaml
    # ── Interpreters: safe invocations only ─────────────────────
    - "python --version"
    - "python -V"
    - "python3 --version"
    - "python3 -V"
    - "python -m json.tool"
    - "python3 -m json.tool"
    - "python -m py_compile"
    - "python3 -m py_compile"
    - "python -m compileall"
    - "python3 -m compileall"
    - "node --version"
    - "node -v"
    - "ruby --version"
    - "ruby -v"
    # ── uv: safe tool invocations ───────────────────────────────
    - "uv run pytest"
    - "uv run mypy"
    - "uv run ruff"
    - "uv run black"
    - "uv run isort"
    - "uv run flake8"
    - "uv run pylint"
```

**Step 2: Run ALL golden tests**

Run: `cargo test golden -- --nocapture`
Expected: ALL PASS — the updated rules match the updated golden tests.

**Step 3: Run full test suite**

Run: `cargo test`
Expected: ALL PASS

---

### Task 5: Commit Phase 1

```bash
git add rules/default-rules.yaml tests/golden/safe-commands.yaml tests/golden/interpreters.yaml tests/golden_tests.rs
git commit -m "$(cat <<'EOF'
feat: remove interpreters from bare allowlist, add safe patterns

Remove python, python3, node, ruby from bare command allowlist.
These are full interpreters and should not auto-allow arbitrary
code execution via -c/-e flags.

Add specific allowlist entries for safe invocations: version
checks, safe Python modules (json.tool, py_compile, compileall),
and uv run tool commands (pytest, mypy, ruff, black, etc.).

All other interpreter invocations now default to ask.
EOF
)"
```

---

## Phase 2: AI Judge (`--ask-ai` flag)

### Task 6: Add `--ask-ai` CLI flag

**Files:**
- Modify: `src/cli.rs:11-24` (Cli struct)
- Modify: `src/cli.rs:110` (run_hook call)
- Modify: `src/cli.rs:115` (run_hook signature)

**Step 1: Write integration test for the flag**

Add to `tests/integration.rs` after the last test:
```rust
#[test]
fn test_e2e_ask_ai_flag_accepted() {
    // Verify --ask-ai flag is accepted without error.
    // Without codex installed in CI, the flag should still work —
    // ai_judge failures fall back to ask.
    let (code, stdout) = run_hook_with_flags("Bash", "ls -la", &["--ask-ai"]);
    assert_eq!(code, 0);
    // ls is allowlisted, so --ask-ai doesn't change the result
    assert_eq!(stdout.trim(), "{}");
}

#[test]
fn test_e2e_ask_ai_does_not_affect_deny() {
    // --ask-ai should NOT override deny decisions
    let (code, stdout) = run_hook_with_flags("Bash", "rm -rf /", &["--ask-ai"]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
}
```

**Step 2: Run tests to verify they FAIL**

Run: `cargo test test_e2e_ask_ai -- --nocapture`
Expected: FAIL — `--ask-ai` flag doesn't exist yet.

**Step 3: Add the flag to Cli struct**

In `src/cli.rs`, add to the `Cli` struct (after line 20):
```rust
    /// Use AI to evaluate inline interpreter code instead of asking
    #[arg(long)]
    ask_ai: bool,
```

**Step 4: Thread the flag through to run_hook**

In `src/cli.rs`, change line 110:
```rust
        None => run_hook(&rules_config, cli.ask_on_deny),
```
to:
```rust
        None => run_hook(&rules_config, cli.ask_on_deny, cli.ask_ai),
```

Change the `run_hook` signature at line 115:
```rust
fn run_hook(rules_config: &policy::RulesConfig, ask_on_deny: bool) -> i32 {
```
to:
```rust
fn run_hook(rules_config: &policy::RulesConfig, ask_on_deny: bool, _ask_ai: bool) -> i32 {
```

Note: `_ask_ai` is unused for now — we'll wire it in after creating `ai_judge.rs`.

**Step 5: Run tests**

Run: `cargo test test_e2e_ask_ai -- --nocapture`
Expected: PASS

**Step 6: Commit**

```bash
git add src/cli.rs tests/integration.rs
git commit -m "feat: add --ask-ai CLI flag (wiring pending)"
```

---

### Task 7: Create `ai_judge.rs` — config and trigger detection

**Files:**
- Create: `src/ai_judge.rs`
- Modify: `src/main.rs:1-6` (add module declaration)
- Modify: `src/lib.rs:1-3` (add public module)

**Step 1: Write unit tests for config and trigger detection**

Create `src/ai_judge.rs` with config types, defaults, trigger detection, and tests at the bottom:

```rust
use serde::Deserialize;
use std::path::PathBuf;

use crate::parser::Statement;
use crate::types::Decision;

// ── Config types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AiJudgeConfig {
    #[serde(default = "default_command")]
    pub command: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub triggers: TriggersConfig,
}

#[derive(Debug, Deserialize)]
pub struct TriggersConfig {
    #[serde(default = "default_interpreters")]
    pub interpreters: Vec<InterpreterTrigger>,
}

impl Default for TriggersConfig {
    fn default() -> Self {
        Self {
            interpreters: default_interpreters(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InterpreterTrigger {
    pub name: Vec<String>,
    pub inline_flag: String,
}

fn default_command() -> String {
    "codex exec".to_string()
}

fn default_timeout() -> u64 {
    15
}

fn default_interpreters() -> Vec<InterpreterTrigger> {
    vec![
        InterpreterTrigger {
            name: vec!["python".into(), "python3".into()],
            inline_flag: "-c".into(),
        },
        InterpreterTrigger {
            name: vec!["node".into()],
            inline_flag: "-e".into(),
        },
        InterpreterTrigger {
            name: vec!["ruby".into()],
            inline_flag: "-e".into(),
        },
        InterpreterTrigger {
            name: vec!["perl".into()],
            inline_flag: "-e".into(),
        },
    ]
}

// ── Config loading ──────────────────────────────────────────────

fn default_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".config")
        .join("longline")
        .join("ai-judge.yaml")
}

pub fn load_config() -> AiJudgeConfig {
    let path = default_config_path();
    if !path.exists() {
        return default_config();
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_yaml::from_str(&content).unwrap_or_else(|e| {
            eprintln!("longline: failed to parse ai-judge config: {e}");
            default_config()
        }),
        Err(e) => {
            eprintln!("longline: failed to read ai-judge config: {e}");
            default_config()
        }
    }
}

fn default_config() -> AiJudgeConfig {
    AiJudgeConfig {
        command: default_command(),
        timeout: default_timeout(),
        triggers: TriggersConfig::default(),
    }
}

// ── Trigger detection ───────────────────────────────────────────

/// Check if a statement is an interpreter with inline code.
/// Returns (language, code) if matched.
pub fn extract_inline_code(stmt: &Statement, config: &AiJudgeConfig) -> Option<(String, String)> {
    let cmd = match stmt {
        Statement::SimpleCommand(cmd) => cmd,
        _ => return None,
    };

    let cmd_name = cmd.name.as_deref()?;

    for trigger in &config.triggers.interpreters {
        if !trigger.name.iter().any(|n| n == cmd_name) {
            continue;
        }
        let flag_pos = cmd.argv.iter().position(|a| a == &trigger.inline_flag)?;
        let code = cmd.argv.get(flag_pos + 1)?;
        return Some((cmd_name.to_string(), code.clone()));
    }

    None
}

// ── Prompt ──────────────────────────────────────────────────────

const PROMPT_TEMPLATE: &str = r#"Security evaluation of inline {language} code to be executed on a developer's machine.

Working directory: {cwd}

```{language}
{code}
```

Evaluate safety. Respond with EXACTLY one line, no other output:

ALLOW: <brief reason>
— Code only does: computation, data formatting, printing output, reading/writing
  files in the working directory or temp directories (/tmp, $TMPDIR, tempfile
  module), string/regex operations, JSON/YAML/CSV parsing, encoding, hashing,
  math, type checking, or version queries.

ASK: <brief reason>
— Code does ANY of: write/delete/move/rename files outside temp dirs or the
  working directory, network requests, subprocess or shell execution (os.system,
  subprocess), access secrets or credentials (.env, SSH keys, tokens), modify
  system configuration, install packages, or access sensitive paths outside the
  working directory."#;

pub fn build_prompt(language: &str, code: &str, cwd: &str) -> String {
    PROMPT_TEMPLATE
        .replace("{language}", language)
        .replace("{code}", code)
        .replace("{cwd}", cwd)
}

// ── Response parsing ────────────────────────────────────────────

pub fn parse_response(output: &str) -> Decision {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ALLOW:") {
            return Decision::Allow;
        }
        if trimmed.starts_with("ASK:") {
            return Decision::Ask;
        }
    }
    Decision::Ask
}

// ── LLM invocation ─────────────────────────────────────────────

pub fn evaluate(config: &AiJudgeConfig, language: &str, code: &str, cwd: &str) -> Decision {
    let prompt = build_prompt(language, code, cwd);

    let parts: Vec<String> = config.command.split_whitespace().map(String::from).collect();
    if parts.is_empty() {
        eprintln!("longline: ai-judge command is empty");
        return Decision::Ask;
    }

    let timeout = std::time::Duration::from_secs(config.timeout);
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let result = std::process::Command::new(&parts[0])
            .args(&parts[1..])
            .arg(&prompt)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output();
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_response(&stdout)
        }
        Ok(Err(e)) => {
            eprintln!("longline: ai-judge process error: {e}");
            Decision::Ask
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            eprintln!("longline: ai-judge timed out after {}s", config.timeout);
            Decision::Ask
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            eprintln!("longline: ai-judge thread error");
            Decision::Ask
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{self, SimpleCommand};

    fn test_config() -> AiJudgeConfig {
        default_config()
    }

    #[test]
    fn test_extract_python_c() {
        let stmt = parser::parse("python3 -c 'print(1)'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some());
        let (lang, code) = result.unwrap();
        assert_eq!(lang, "python3");
        assert_eq!(code, "print(1)");
    }

    #[test]
    fn test_extract_node_e() {
        let stmt = parser::parse("node -e 'console.log(1)'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some());
        let (lang, code) = result.unwrap();
        assert_eq!(lang, "node");
        assert_eq!(code, "console.log(1)");
    }

    #[test]
    fn test_extract_ruby_e() {
        let stmt = parser::parse("ruby -e 'puts 1'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some());
        let (lang, code) = result.unwrap();
        assert_eq!(lang, "ruby");
        assert_eq!(code, "puts 1");
    }

    #[test]
    fn test_no_extract_for_script() {
        let stmt = parser::parse("python3 script.py").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_none(), "script.py should not match -c trigger");
    }

    #[test]
    fn test_no_extract_for_version() {
        let stmt = parser::parse("python3 --version").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_none(), "--version should not match -c trigger");
    }

    #[test]
    fn test_no_extract_for_non_interpreter() {
        let stmt = parser::parse("ls -la").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_no_extract_for_pipeline() {
        let stmt = parser::parse("echo hello | python3 -c 'import sys'").unwrap();
        let config = test_config();
        // Pipeline is not a SimpleCommand at the top level
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_prompt() {
        let prompt = build_prompt("python3", "print(1)", "/home/user/project");
        assert!(prompt.contains("python3"));
        assert!(prompt.contains("print(1)"));
        assert!(prompt.contains("/home/user/project"));
        assert!(prompt.contains("ALLOW:"));
        assert!(prompt.contains("ASK:"));
    }

    #[test]
    fn test_parse_response_allow() {
        assert_eq!(parse_response("ALLOW: safe computation"), Decision::Allow);
    }

    #[test]
    fn test_parse_response_ask() {
        assert_eq!(parse_response("ASK: network access detected"), Decision::Ask);
    }

    #[test]
    fn test_parse_response_with_noise() {
        let output = "OpenAI Codex v0.84.0\n--------\nALLOW: safe computation\ntokens used\n";
        assert_eq!(parse_response(output), Decision::Allow);
    }

    #[test]
    fn test_parse_response_unparseable() {
        assert_eq!(parse_response("something unexpected"), Decision::Ask);
    }

    #[test]
    fn test_parse_response_empty() {
        assert_eq!(parse_response(""), Decision::Ask);
    }

    #[test]
    fn test_config_deserialization() {
        let yaml = r#"
command: claude -p
timeout: 10
triggers:
  interpreters:
    - name: [python, python3]
      inline_flag: "-c"
"#;
        let config: AiJudgeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.command, "claude -p");
        assert_eq!(config.timeout, 10);
        assert_eq!(config.triggers.interpreters.len(), 1);
        assert_eq!(config.triggers.interpreters[0].name, vec!["python", "python3"]);
    }

    #[test]
    fn test_config_defaults() {
        let yaml = "{}";
        let config: AiJudgeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.command, "codex exec");
        assert_eq!(config.timeout, 15);
        assert!(!config.triggers.interpreters.is_empty());
    }
}
```

**Step 2: Add module declarations**

In `src/main.rs`, add after line 2 (`mod logger;`):
```rust
mod ai_judge;
```

In `src/lib.rs`, add:
```rust
pub mod ai_judge;
```

**Step 3: Run unit tests**

Run: `cargo test ai_judge -- --nocapture`
Expected: ALL PASS

**Step 4: Commit**

```bash
git add src/ai_judge.rs src/main.rs src/lib.rs
git commit -m "feat: add ai_judge module with config, trigger detection, and prompt"
```

---

### Task 8: Wire ai_judge into cli.rs run_hook

**Files:**
- Modify: `src/cli.rs:115-219` (run_hook function)

**Step 1: Write integration test for ai_judge with mock**

Add to `tests/integration.rs`:
```rust
#[test]
fn test_e2e_ask_ai_falls_back_on_missing_codex() {
    // python3 -c should be ask (not on allowlist).
    // With --ask-ai, if codex isn't available, fallback to ask.
    let (code, stdout) = run_hook_with_flags("Bash", "python3 -c 'print(1)'", &["--ask-ai"]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        parsed["hookSpecificOutput"]["permissionDecision"], "ask",
        "Should fall back to ask when codex unavailable"
    );
}
```

**Step 2: Run test to verify it FAILS**

Run: `cargo test test_e2e_ask_ai_falls_back -- --nocapture`
Expected: FAIL — `_ask_ai` is unused.

**Step 3: Wire ai_judge into run_hook**

In `src/cli.rs`, change the `run_hook` signature to use `ask_ai` (remove underscore):
```rust
fn run_hook(rules_config: &policy::RulesConfig, ask_on_deny: bool, ask_ai: bool) -> i32 {
```

Add the ai_judge import at the top of cli.rs (after line 7):
```rust
use crate::ai_judge;
```

In `run_hook`, after the `ask_on_deny` block (after line 179), add:
```rust
    // AI judge: evaluate inline interpreter code instead of asking user
    let final_decision = if ask_ai && final_decision == Decision::Ask {
        let ai_config = ai_judge::load_config();
        match ai_judge::extract_inline_code(&stmt, &ai_config) {
            Some((language, code)) => {
                let cwd = hook_input.cwd.as_deref().unwrap_or("");
                let ai_decision = ai_judge::evaluate(&ai_config, &language, &code, cwd);
                eprintln!(
                    "longline: ai-judge evaluated {language} code → {ai_decision}",
                );
                ai_decision
            }
            None => final_decision,
        }
    } else {
        final_decision
    };
```

Note: `final_decision` needs to be `let mut` or re-bound. Since the existing code uses `let (final_decision, overridden)`, change that line to:
```rust
    let (initial_decision, overridden) = if ask_on_deny && result.decision == Decision::Deny {
```

Then the ai_judge block becomes:
```rust
    let final_decision = if ask_ai && initial_decision == Decision::Ask {
        ...
    } else {
        initial_decision
    };
```

And update all subsequent references from `final_decision` to use the new binding (they already do since we re-bound the name).

**Step 4: Run integration tests**

Run: `cargo test test_e2e_ask_ai -- --nocapture`
Expected: ALL PASS (codex not installed → falls back to ask)

**Step 5: Run full test suite**

Run: `cargo test`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add src/cli.rs tests/integration.rs
git commit -m "feat: wire --ask-ai flag into hook evaluation flow"
```

---

### Task 9: Run clippy and format

**Step 1: Format**

Run: `cargo fmt`

**Step 2: Lint**

Run: `cargo clippy -- -D warnings`
Expected: PASS with no warnings.

**Step 3: Full test suite**

Run: `cargo test`
Expected: ALL PASS

**Step 4: Commit if any formatting changes**

```bash
git add -A
git commit -m "chore: format and lint"
```

---

## Verification Checklist

After all tasks are complete, verify:

- [ ] `cargo test` — all tests pass
- [ ] `cargo clippy -- -D warnings` — no warnings
- [ ] `echo '{"tool_name":"Bash","tool_input":{"command":"python3 --version"}}' | cargo run -- --config rules/default-rules.yaml` — outputs `{}`
- [ ] `echo '{"tool_name":"Bash","tool_input":{"command":"python3 -c \"print(1)\""}}' | cargo run -- --config rules/default-rules.yaml` — outputs ask decision
- [ ] `echo '{"tool_name":"Bash","tool_input":{"command":"python3 -c \"print(1)\""}}' | cargo run -- --config rules/default-rules.yaml --ask-ai` — attempts codex, falls back to ask if not installed
- [ ] `echo '{"tool_name":"Bash","tool_input":{"command":"uv run pytest tests/"}}' | cargo run -- --config rules/default-rules.yaml` — outputs `{}`
- [ ] `echo '{"tool_name":"Bash","tool_input":{"command":"uv run python -c \"print(1)\""}}' | cargo run -- --config rules/default-rules.yaml` — outputs ask decision
