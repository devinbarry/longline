# Diagnostic and Override Modes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add two diagnostic subcommands (`check`, `rules`) and one runtime override flag (`--ask-on-deny`) to the longline CLI.

**Architecture:** Restructure cli.rs from flat `Args` to clap subcommands with an `Option<Commands>` enum. When no subcommand is given, existing hook mode runs. New subcommands produce human-readable table output to stdout. The `--ask-on-deny` flag is root-level and only applies in hook mode. Logger gains optional `original_decision`/`overridden` fields.

**Tech Stack:** Rust, clap 4 (derive), serde, existing policy/parser modules.

---

### Task 1: Restructure CLI for subcommands

Refactor cli.rs to support optional subcommands. No new behavior -- existing hook mode must work identically. Remove the unused `dry_run` flag.

**Files:**
- Modify: `src/cli.rs:10-20` (Args struct -> Cli + Commands enum)

**Step 1: Run existing tests to establish baseline**

Run: `cargo test`
Expected: All tests pass.

**Step 2: Restructure Args into Cli with optional subcommand**

Replace the `Args` struct in `src/cli.rs:10-20` with:

```rust
#[derive(ClapParser)]
#[command(name = "longline", version, about = "Safety hook for Claude Code")]
struct Cli {
    /// Path to rules YAML file
    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    /// Downgrade deny decisions to ask (hook mode only)
    #[arg(long)]
    ask_on_deny: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Test commands against rules
    Check {
        /// File with one command per line (stdin if omitted)
        file: Option<PathBuf>,

        /// Show only: allow, ask, deny
        #[arg(short, long)]
        filter: Option<DecisionFilter>,
    },
    /// Show current rule configuration
    Rules {
        /// Show full matcher patterns and details
        #[arg(short, long)]
        verbose: bool,

        /// Show only: allow, ask, deny
        #[arg(short, long)]
        filter: Option<DecisionFilter>,

        /// Show only: critical, high, strict
        #[arg(short, long)]
        level: Option<LevelFilter>,

        /// Group by: decision, level
        #[arg(short, long)]
        group_by: Option<GroupBy>,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum DecisionFilter {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, clap::ValueEnum)]
enum LevelFilter {
    Critical,
    High,
    Strict,
}

#[derive(Clone, clap::ValueEnum)]
enum GroupBy {
    Decision,
    Level,
}
```

**Step 3: Update run() to dispatch on subcommand**

In `run()`, change `Args::parse()` to `Cli::parse()`. Add subcommand dispatch after loading config:

```rust
pub fn run() -> i32 {
    let cli = Cli::parse();

    let config_path = cli.config.unwrap_or_else(default_config_path);
    let rules_config = match policy::load_rules(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("longline: {e}");
            return 2;
        }
    };

    match cli.command {
        Some(Commands::Check { file, filter }) => {
            run_check(&rules_config, file, filter)
        }
        Some(Commands::Rules { verbose, filter, level, group_by }) => {
            run_rules(&rules_config, verbose, filter, level, group_by)
        }
        None => run_hook(&rules_config, cli.ask_on_deny),
    }
}
```

Move the existing hook logic from `run()` into a new `fn run_hook(config: &policy::RulesConfig, ask_on_deny: bool) -> i32`. Add stub functions for the subcommands:

```rust
fn run_check(
    _config: &policy::RulesConfig,
    _file: Option<PathBuf>,
    _filter: Option<DecisionFilter>,
) -> i32 {
    eprintln!("longline: check subcommand not yet implemented");
    1
}

fn run_rules(
    _config: &policy::RulesConfig,
    _verbose: bool,
    _filter: Option<DecisionFilter>,
    _level: Option<LevelFilter>,
    _group_by: Option<GroupBy>,
) -> i32 {
    eprintln!("longline: rules subcommand not yet implemented");
    1
}
```

**Step 4: Run tests to verify no regression**

Run: `cargo test`
Expected: All existing tests pass (hook mode behavior unchanged).

**Step 5: Commit**

```
git add src/cli.rs
git commit -m "refactor: restructure CLI for subcommand support"
```

---

### Task 2: Add `--ask-on-deny` runtime override

Wire the `--ask-on-deny` flag into hook mode. Modify logger to record overrides.

**Files:**
- Modify: `src/cli.rs` (run_hook function)
- Modify: `src/logger.rs` (LogEntry fields)
- Modify: `tests/integration.rs` (new E2E tests)

**Step 1: Write failing integration tests**

Add to `tests/integration.rs`:

```rust
fn run_hook_with_flags(tool_name: &str, command: &str, extra_args: &[&str]) -> (i32, String) {
    let input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {
            "command": command,
        },
        "session_id": "test-session",
        "cwd": "/tmp"
    });

    let mut args = vec!["--config", &rules_path()];
    args.extend_from_slice(extra_args);

    let mut child = Command::new(longline_bin())
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (code, stdout)
}

#[test]
fn test_e2e_ask_on_deny_downgrades_deny_to_ask() {
    let (code, stdout) = run_hook_with_flags("Bash", "rm -rf /", &["--ask-on-deny"]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "ask");
    let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("[overridden]"), "Reason should be prefixed: {reason}");
    assert!(reason.contains("rm-recursive-root"), "Should preserve rule ID: {reason}");
}

#[test]
fn test_e2e_ask_on_deny_does_not_affect_allow() {
    let (code, stdout) = run_hook_with_flags("Bash", "ls -la", &["--ask-on-deny"]);
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "{}");
}

#[test]
fn test_e2e_ask_on_deny_does_not_affect_ask() {
    // chmod 777 triggers ask via chmod-777 rule
    let (code, stdout) = run_hook_with_flags("Bash", "chmod 777 /tmp/f", &["--ask-on-deny"]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "ask");
    let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(!reason.contains("[overridden]"), "Ask should not be overridden: {reason}");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test test_e2e_ask_on_deny`
Expected: FAIL (--ask-on-deny not implemented yet -- stubs return exit code 0 but deny is not downgraded).

**Step 3: Add override fields to LogEntry**

In `src/logger.rs`, add fields to `LogEntry`:

```rust
#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub ts: String,
    pub tool: String,
    pub cwd: String,
    pub command: String,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_decision: Option<Decision>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub overridden: bool,
    pub matched_rules: Vec<String>,
    pub reason: Option<String>,
    pub parse_ok: bool,
    pub session_id: Option<String>,
}
```

Update `make_entry` to initialize the new fields to `None`/`false`. All existing callers continue to work.

**Step 4: Implement override logic in run_hook**

In `src/cli.rs`, in `run_hook()`, after `policy::evaluate()` returns `result`, add:

```rust
let (final_decision, overridden) = if ask_on_deny && result.decision == Decision::Deny {
    (Decision::Ask, true)
} else {
    (result.decision, false)
};
```

Update the log call to pass `original_decision` and `overridden`:

```rust
let mut entry = logger::make_entry(
    &hook_input.tool_name,
    hook_input.cwd.as_deref().unwrap_or(""),
    command,
    final_decision,
    result.rule_id.clone().into_iter().collect(),
    if result.reason.is_empty() { None } else { Some(result.reason.clone()) },
    parse_ok,
    hook_input.session_id.clone(),
);
if overridden {
    entry.original_decision = Some(result.decision);
    entry.overridden = true;
}
logger::log_decision(&entry);
```

Update the output logic to use `final_decision` and prefix reason when overridden:

```rust
match final_decision {
    Decision::Allow => {
        print_allow();
    }
    Decision::Ask | Decision::Deny => {
        let reason = if overridden {
            format!("[overridden] {}", format_reason(&result))
        } else {
            format_reason(&result)
        };
        let output = HookOutput::decision(final_decision, &reason);
        print_json(&output);
    }
}
```

**Step 5: Run tests to verify they pass**

Run: `cargo test`
Expected: All tests pass including new `test_e2e_ask_on_deny_*` tests.

**Step 6: Commit**

```
git add src/cli.rs src/logger.rs tests/integration.rs
git commit -m "feat: add --ask-on-deny flag to downgrade denies to asks"
```

---

### Task 3: Add `rules` subcommand

Display the loaded rule configuration in human-readable table form.

**Files:**
- Modify: `src/cli.rs` (implement run_rules)
- Modify: `src/policy.rs` (add Display impls or format helpers)
- Modify: `tests/integration.rs` (new E2E tests)

**Step 1: Write failing integration tests**

Add to `tests/integration.rs`:

```rust
fn run_subcommand(args: &[&str]) -> (i32, String, String) {
    let child = Command::new(longline_bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    let output = child.wait_with_output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

#[test]
fn test_e2e_rules_shows_table() {
    let (code, stdout, _) = run_subcommand(&["rules", "--config", &rules_path()]);
    assert_eq!(code, 0);
    assert!(stdout.contains("DECISION"), "Should have header: {stdout}");
    assert!(stdout.contains("rm-recursive-root"), "Should list rules: {stdout}");
    assert!(stdout.contains("Allowlist:"), "Should show allowlist: {stdout}");
    assert!(stdout.contains("Safety level:"), "Should show safety level: {stdout}");
}

#[test]
fn test_e2e_rules_filter_deny() {
    let (code, stdout, _) = run_subcommand(&["rules", "--config", &rules_path(), "--filter", "deny"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("deny"), "Should have deny rules: {stdout}");
    assert!(!stdout.contains("\nask "), "Should not have ask rules in filtered output");
}

#[test]
fn test_e2e_rules_filter_level() {
    let (code, stdout, _) = run_subcommand(&["rules", "--config", &rules_path(), "--level", "critical"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("critical"), "Should have critical rules: {stdout}");
    assert!(!stdout.contains("high"), "Should not have high rules: {stdout}");
}

#[test]
fn test_e2e_rules_group_by_decision() {
    let (code, stdout, _) = run_subcommand(&[
        "rules", "--config", &rules_path(), "--group-by", "decision",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("-- deny"), "Should have deny group header: {stdout}");
    assert!(stdout.contains("-- ask"), "Should have ask group header: {stdout}");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test test_e2e_rules`
Expected: FAIL (run_rules returns exit code 1 from stub).

**Step 3: Add Display impls for SafetyLevel and Decision**

In `src/policy.rs`, add `Display` for `SafetyLevel`:

```rust
impl std::fmt::Display for SafetyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyLevel::Critical => write!(f, "critical"),
            SafetyLevel::High => write!(f, "high"),
            SafetyLevel::Strict => write!(f, "strict"),
        }
    }
}
```

In `src/types.rs`, add `Display` for `Decision`:

```rust
impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "allow"),
            Decision::Ask => write!(f, "ask"),
            Decision::Deny => write!(f, "deny"),
        }
    }
}
```

**Step 4: Implement run_rules**

In `src/cli.rs`, replace the stub `run_rules` with the full implementation:

```rust
fn run_rules(
    config: &policy::RulesConfig,
    verbose: bool,
    filter: Option<DecisionFilter>,
    level: Option<LevelFilter>,
    group_by: Option<GroupBy>,
) -> i32 {
    let rules: Vec<&policy::Rule> = config
        .rules
        .iter()
        .filter(|r| match &filter {
            Some(DecisionFilter::Allow) => r.decision == Decision::Allow,
            Some(DecisionFilter::Ask) => r.decision == Decision::Ask,
            Some(DecisionFilter::Deny) => r.decision == Decision::Deny,
            None => true,
        })
        .filter(|r| match &level {
            Some(LevelFilter::Critical) => r.level == policy::SafetyLevel::Critical,
            Some(LevelFilter::High) => r.level == policy::SafetyLevel::High,
            Some(LevelFilter::Strict) => r.level == policy::SafetyLevel::Strict,
            None => true,
        })
        .collect();

    match group_by {
        Some(GroupBy::Decision) => print_rules_grouped_by_decision(&rules, verbose),
        Some(GroupBy::Level) => print_rules_grouped_by_level(&rules, verbose),
        None => print_rules_table(&rules, verbose),
    }

    // Footer
    print_allowlist_summary(&config.allowlists.commands);
    println!("Safety level: {} | Default decision: {}", config.safety_level, config.default_decision);

    0
}

fn print_rules_table(rules: &[&policy::Rule], verbose: bool) {
    println!("{:<10}{:<10}{:<28}{}", "DECISION", "LEVEL", "ID", "DESCRIPTION");
    for rule in rules {
        println!("{:<10}{:<10}{:<28}{}", rule.decision, rule.level, rule.id, rule.reason);
        if verbose {
            print_matcher_details(&rule.matcher);
        }
    }
    println!();
}

fn print_rules_grouped_by_decision(rules: &[&policy::Rule], verbose: bool) {
    for decision in &[Decision::Deny, Decision::Ask, Decision::Allow] {
        let group: Vec<_> = rules.iter().filter(|r| r.decision == *decision).collect();
        if group.is_empty() {
            continue;
        }
        println!("-- {} {}", decision, "-".repeat(55));
        for rule in &group {
            println!("  {:<10}{:<28}{}", rule.level, rule.id, rule.reason);
            if verbose {
                print_matcher_details(&rule.matcher);
            }
        }
        println!();
    }
}

fn print_rules_grouped_by_level(rules: &[&policy::Rule], verbose: bool) {
    for level in &[policy::SafetyLevel::Critical, policy::SafetyLevel::High, policy::SafetyLevel::Strict] {
        let group: Vec<_> = rules.iter().filter(|r| r.level == *level).collect();
        if group.is_empty() {
            continue;
        }
        println!("-- {} {}", level, "-".repeat(55));
        for rule in &group {
            println!("  {:<10}{:<28}{}", rule.decision, rule.id, rule.reason);
            if verbose {
                print_matcher_details(&rule.matcher);
            }
        }
        println!();
    }
}

fn print_matcher_details(matcher: &policy::Matcher) {
    match matcher {
        policy::Matcher::Command { command, flags, args } => {
            println!("    match: command={}", format_string_or_list(command));
            if let Some(f) = flags {
                if !f.any_of.is_empty() {
                    println!("    flags.any_of: {:?}", f.any_of);
                }
                if !f.all_of.is_empty() {
                    println!("    flags.all_of: {:?}", f.all_of);
                }
            }
            if let Some(a) = args {
                if !a.any_of.is_empty() {
                    println!("    args.any_of: {:?}", a.any_of);
                }
            }
        }
        policy::Matcher::Pipeline { pipeline } => {
            let stages: Vec<String> = pipeline
                .stages
                .iter()
                .map(|s| format_string_or_list(&s.command))
                .collect();
            println!("    match: pipeline [{}]", stages.join(" | "));
        }
        policy::Matcher::Redirect { redirect } => {
            if let Some(op) = &redirect.op {
                println!("    redirect.op: {}", format_string_or_list(op));
            }
            if let Some(target) = &redirect.target {
                println!("    redirect.target: {}", format_string_or_list(target));
            }
        }
    }
}

fn format_string_or_list(sol: &policy::StringOrList) -> String {
    match sol {
        policy::StringOrList::Single(s) => s.clone(),
        policy::StringOrList::List { any_of } => format!("{{{}}}", any_of.join(", ")),
    }
}

fn print_allowlist_summary(commands: &[String]) {
    if commands.is_empty() {
        println!("Allowlist: (none)");
        return;
    }
    let display: Vec<&str> = commands.iter().take(10).map(|s| s.as_str()).collect();
    let suffix = if commands.len() > 10 {
        format!(", ... ({} total)", commands.len())
    } else {
        String::new()
    };
    println!("Allowlist: {}{}", display.join(", "), suffix);
}
```

Note: `policy::SafetyLevel`, `policy::Rule`, `policy::Matcher`, `policy::StringOrList`, `policy::PipelineMatcher`, `policy::RedirectMatcher`, `policy::FlagsMatcher`, `policy::ArgsMatcher` must all be `pub`. Check that they are already public in `src/policy.rs` -- they are (all structs/enums are `pub`).

**Step 5: Run tests to verify they pass**

Run: `cargo test`
Expected: All tests pass including new `test_e2e_rules_*` tests.

**Step 6: Commit**

```
git add src/cli.rs src/policy.rs src/types.rs tests/integration.rs
git commit -m "feat: add rules subcommand for config inspection"
```

---

### Task 4: Add `check` subcommand

Evaluate a list of commands against the rules and display results in a table.

**Files:**
- Modify: `src/cli.rs` (implement run_check)
- Modify: `tests/integration.rs` (new E2E tests)

**Step 1: Write failing integration tests**

Create a test commands file and add tests to `tests/integration.rs`:

```rust
use std::fs;

#[test]
fn test_e2e_check_from_file() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("test-tmp");
    let _ = fs::create_dir_all(&dir);
    let file = dir.join("test-commands.txt");
    fs::write(&file, "ls -la\nrm -rf /\nchmod 777 /tmp/f\n").unwrap();

    let (code, stdout, _) = run_subcommand(&[
        "check",
        "--config", &rules_path(),
        file.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("DECISION"), "Should have header: {stdout}");
    assert!(stdout.contains("allow"), "Should have allow: {stdout}");
    assert!(stdout.contains("deny"), "Should have deny: {stdout}");
    assert!(stdout.contains("ask"), "Should have ask: {stdout}");

    let _ = fs::remove_file(&file);
}

#[test]
fn test_e2e_check_filter_deny() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("test-tmp");
    let _ = fs::create_dir_all(&dir);
    let file = dir.join("test-commands-filter.txt");
    fs::write(&file, "ls -la\nrm -rf /\nchmod 777 /tmp/f\n").unwrap();

    let (code, stdout, _) = run_subcommand(&[
        "check",
        "--config", &rules_path(),
        "--filter", "deny",
        file.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("deny"), "Should have deny: {stdout}");
    // The header line will contain DECISION, and there should be no "allow " data rows
    let data_lines: Vec<&str> = stdout.lines().skip(1).collect();
    for line in &data_lines {
        if !line.is_empty() {
            assert!(line.starts_with("deny"), "Non-deny line in filtered output: {line}");
        }
    }

    let _ = fs::remove_file(&file);
}

#[test]
fn test_e2e_check_skips_comments_and_blanks() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("test-tmp");
    let _ = fs::create_dir_all(&dir);
    let file = dir.join("test-commands-comments.txt");
    fs::write(&file, "# this is a comment\n\nls -la\n").unwrap();

    let (code, stdout, _) = run_subcommand(&[
        "check",
        "--config", &rules_path(),
        file.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    // Should only have header + 1 data line (ls -la)
    let data_lines: Vec<&str> = stdout.lines()
        .skip(1)  // skip header
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(data_lines.len(), 1, "Should have 1 result, got: {data_lines:?}");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test test_e2e_check`
Expected: FAIL (run_check returns exit code 1 from stub).

**Step 3: Implement run_check**

In `src/cli.rs`, replace the stub `run_check` with:

```rust
fn run_check(
    config: &policy::RulesConfig,
    file: Option<PathBuf>,
    filter: Option<DecisionFilter>,
) -> i32 {
    let input = match read_check_input(file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("longline: {e}");
            return 1;
        }
    };

    let commands: Vec<&str> = input
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    println!("{:<10}{:<18}{}", "DECISION", "RULE", "COMMAND");

    for cmd_str in commands {
        let (decision, rule_label) = match parser::parse(cmd_str) {
            Ok(stmt) => {
                let result = policy::evaluate(config, &stmt);
                let label = match &result.rule_id {
                    Some(id) => id.clone(),
                    None => match result.decision {
                        Decision::Allow => "(allowlist)".to_string(),
                        Decision::Ask => {
                            if result.reason.contains("Unrecognized") {
                                "(opaque)".to_string()
                            } else {
                                "(default)".to_string()
                            }
                        }
                        Decision::Deny => "(default)".to_string(),
                    },
                };
                (result.decision, label)
            }
            Err(_) => (Decision::Ask, "(parse-error)".to_string()),
        };

        // Apply filter
        let show = match &filter {
            Some(DecisionFilter::Allow) => decision == Decision::Allow,
            Some(DecisionFilter::Ask) => decision == Decision::Ask,
            Some(DecisionFilter::Deny) => decision == Decision::Deny,
            None => true,
        };

        if show {
            println!("{:<10}{:<18}{}", decision, rule_label, cmd_str);
        }
    }

    0
}

fn read_check_input(file: Option<PathBuf>) -> Result<String, String> {
    match file {
        Some(path) if path.to_str() != Some("-") => {
            std::fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read {}: {e}", path.display()))
        }
        _ => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("Failed to read stdin: {e}"))?;
            Ok(buf)
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: All tests pass including new `test_e2e_check_*` tests.

**Step 5: Commit**

```
git add src/cli.rs tests/integration.rs
git commit -m "feat: add check subcommand for command testing"
```

---

### Task 5: Final cleanup and verification

**Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass.

**Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings.

**Step 3: Run fmt**

Run: `cargo fmt`
Expected: Clean.

**Step 4: Manual smoke test**

```bash
# Hook mode (existing)
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | cargo run -- --config rules/default-rules.yaml

# Hook mode with --ask-on-deny
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | cargo run -- --ask-on-deny --config rules/default-rules.yaml

# Rules subcommand
cargo run -- rules --config rules/default-rules.yaml
cargo run -- rules --config rules/default-rules.yaml --filter deny
cargo run -- rules --config rules/default-rules.yaml --group-by decision
cargo run -- rules --config rules/default-rules.yaml --level critical --verbose

# Check subcommand
echo -e "ls -la\nrm -rf /\nchmod 777 /tmp/f" | cargo run -- check --config rules/default-rules.yaml
echo -e "ls -la\nrm -rf /\nchmod 777 /tmp/f" | cargo run -- check --config rules/default-rules.yaml --filter deny
```

**Step 5: Commit any final fixes**

```
git add -A
git commit -m "chore: final cleanup for diagnostic and override modes"
```
