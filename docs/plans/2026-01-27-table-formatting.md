# Terminal Output Formatting Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace all `println!`-based table output with `comfy-table` (unicode borders, auto-sized columns, colored decision cells) and `yansi` (colored non-table text), respecting `NO_COLOR`.

**Architecture:** Add `comfy-table` and `yansi` as dependencies. Create a new `output.rs` module that owns all table-building logic. Refactor `cli.rs` output functions to call `output.rs` builders. Color init happens once at startup in `cli::run()`.

**Tech Stack:** comfy-table v7 (table formatting + built-in color via crossterm), yansi v1 (zero-dep coloring for non-table text)

---

### Task 1: Add dependencies and create output module skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `src/output.rs`
- Modify: `src/main.rs` (add `mod output;`)

**Step 1: Add dependencies to Cargo.toml**

Add after `glob-match = "0.2"`:
```toml
comfy-table = "7"
yansi = "1"
```

**Step 2: Create `src/output.rs` with module skeleton**

```rust
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement, Table};
use crate::policy;
use crate::types::Decision;

/// Map a Decision to its display color.
fn decision_color(d: Decision) -> Color {
    match d {
        Decision::Allow => Color::Green,
        Decision::Ask => Color::Yellow,
        Decision::Deny => Color::Red,
    }
}

/// Create a colored Cell for a Decision value.
fn decision_cell(d: Decision) -> Cell {
    Cell::new(d).fg(decision_color(d))
}
```

**Step 3: Register module in main.rs**

Add `mod output;` alongside the existing module declarations.

**Step 4: Verify it compiles**

Run: `cargo build 2>&1`
Expected: compiles successfully (unused warnings are fine)

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/output.rs src/main.rs
git commit -m "feat: add comfy-table and yansi deps, create output module skeleton"
```

---

### Task 2: Implement rules table builder (default, non-verbose)

**Files:**
- Modify: `src/output.rs`
- Modify: `src/cli.rs`

**Step 1: Add `pub fn rules_table()` to output.rs**

```rust
/// Build the default rules table (non-verbose).
pub fn rules_table(rules: &[&policy::Rule]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("DECISION").add_attribute(Attribute::Bold),
            Cell::new("LEVEL").add_attribute(Attribute::Bold),
            Cell::new("ID").add_attribute(Attribute::Bold),
            Cell::new("DESCRIPTION").add_attribute(Attribute::Bold),
        ]);

    for rule in rules {
        table.add_row(vec![
            decision_cell(rule.decision),
            Cell::new(&rule.level),
            Cell::new(&rule.id),
            Cell::new(&rule.reason),
        ]);
    }

    table
}
```

**Step 2: Replace `print_rules_table()` in cli.rs**

Replace the body of `print_rules_table` (lines 333-345) with:

```rust
fn print_rules_table(rules: &[&policy::Rule], verbose: bool) {
    if verbose {
        println!("{}", crate::output::rules_table_verbose(rules));
    } else {
        println!("{}", crate::output::rules_table(rules));
    }
}
```

Note: `rules_table_verbose` will be implemented in Task 3. For now, just wire up the non-verbose path and leave verbose calling the old code temporarily, or gate it behind an `if verbose { todo!() }`.

Actually, simpler: just replace the non-verbose path first. Keep the verbose inline code for now:

```rust
fn print_rules_table(rules: &[&policy::Rule], verbose: bool) {
    if verbose {
        // Verbose handled in Task 3
        println!("{}", crate::output::rules_table_verbose(rules));
    } else {
        println!("{}", crate::output::rules_table(rules));
    }
}
```

Since `rules_table_verbose` doesn't exist yet, add a temporary stub in output.rs:

```rust
/// Build the verbose rules table (with matcher columns).
pub fn rules_table_verbose(rules: &[&policy::Rule]) -> Table {
    // TODO: Task 3
    rules_table(rules)
}
```

**Step 3: Delete the old `print_matcher_details` and `format_string_or_list` functions from cli.rs**

Actually wait -- those are still used by the grouped views. Keep them for now; Task 4 will clean them up.

**Step 4: Run tests**

Run: `cargo test --lib`
Expected: PASS (table output isn't tested by unit tests, only golden/integration tests)

Run: `cargo build`
Expected: compiles

**Step 5: Manually verify**

Run: `echo '' | cargo run -- --config rules/default-rules.yaml rules`
Expected: Unicode-bordered table with colored decision cells

**Step 6: Commit**

```bash
git add src/output.rs src/cli.rs
git commit -m "feat: replace rules table output with comfy-table"
```

---

### Task 3: Implement verbose rules table (extra columns)

**Files:**
- Modify: `src/output.rs`

**Step 1: Replace `rules_table_verbose` stub**

```rust
/// Build the verbose rules table with MATCH TYPE and PATTERN columns.
pub fn rules_table_verbose(rules: &[&policy::Rule]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("DECISION").add_attribute(Attribute::Bold),
            Cell::new("LEVEL").add_attribute(Attribute::Bold),
            Cell::new("ID").add_attribute(Attribute::Bold),
            Cell::new("MATCH").add_attribute(Attribute::Bold),
            Cell::new("PATTERN").add_attribute(Attribute::Bold),
            Cell::new("DESCRIPTION").add_attribute(Attribute::Bold),
        ]);

    for rule in rules {
        let (match_type, pattern) = format_matcher(&rule.matcher);
        table.add_row(vec![
            decision_cell(rule.decision),
            Cell::new(&rule.level),
            Cell::new(&rule.id),
            Cell::new(match_type),
            Cell::new(pattern),
            Cell::new(&rule.reason),
        ]);
    }

    table
}

/// Format a matcher into (type, pattern) strings for verbose display.
fn format_matcher(matcher: &policy::Matcher) -> (String, String) {
    match matcher {
        policy::Matcher::Command { command, flags, args } => {
            let mut parts = vec![format!("cmd={}", format_string_or_list(command))];
            if let Some(f) = flags {
                if !f.any_of.is_empty() {
                    parts.push(format!("flags={{{}}}", f.any_of.join(", ")));
                }
                if !f.all_of.is_empty() {
                    parts.push(format!("flags.all={{{}}}", f.all_of.join(", ")));
                }
            }
            if let Some(a) = args {
                if !a.any_of.is_empty() {
                    parts.push(format!("args={{{}}}", a.any_of.join(", ")));
                }
            }
            ("command".to_string(), parts.join(" "))
        }
        policy::Matcher::Pipeline { pipeline } => {
            let stages: Vec<String> = pipeline
                .stages
                .iter()
                .map(|s| format_string_or_list(&s.command))
                .collect();
            ("pipeline".to_string(), stages.join(" | "))
        }
        policy::Matcher::Redirect { redirect } => {
            let mut parts = Vec::new();
            if let Some(op) = &redirect.op {
                parts.push(format!("op={}", format_string_or_list(op)));
            }
            if let Some(target) = &redirect.target {
                parts.push(format!("target={}", format_string_or_list(target)));
            }
            ("redirect".to_string(), parts.join(" "))
        }
    }
}

fn format_string_or_list(sol: &policy::StringOrList) -> String {
    match sol {
        policy::StringOrList::Single(s) => s.clone(),
        policy::StringOrList::List { any_of } => format!("{{{}}}", any_of.join(", ")),
    }
}
```

**Step 2: Remove `format_string_or_list` and `print_matcher_details` from cli.rs**

These functions are now fully handled by output.rs. Remove them from cli.rs. The grouped views (Task 4) will also be moved to output.rs, but first check: are they referenced? Yes, `print_rules_grouped_by_decision` and `print_rules_grouped_by_level` still use `print_matcher_details`. Leave those for Task 4.

Actually, we can remove `print_matcher_details` and `format_string_or_list` from cli.rs now IF we also update the grouped functions in the same task. Let's defer the cleanup to Task 4 to keep this task focused.

**Step 3: Run tests and manual verify**

Run: `cargo build && cargo test --lib`
Run: `echo '' | cargo run -- --config rules/default-rules.yaml rules --verbose`
Expected: Table with 6 columns including MATCH and PATTERN

**Step 4: Commit**

```bash
git add src/output.rs
git commit -m "feat: add verbose rules table with match type and pattern columns"
```

---

### Task 4: Implement grouped rules output

**Files:**
- Modify: `src/output.rs`
- Modify: `src/cli.rs`

**Step 1: Add grouped output functions to output.rs**

```rust
/// Print rules grouped by decision (deny, ask, allow sections).
pub fn print_rules_grouped_by_decision(rules: &[&policy::Rule], verbose: bool) {
    for decision in &[Decision::Deny, Decision::Ask, Decision::Allow] {
        let group: Vec<&policy::Rule> = rules.iter().filter(|r| r.decision == *decision).copied().collect();
        if group.is_empty() {
            continue;
        }
        // Section header
        let header = format!("  {} ", decision);
        let colored_header = match decision {
            Decision::Deny => yansi::Paint::red(&header).bold(),
            Decision::Ask => yansi::Paint::yellow(&header).bold(),
            Decision::Allow => yansi::Paint::green(&header).bold(),
        };
        println!("{}", colored_header);

        let group_refs: Vec<&policy::Rule> = group.iter().map(|r| *r).collect();
        if verbose {
            println!("{}", rules_table_verbose(&group_refs));
        } else {
            println!("{}", rules_table(&group_refs));
        }
    }
}

/// Print rules grouped by safety level (critical, high, strict sections).
pub fn print_rules_grouped_by_level(rules: &[&policy::Rule], verbose: bool) {
    for level in &[
        policy::SafetyLevel::Critical,
        policy::SafetyLevel::High,
        policy::SafetyLevel::Strict,
    ] {
        let group: Vec<&policy::Rule> = rules.iter().filter(|r| r.level == *level).copied().collect();
        if group.is_empty() {
            continue;
        }
        let header = format!("  {} ", level);
        println!("{}", yansi::Paint::new(&header).bold());

        let group_refs: Vec<&policy::Rule> = group.iter().map(|r| *r).collect();
        if verbose {
            println!("{}", rules_table_verbose(&group_refs));
        } else {
            println!("{}", rules_table(&group_refs));
        }
    }
}
```

**Step 2: Replace grouped functions in cli.rs**

Replace `print_rules_grouped_by_decision` and `print_rules_grouped_by_level` bodies:

```rust
fn print_rules_grouped_by_decision(rules: &[&policy::Rule], verbose: bool) {
    crate::output::print_rules_grouped_by_decision(rules, verbose);
}

fn print_rules_grouped_by_level(rules: &[&policy::Rule], verbose: bool) {
    crate::output::print_rules_grouped_by_level(rules, verbose);
}
```

**Step 3: Now safe to remove `print_matcher_details` and `format_string_or_list` from cli.rs**

Delete both functions from cli.rs -- they are no longer referenced.

**Step 4: Run tests and verify**

Run: `cargo build && cargo test --lib`
Run: `echo '' | cargo run -- --config rules/default-rules.yaml rules --group-by decision`
Run: `echo '' | cargo run -- --config rules/default-rules.yaml rules --group-by level --verbose`

**Step 5: Commit**

```bash
git add src/output.rs src/cli.rs
git commit -m "feat: implement grouped rules output with comfy-table"
```

---

### Task 5: Implement check command table

**Files:**
- Modify: `src/output.rs`
- Modify: `src/cli.rs`

**Step 1: Add check table builder to output.rs**

```rust
/// Build the check results table.
pub fn check_table(rows: &[(Decision, String, String)]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("DECISION").add_attribute(Attribute::Bold),
            Cell::new("RULE").add_attribute(Attribute::Bold),
            Cell::new("COMMAND").add_attribute(Attribute::Bold),
        ]);

    for (decision, rule_label, cmd) in rows {
        table.add_row(vec![
            decision_cell(*decision),
            Cell::new(rule_label),
            Cell::new(cmd),
        ]);
    }

    table
}
```

**Step 2: Refactor `run_check` in cli.rs to collect rows then print table**

Replace the inline println loop (lines 238-274) with:

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

    let mut rows: Vec<(Decision, String, String)> = Vec::new();

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

        let show = match &filter {
            Some(DecisionFilter::Allow) => decision == Decision::Allow,
            Some(DecisionFilter::Ask) => decision == Decision::Ask,
            Some(DecisionFilter::Deny) => decision == Decision::Deny,
            None => true,
        };

        if show {
            rows.push((decision, rule_label, cmd_str.to_string()));
        }
    }

    println!("{}", crate::output::check_table(&rows));

    0
}
```

**Step 3: Run tests and verify**

Run: `cargo test --test integration`
Note: Integration tests check JSON output from hook mode, not check/rules subcommands, so they should still pass.

Run: `echo 'ls\nrm -rf /\ngit commit --amend' | cargo run -- --config rules/default-rules.yaml check`
Expected: Unicode table with green allow, red deny, yellow ask rows

**Step 4: Commit**

```bash
git add src/output.rs src/cli.rs
git commit -m "feat: replace check output with comfy-table"
```

---

### Task 6: Implement full allowlist display for --filter allow

**Files:**
- Modify: `src/output.rs`
- Modify: `src/cli.rs`

**Step 1: Add allowlist table builder to output.rs**

```rust
/// Build a table showing all allowlisted commands.
pub fn allowlist_table(commands: &[String]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("ALLOWLISTED COMMANDS").add_attribute(Attribute::Bold),
        ]);

    for cmd in commands {
        table.add_row(vec![Cell::new(cmd).fg(Color::Green)]);
    }

    table
}

/// Print allowlist summary (compact, for non-allow-filter views).
pub fn print_allowlist_summary(commands: &[String]) {
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

/// Print the footer (safety level + default decision).
pub fn print_footer(config: &policy::RulesConfig) {
    println!(
        "Safety level: {} | Default decision: {}",
        config.safety_level, config.default_decision
    );
}
```

**Step 2: Refactor `run_rules` in cli.rs to expand allowlist when `--filter allow`**

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
        Some(GroupBy::Decision) => crate::output::print_rules_grouped_by_decision(&rules, verbose),
        Some(GroupBy::Level) => crate::output::print_rules_grouped_by_level(&rules, verbose),
        None => {
            if verbose {
                println!("{}", crate::output::rules_table_verbose(&rules));
            } else {
                println!("{}", crate::output::rules_table(&rules));
            }
        }
    }

    // Show full allowlist when filtering to allow, compact summary otherwise
    let is_allow_filter = matches!(&filter, Some(DecisionFilter::Allow));
    if is_allow_filter {
        println!("{}", crate::output::allowlist_table(&config.allowlists.commands));
    } else {
        crate::output::print_allowlist_summary(&config.allowlists.commands);
    }

    crate::output::print_footer(config);

    0
}
```

**Step 3: Delete old `print_allowlist_summary` from cli.rs**

Remove the old function -- it's now in output.rs.

**Step 4: Also delete the now-unused wrapper functions**

Remove `print_rules_table`, `print_rules_grouped_by_decision`, `print_rules_grouped_by_level` from cli.rs since `run_rules` now calls output.rs directly.

**Step 5: Run tests and verify**

Run: `cargo build && cargo test`
Run: `echo '' | cargo run -- --config rules/default-rules.yaml rules --filter allow`
Expected: Any explicit allow rules in a table, then a full bordered table listing every allowlisted command (green text)

Run: `echo '' | cargo run -- --config rules/default-rules.yaml rules --filter deny`
Expected: Deny rules table + compact allowlist summary

**Step 6: Commit**

```bash
git add src/output.rs src/cli.rs
git commit -m "feat: expand full allowlist display for --filter allow"
```

---

### Task 7: Initialize color support with NO_COLOR respect

**Files:**
- Modify: `src/cli.rs`

**Step 1: Add yansi color initialization at startup**

At the top of `cli::run()`, before anything else:

```rust
pub fn run() -> i32 {
    // Respect NO_COLOR convention and non-TTY detection
    yansi::whenever(yansi::Condition::TTY_AND_COLOR);

    let cli = Cli::parse();
    // ... rest unchanged
```

This makes yansi automatically disable colors when:
- `NO_COLOR` env var is set
- stdout is not a TTY (e.g., piped to a file)

For comfy-table: it respects `NO_COLOR` by default when the `tty` feature is enabled (which is the default).

**Step 2: Verify**

Run: `echo '' | cargo run -- --config rules/default-rules.yaml rules | cat`
Expected: No ANSI escape codes in output (piped to cat = not a TTY)

Run: `NO_COLOR=1 cargo run -- --config rules/default-rules.yaml rules < /dev/null`
Expected: No ANSI escape codes

Run: `cargo run -- --config rules/default-rules.yaml rules < /dev/null`
Expected: Colors visible (assuming terminal)

**Step 3: Commit**

```bash
git add src/cli.rs
git commit -m "feat: respect NO_COLOR convention for terminal output"
```

---

### Task 8: Clean up cli.rs -- remove dead code

**Files:**
- Modify: `src/cli.rs`

**Step 1: Remove all dead output functions from cli.rs**

After Tasks 2-6, the following functions in cli.rs should be dead code (moved to output.rs):
- `print_rules_table` (if not already removed)
- `print_rules_grouped_by_decision` (if not already removed)
- `print_rules_grouped_by_level` (if not already removed)
- `print_matcher_details` (if not already removed)
- `format_string_or_list` (if not already removed)
- `print_allowlist_summary` (if not already removed)

Remove any that still exist. The compiler will tell you if any are still referenced.

**Step 2: Run full test suite**

Run: `cargo test`
Run: `cargo clippy -- -D warnings`
Expected: All pass, no warnings

**Step 3: Commit**

```bash
git add src/cli.rs
git commit -m "refactor: remove dead output functions from cli.rs"
```

---

### Task 9: Update golden tests (if needed)

**Context:** Golden tests in `tests/golden/*.yaml` test the hook protocol (JSON stdin/stdout), not the CLI subcommands. Integration tests in `tests/integration.rs` test the full binary. If any tests check `rules` or `check` subcommand output, they'll need updating for the new table format.

**Step 1: Check what integration tests assert on**

Read `tests/integration.rs` and check if any tests invoke `rules` or `check` subcommands and assert on their output format.

**Step 2: If tests exist that check formatted output, update expected strings**

Update to match the new comfy-table unicode border format.

**Step 3: Run full suite**

Run: `cargo test`
Expected: All pass

**Step 4: Commit if any changes**

```bash
git add tests/
git commit -m "test: update expected output for comfy-table formatting"
```
