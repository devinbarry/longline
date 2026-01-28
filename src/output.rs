use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement,
    Table,
};

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

/// Build a default rules table with 4 columns: DECISION, LEVEL, ID, DESCRIPTION.
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
            Cell::new(rule.level),
            Cell::new(&rule.id),
            Cell::new(&rule.reason),
        ]);
    }

    table
}

/// Build a verbose rules table with 6 columns: DECISION, LEVEL, ID, MATCH, PATTERN, DESCRIPTION.
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
            Cell::new(rule.level),
            Cell::new(&rule.id),
            Cell::new(match_type),
            Cell::new(pattern),
            Cell::new(&rule.reason),
        ]);
    }

    table
}

/// Return (match_type, pattern) for a matcher, used in the verbose table.
fn format_matcher(matcher: &policy::Matcher) -> (String, String) {
    match matcher {
        policy::Matcher::Command {
            command,
            flags,
            args,
        } => {
            let mut parts = vec![format!("cmd={}", format_string_or_list(command))];
            if let Some(f) = flags {
                let mut flag_items = Vec::new();
                if !f.any_of.is_empty() {
                    flag_items.extend(f.any_of.iter().cloned());
                }
                if !f.all_of.is_empty() {
                    flag_items.extend(f.all_of.iter().cloned());
                }
                if !flag_items.is_empty() {
                    parts.push(format!("flags={{{}}}", flag_items.join(", ")));
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

/// Format a StringOrList as "value" or "{a, b, c}".
fn format_string_or_list(sol: &policy::StringOrList) -> String {
    match sol {
        policy::StringOrList::Single(s) => s.clone(),
        policy::StringOrList::List { any_of } => format!("{{{}}}", any_of.join(", ")),
    }
}

/// Print rules grouped by decision (Deny, Ask, Allow) with colored section headers.
pub fn print_rules_grouped_by_decision(rules: &[&policy::Rule], verbose: bool) {
    for decision in &[Decision::Deny, Decision::Ask, Decision::Allow] {
        let group: Vec<&policy::Rule> = rules
            .iter()
            .filter(|r| r.decision == *decision)
            .copied()
            .collect();
        if group.is_empty() {
            continue;
        }

        let header = match decision {
            Decision::Deny => yansi::Paint::red("DENY").bold(),
            Decision::Ask => yansi::Paint::yellow("ASK").bold(),
            Decision::Allow => yansi::Paint::green("ALLOW").bold(),
        };
        println!("\n{header}");

        let refs: Vec<&policy::Rule> = group.to_vec();
        if verbose {
            println!("{}", rules_table_verbose(&refs));
        } else {
            println!("{}", rules_table(&refs));
        }
    }
}

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

/// Build a table showing all allowlisted commands.
pub fn allowlist_table(commands: &[String]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("ALLOWLISTED COMMANDS").add_attribute(Attribute::Bold)
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

/// Print rules grouped by safety level (Critical, High, Strict) with bold section headers.
pub fn print_rules_grouped_by_level(rules: &[&policy::Rule], verbose: bool) {
    for level_val in &[
        policy::SafetyLevel::Critical,
        policy::SafetyLevel::High,
        policy::SafetyLevel::Strict,
    ] {
        let group: Vec<&policy::Rule> = rules
            .iter()
            .filter(|r| r.level == *level_val)
            .copied()
            .collect();
        if group.is_empty() {
            continue;
        }

        let header = yansi::Paint::new(level_val.to_string().to_uppercase()).bold();
        println!("\n{header}");

        let refs: Vec<&policy::Rule> = group.to_vec();
        if verbose {
            println!("{}", rules_table_verbose(&refs));
        } else {
            println!("{}", rules_table(&refs));
        }
    }
}
