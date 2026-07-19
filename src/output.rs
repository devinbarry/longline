use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement,
    Table,
};

use longline::domain::Decision;
use longline::policy;

/// Map a RuleSource to its display color.
fn source_color(s: policy::RuleSource) -> Color {
    match s {
        policy::RuleSource::BuiltIn => Color::DarkGrey,
        policy::RuleSource::Global => Color::Blue,
        policy::RuleSource::Project => Color::Cyan,
    }
}

/// Create a colored Cell for a RuleSource value.
fn source_cell(s: policy::RuleSource) -> Cell {
    let label = match s {
        policy::RuleSource::BuiltIn => "builtin",
        policy::RuleSource::Global => "global",
        policy::RuleSource::Project => "project",
    };
    Cell::new(label).fg(source_color(s))
}

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

/// Build a default rules table with 5 columns: DECISION, LEVEL, ID, DESCRIPTION, SOURCE.
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
            Cell::new("SOURCE").add_attribute(Attribute::Bold),
        ]);

    for rule in rules {
        table.add_row(vec![
            decision_cell(rule.decision),
            Cell::new(rule.level),
            Cell::new(&rule.id),
            Cell::new(&rule.reason),
            source_cell(rule.source),
        ]);
    }

    table
}

/// Build a verbose rules table with 7 columns: DECISION, LEVEL, ID, MATCH, PATTERN, DESCRIPTION, SOURCE.
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
            Cell::new("SOURCE").add_attribute(Attribute::Bold),
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
            source_cell(rule.source),
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
            env,
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
            if let Some(e) = env {
                parts.push(format!("env={{{}}}", e.any_of.join(", ")));
                parts.push(format!(
                    "env_case={}",
                    if e.case_insensitive {
                        "insensitive"
                    } else {
                        "sensitive"
                    }
                ));
                if !e.except.is_empty() {
                    let exceptions = e
                        .except
                        .iter()
                        .map(|exception| {
                            format!(
                                "{{names={{{}}} name_case={} value_class={}}}",
                                exception.names.join(", "),
                                if exception.name_case_insensitive {
                                    "insensitive"
                                } else {
                                    "sensitive"
                                },
                                exception.value_class
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    parts.push(format!("env_except=[{exceptions}]"));
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
        policy::Matcher::GitConfig { git_config } => (
            "git_config".to_string(),
            format!(
                "cmd={} source={} keys={{{}}} key_case={} except_value_class={}",
                format_string_or_list(&git_config.command),
                git_config.source,
                git_config.keys.join(", "),
                if git_config.key_case_insensitive {
                    "insensitive"
                } else {
                    "sensitive"
                },
                git_config.except_value_class,
            ),
        ),
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

/// Map a TrustLevel to its display color.
fn trust_color(t: policy::TrustLevel) -> Color {
    match t {
        policy::TrustLevel::Minimal => Color::Cyan,
        policy::TrustLevel::Standard => Color::Green,
        policy::TrustLevel::Full => Color::Yellow,
    }
}

/// Build a table showing all allowlisted commands with trust level and source.
pub fn allowlist_table(commands: &[policy::AllowlistEntry]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("ALLOWLISTED COMMANDS").add_attribute(Attribute::Bold),
            Cell::new("TRUST").add_attribute(Attribute::Bold),
            Cell::new("SOURCE").add_attribute(Attribute::Bold),
        ]);

    for entry in commands {
        table.add_row(vec![
            Cell::new(&entry.command).fg(Color::Green),
            Cell::new(entry.trust).fg(trust_color(entry.trust)),
            source_cell(entry.source),
        ]);
    }

    table
}

/// Print allowlist summary (compact, for non-allow-filter views).
pub fn print_allowlist_summary(commands: &[policy::AllowlistEntry]) {
    if commands.is_empty() {
        println!("Allowlist: (none)");
        return;
    }
    let display: Vec<&str> = commands
        .iter()
        .take(10)
        .map(|e| e.command.as_str())
        .collect();
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

// ── profiles subcommand output ────────────────────────────────────────────────

pub struct ProfileRow {
    pub name: String,
    pub extends: Option<String>,
    pub safety: String,
    pub rule_count: usize,
    pub allowlist_count: usize,
    pub ai_judge_source: &'static str,
    pub source: &'static str,
}

pub fn print_profiles_table(rows: &[ProfileRow]) {
    println!(
        "{:<12} {:<10} {:<8} {:<7} {:<11} {:<17} SOURCE",
        "NAME", "EXTENDS", "SAFETY", "RULES", "ALLOWLIST", "AI_JUDGE_SOURCE"
    );
    for r in rows {
        println!(
            "{:<12} {:<10} {:<8} {:<7} {:<11} {:<17} {}",
            r.name,
            r.extends.as_deref().unwrap_or("\u{2014}"),
            r.safety,
            r.rule_count,
            r.allowlist_count,
            r.ai_judge_source,
            r.source
        );
    }
}

pub fn print_profile_default_for_runtime(runtime: &str, resolved: &str, source: &str) {
    println!("Default profile for {runtime}: {resolved}  (source: {source})");
}

pub fn print_profiles_json(
    rows: &[ProfileRow],
    defaults_resolution: &[(String, String, String)], // (runtime, resolved_name, source)
) {
    let profiles_json: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "extends": r.extends,
                "safety": r.safety,
                "rule_count": r.rule_count,
                "allowlist_count": r.allowlist_count,
                "ai_judge_source": r.ai_judge_source,
                "source": r.source,
            })
        })
        .collect();
    let defaults_json: serde_json::Map<String, serde_json::Value> = defaults_resolution
        .iter()
        .map(|(runtime, name, source)| {
            (
                runtime.clone(),
                serde_json::json!({ "name": name, "source": source }),
            )
        })
        .collect();
    let out = serde_json::json!({
        "profiles": profiles_json,
        "defaults": defaults_json,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

#[cfg(test)]
mod tests {
    use super::format_matcher;
    use longline::policy::{
        EnvException, EnvMatcher, EnvValueClass, GitConfigMatcher, GitConfigSource, Matcher,
        StringOrList,
    };

    #[test]
    fn verbose_command_matcher_formats_environment_exceptions_deterministically() {
        let matcher = Matcher::Command {
            command: StringOrList::Single("git".to_string()),
            flags: None,
            args: None,
            env: Some(EnvMatcher {
                any_of: vec!["GIT_SSH_COMMAND".to_string(), "GIT_EDITOR".to_string()],
                case_insensitive: true,
                except: vec![EnvException {
                    names: vec!["GIT_EDITOR".to_string(), "EDITOR".to_string()],
                    name_case_insensitive: false,
                    value_class: EnvValueClass::ShellNoop,
                }],
            }),
        };

        assert_eq!(
            format_matcher(&matcher),
            (
                "command".to_string(),
                "cmd=git env={GIT_SSH_COMMAND, GIT_EDITOR} env_case=insensitive env_except=[{names={GIT_EDITOR, EDITOR} name_case=sensitive value_class=shell-noop}]"
                    .to_string(),
            )
        );
    }

    #[test]
    fn verbose_git_config_matcher_formats_every_field_deterministically() {
        let matcher = Matcher::GitConfig {
            git_config: GitConfigMatcher {
                command: StringOrList::List {
                    any_of: vec!["git".to_string(), "git-safe".to_string()],
                },
                source: GitConfigSource::CliC,
                keys: vec!["core.editor".to_string(), "sequence.editor".to_string()],
                key_case_insensitive: true,
                except_value_class: EnvValueClass::ShellNoop,
            },
        };

        assert_eq!(
            format_matcher(&matcher),
            (
                "git_config".to_string(),
                "cmd={git, git-safe} source=cli-c keys={core.editor, sequence.editor} key_case=insensitive except_value_class=shell-noop".to_string(),
            )
        );
    }
}
