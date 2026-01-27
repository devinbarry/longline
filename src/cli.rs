use clap::Parser as ClapParser;
use clap::Subcommand;
use std::io::Read;
use std::path::PathBuf;

use crate::logger;
use crate::parser;
use crate::policy;
use crate::types::{Decision, HookInput, HookOutput, PolicyResult};

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

/// Default config file path.
fn default_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
        .join(".config")
        .join("longline")
        .join("rules.yaml")
}

/// Main entry point. Returns the process exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();

    // Load rules config
    let config_path = cli.config.unwrap_or_else(default_config_path);
    let rules_config = match policy::load_rules(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("longline: {e}");
            return 2;
        }
    };

    match cli.command {
        Some(Commands::Check { file, filter }) => run_check(&rules_config, file, filter),
        Some(Commands::Rules {
            verbose,
            filter,
            level,
            group_by,
        }) => run_rules(&rules_config, verbose, filter, level, group_by),
        None => run_hook(&rules_config, cli.ask_on_deny),
    }
}

/// Run hook mode: read stdin, evaluate, output decision.
fn run_hook(rules_config: &policy::RulesConfig, ask_on_deny: bool) -> i32 {
    // Read hook input from stdin
    let mut input_str = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input_str) {
        let output = HookOutput::decision(Decision::Ask, "Failed to read stdin");
        print_json(&output);
        eprintln!("longline: failed to read stdin: {e}");
        return 0;
    }

    let hook_input: HookInput = match serde_json::from_str(&input_str) {
        Ok(h) => h,
        Err(e) => {
            let output =
                HookOutput::decision(Decision::Ask, &format!("Failed to parse hook input: {e}"));
            print_json(&output);
            return 0;
        }
    };

    // Only handle Bash tool in MVP
    if hook_input.tool_name != "Bash" {
        print_allow();
        return 0;
    }

    let command = match &hook_input.tool_input.command {
        Some(cmd) => cmd.as_str(),
        None => {
            print_allow();
            return 0;
        }
    };

    // Parse the bash command
    let (stmt, parse_ok) = match parser::parse(command) {
        Ok(s) => (s, true),
        Err(e) => {
            let output =
                HookOutput::decision(Decision::Ask, &format!("Failed to parse bash command: {e}"));
            print_json(&output);

            let entry = logger::make_entry(
                &hook_input.tool_name,
                hook_input.cwd.as_deref().unwrap_or(""),
                command,
                Decision::Ask,
                vec![],
                Some(format!("Parse error: {e}")),
                false,
                hook_input.session_id.clone(),
            );
            logger::log_decision(&entry);
            return 0;
        }
    };

    // Evaluate against policy
    let result = policy::evaluate(rules_config, &stmt);

    let (final_decision, overridden) = if ask_on_deny && result.decision == Decision::Deny {
        (Decision::Ask, true)
    } else {
        (result.decision, false)
    };

    // Log the decision
    let mut entry = logger::make_entry(
        &hook_input.tool_name,
        hook_input.cwd.as_deref().unwrap_or(""),
        command,
        final_decision,
        result.rule_id.clone().into_iter().collect(),
        if result.reason.is_empty() {
            None
        } else {
            Some(result.reason.clone())
        },
        parse_ok,
        hook_input.session_id.clone(),
    );
    if overridden {
        entry.original_decision = Some(result.decision);
        entry.overridden = true;
    }
    logger::log_decision(&entry);

    // Output the decision
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

    0
}

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

    println!("{:<10}{:<18}COMMAND", "DECISION", "RULE");

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
        Some(path) if path.to_str() != Some("-") => std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display())),
        _ => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("Failed to read stdin: {e}"))?;
            Ok(buf)
        }
    }
}

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
    println!(
        "Safety level: {} | Default decision: {}",
        config.safety_level, config.default_decision
    );

    0
}

fn print_rules_table(rules: &[&policy::Rule], verbose: bool) {
    println!("{:<10}{:<10}{:<28}DESCRIPTION", "DECISION", "LEVEL", "ID");
    for rule in rules {
        println!(
            "{:<10}{:<10}{:<28}{}",
            rule.decision, rule.level, rule.id, rule.reason
        );
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
    for level_val in &[
        policy::SafetyLevel::Critical,
        policy::SafetyLevel::High,
        policy::SafetyLevel::Strict,
    ] {
        let group: Vec<_> = rules.iter().filter(|r| r.level == *level_val).collect();
        if group.is_empty() {
            continue;
        }
        println!("-- {} {}", level_val, "-".repeat(55));
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
        policy::Matcher::Command {
            command,
            flags,
            args,
        } => {
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

fn format_reason(result: &PolicyResult) -> String {
    match &result.rule_id {
        Some(id) => format!("[{id}] {}", result.reason),
        None => result.reason.clone(),
    }
}

/// Print the empty JSON object to allow the operation.
fn print_allow() {
    println!("{{}}");
}

/// Print a JSON value to stdout.
fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("longline: failed to serialize output: {e}");
            println!("{{}}");
        }
    }
}
