use clap::Parser as ClapParser;
use clap::Subcommand;
use std::io::Read;
use std::path::PathBuf;

use crate::ai_judge;
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

    /// Use AI to evaluate inline interpreter code instead of asking
    #[arg(long)]
    ask_ai: bool,

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
    yansi::whenever(yansi::Condition::TTY_AND_COLOR);

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
        None => run_hook(&rules_config, cli.ask_on_deny, cli.ask_ai),
    }
}

/// Run hook mode: read stdin, evaluate, output decision.
fn run_hook(rules_config: &policy::RulesConfig, ask_on_deny: bool, ask_ai: bool) -> i32 {
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
        let output = HookOutput::decision(Decision::Allow, "longline: non-Bash tool");
        print_json(&output);
        return 0;
    }

    let command = match &hook_input.tool_input.command {
        Some(cmd) => cmd.as_str(),
        None => {
            let output = HookOutput::decision(Decision::Allow, "longline: no command");
            print_json(&output);
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

    let (initial_decision, overridden) = if ask_on_deny && result.decision == Decision::Deny {
        (Decision::Ask, true)
    } else {
        (result.decision, false)
    };

    // AI judge: evaluate inline interpreter code instead of asking user
    let (final_decision, ai_reason) = if ask_ai && initial_decision == Decision::Ask {
        let ai_config = ai_judge::load_config();
        match ai_judge::extract_inline_code(&stmt, &ai_config) {
            Some((language, code)) => {
                // Default to "." if cwd is empty or missing
                let cwd = hook_input
                    .cwd
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(".");
                let (ai_decision, reason) = ai_judge::evaluate(&ai_config, &language, &code, cwd);
                eprintln!("longline: ai-judge evaluated {language} code: {ai_decision}");
                (ai_decision, Some(reason))
            }
            None => (initial_decision, None),
        }
    } else {
        (initial_decision, None)
    };

    // Log the decision
    // Use AI reason if available, otherwise policy reason
    let log_reason = if let Some(ref ai_reason) = ai_reason {
        Some(ai_reason.clone())
    } else if result.reason.is_empty() {
        None
    } else {
        Some(result.reason.clone())
    };
    let mut entry = logger::make_entry(
        &hook_input.tool_name,
        hook_input.cwd.as_deref().unwrap_or(""),
        command,
        final_decision,
        result.rule_id.clone().into_iter().collect(),
        log_reason,
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
            // Use AI reason if available, otherwise policy reason
            let reason = if let Some(ref ai_reason) = ai_reason {
                format!("longline: {}", ai_reason)
            } else {
                format!("longline: {}", result.reason)
            };
            let output = HookOutput::decision(Decision::Allow, &reason);
            print_json(&output);
        }
        Decision::Ask | Decision::Deny => {
            // Use AI reason if available, otherwise policy reason
            let reason = if let Some(ref ai_reason) = ai_reason {
                ai_reason.clone()
            } else if overridden {
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
        println!(
            "{}",
            crate::output::allowlist_table(&config.allowlists.commands)
        );
    } else {
        crate::output::print_allowlist_summary(&config.allowlists.commands);
    }

    println!(
        "Safety level: {} | Default decision: {}",
        config.safety_level, config.default_decision
    );

    0
}

fn format_reason(result: &PolicyResult) -> String {
    match &result.rule_id {
        Some(id) => format!("[{id}] {}", result.reason),
        None => result.reason.clone(),
    }
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
