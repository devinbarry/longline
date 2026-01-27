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
fn run_hook(rules_config: &policy::RulesConfig, _ask_on_deny: bool) -> i32 {
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
            let output = HookOutput::decision(
                Decision::Ask,
                &format!("Failed to parse hook input: {e}"),
            );
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
            let output = HookOutput::decision(
                Decision::Ask,
                &format!("Failed to parse bash command: {e}"),
            );
            print_json(&output);

            log_result(
                &hook_input,
                command,
                Decision::Ask,
                vec![],
                Some(format!("Parse error: {e}")),
                false,
            );
            return 0;
        }
    };

    // Evaluate against policy
    let result = policy::evaluate(rules_config, &stmt);

    // Log the decision
    log_result(
        &hook_input,
        command,
        result.decision,
        result.rule_id.clone().into_iter().collect(),
        if result.reason.is_empty() {
            None
        } else {
            Some(result.reason.clone())
        },
        parse_ok,
    );

    // Output the decision
    match result.decision {
        Decision::Allow => {
            print_allow();
        }
        Decision::Ask | Decision::Deny => {
            let reason = format_reason(&result);
            let output = HookOutput::decision(result.decision, &reason);
            print_json(&output);
        }
    }

    0
}

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

/// Log the evaluation result.
fn log_result(
    hook_input: &HookInput,
    command: &str,
    decision: Decision,
    matched_rules: Vec<String>,
    reason: Option<String>,
    parse_ok: bool,
) {
    let entry = logger::make_entry(
        &hook_input.tool_name,
        hook_input.cwd.as_deref().unwrap_or(""),
        command,
        decision,
        matched_rules,
        reason,
        parse_ok,
        hook_input.session_id.clone(),
    );
    logger::log_decision(&entry);
}
