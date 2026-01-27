use clap::Parser as ClapParser;
use std::io::Read;
use std::path::PathBuf;

use crate::logger;
use crate::parser;
use crate::policy;
use crate::types::{Decision, HookInput, HookOutput, PolicyResult};

#[derive(ClapParser)]
#[command(name = "longline", version, about = "Safety hook for Claude Code")]
struct Args {
    /// Path to rules YAML file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Dry-run mode: evaluate but prefix output
    #[arg(long)]
    dry_run: bool,
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
    let args = Args::parse();

    // Load rules config
    let config_path = args.config.unwrap_or_else(default_config_path);
    let rules_config = match policy::load_rules(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("longline: {e}");
            return 2;
        }
    };

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
    let result = policy::evaluate(&rules_config, &stmt);

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
