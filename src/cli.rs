use clap::Parser as ClapParser;
use clap::Subcommand;
use std::io::Read;
use std::path::PathBuf;

use crate::logger;
use longline::ai_judge;
use longline::parser;
use longline::policy;
use longline::types::{Decision, HookInput, HookOutput, PolicyResult};

#[derive(ClapParser)]
#[command(name = "longline", version, about = "Safety hook for Claude Code")]
struct Cli {
    /// Path to rules YAML file
    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    /// Override trust level (minimal, standard, full)
    #[arg(long, value_name = "LEVEL", global = true)]
    trust_level: Option<TrustLevelArg>,

    /// Downgrade deny decisions to ask (hook mode only)
    #[arg(long)]
    ask_on_deny: bool,

    /// Use AI to evaluate inline interpreter code instead of asking
    #[arg(long)]
    ask_ai: bool,

    /// Use AI to evaluate inline interpreter code with a lenient prompt (implies AI judge)
    #[arg(long = "ask-ai-lenient", visible_alias = "lenient")]
    ask_ai_lenient: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, clap::ValueEnum)]
enum TrustLevelArg {
    Minimal,
    Standard,
    Full,
}

impl TrustLevelArg {
    fn to_trust_level(&self) -> policy::TrustLevel {
        match self {
            TrustLevelArg::Minimal => policy::TrustLevel::Minimal,
            TrustLevelArg::Standard => policy::TrustLevel::Standard,
            TrustLevelArg::Full => policy::TrustLevel::Full,
        }
    }
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
    /// Show loaded rule files and their contents
    Files,
    /// Extract embedded rules to ~/.config/longline/ for customization
    Init {
        /// Overwrite existing files
        #[arg(short, long)]
        force: bool,
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

/// Load rules config with fallback: --config flag > default path > embedded.
fn load_config(explicit_path: Option<&PathBuf>) -> Result<policy::RulesConfig, String> {
    if let Some(path) = explicit_path {
        return policy::load_rules(path);
    }

    let default_path = default_config_path();
    if default_path.exists() {
        return policy::load_rules(&default_path);
    }

    policy::load_embedded_rules()
}

/// Main entry point. Returns the process exit code.
pub fn run() -> i32 {
    yansi::whenever(yansi::Condition::TTY_AND_COLOR);

    let cli = Cli::parse();

    // Handle Files command early (needs path before loading)
    if let Some(Commands::Files) = &cli.command {
        return run_files(cli.config.as_ref(), cli.trust_level.as_ref());
    }

    // Handle Init command early (no config needed)
    if let Some(Commands::Init { force }) = &cli.command {
        return run_init(*force);
    }

    // Load rules config for other commands
    let mut rules_config = match load_config(cli.config.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("longline: {e}");
            return 2;
        }
    };

    // Apply CLI trust level override
    if let Some(ref level) = cli.trust_level {
        rules_config.trust_level = level.to_trust_level();
    }

    match cli.command {
        Some(Commands::Check { file, filter }) => run_check(&rules_config, file, filter),
        Some(Commands::Rules {
            verbose,
            filter,
            level,
            group_by,
        }) => run_rules(&rules_config, verbose, filter, level, group_by),
        Some(Commands::Files) => unreachable!(), // handled above
        Some(Commands::Init { .. }) => unreachable!(), // handled above
        None => run_hook(
            rules_config,
            cli.ask_on_deny,
            cli.ask_ai || cli.ask_ai_lenient,
            cli.ask_ai_lenient,
        ),
    }
}

/// Run hook mode: read stdin, evaluate, output decision.
fn run_hook(
    mut rules_config: policy::RulesConfig,
    ask_on_deny: bool,
    ask_ai: bool,
    ask_ai_lenient: bool,
) -> i32 {
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

    // Load and merge per-project config
    if let Some(ref cwd) = hook_input.cwd {
        match policy::load_project_config(std::path::Path::new(cwd)) {
            Ok(Some(project_config)) => {
                policy::merge_project_config(&mut rules_config, project_config);
            }
            Ok(None) => {} // No project config file
            Err(e) => {
                eprintln!("longline: {e}");
                return 2;
            }
        }
    }

    // Only handle Bash tool - passthrough for everything else
    if hook_input.tool_name != "Bash" {
        println!("{{}}");
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
    let result = policy::evaluate(&rules_config, &stmt);

    let (initial_decision, overridden) = if ask_on_deny && result.decision == Decision::Deny {
        (Decision::Ask, true)
    } else {
        (result.decision, false)
    };

    // AI judge: evaluate inline interpreter code instead of asking user
    let (final_decision, ai_reason) = if ask_ai && initial_decision == Decision::Ask {
        let ai_config = ai_judge::load_config();
        // Default to "." if cwd is empty or missing
        let cwd = hook_input
            .cwd
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(".");
        match ai_judge::extract_code(command, &stmt, cwd, &ai_config) {
            Some(extracted) => {
                let (ai_decision, reason) = if ask_ai_lenient {
                    ai_judge::evaluate_lenient(
                        &ai_config,
                        &extracted.language,
                        &extracted.code,
                        cwd,
                        extracted.context.as_deref(),
                    )
                } else {
                    ai_judge::evaluate(
                        &ai_config,
                        &extracted.language,
                        &extracted.code,
                        cwd,
                        extracted.context.as_deref(),
                    )
                };
                if ask_ai_lenient {
                    eprintln!(
                        "longline: ai-judge evaluated {} code (lenient): {ai_decision}",
                        extracted.language
                    );
                } else {
                    eprintln!(
                        "longline: ai-judge evaluated {} code: {ai_decision}",
                        extracted.language
                    );
                }
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
                format!("longline: {}", ai_reason)
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
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                return Err(
                    "No input provided. Use --file <path> or pipe commands to stdin.".to_string(),
                );
            }
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

    // Filter allowlist entries by trust level
    let active_commands: Vec<policy::AllowlistEntry> = config
        .allowlists
        .commands
        .iter()
        .filter(|e| e.trust <= config.trust_level)
        .cloned()
        .collect();
    let active_count = active_commands.len();
    let total_count = config.allowlists.commands.len();

    // Show full allowlist when filtering to allow, compact summary otherwise
    let is_allow_filter = matches!(&filter, Some(DecisionFilter::Allow));
    if is_allow_filter {
        println!("{}", crate::output::allowlist_table(&active_commands));
    } else {
        crate::output::print_allowlist_summary(&active_commands);
    }

    println!(
        "Safety level: {} | Trust level: {} ({}/{} allowlist active) | Default decision: {}",
        config.safety_level, config.trust_level, active_count, total_count, config.default_decision
    );

    0
}

fn run_files(config_path: Option<&PathBuf>, trust_override: Option<&TrustLevelArg>) -> i32 {
    let loaded = if let Some(path) = config_path {
        match policy::load_rules_with_info(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("longline: {e}");
                return 2;
            }
        }
    } else {
        let default_path = default_config_path();
        if default_path.exists() {
            match policy::load_rules_with_info(&default_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("longline: {e}");
                    return 2;
                }
            }
        } else {
            match policy::load_embedded_rules_with_info() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("longline: {e}");
                    return 2;
                }
            }
        }
    };

    if let Some(path) = &loaded.rules_manifest_path {
        println!("Rules manifest: {}", path.display());
    } else if loaded.is_rules_manifest {
        println!("Source: embedded defaults");
    } else {
        println!("Config: (single file)");
    }
    let trust_level = match trust_override {
        Some(level) => level.to_trust_level(),
        None => loaded.config.trust_level,
    };
    println!(
        "Safety level: {} | Trust level: {}",
        loaded.config.safety_level, trust_level
    );
    println!();

    if loaded.is_rules_manifest {
        println!("Included files:");
        for file in &loaded.files {
            println!(
                "  {:<30} ({} allowlist: {} min/{} std/{} full, {} rules)",
                file.name,
                file.allowlist_count,
                file.trust_counts[0],
                file.trust_counts[1],
                file.trust_counts[2],
                file.rule_count
            );
        }
        println!();
    }

    let total_allowlist: usize = loaded.files.iter().map(|f| f.allowlist_count).sum();
    let total_rules: usize = loaded.files.iter().map(|f| f.rule_count).sum();
    let total_trust: [usize; 3] = loaded.files.iter().fold([0; 3], |mut acc, f| {
        acc[0] += f.trust_counts[0];
        acc[1] += f.trust_counts[1];
        acc[2] += f.trust_counts[2];
        acc
    });
    println!(
        "Total: {} allowlist entries ({} min/{} std/{} full), {} rules",
        total_allowlist, total_trust[0], total_trust[1], total_trust[2], total_rules
    );

    0
}

fn run_init(force: bool) -> i32 {
    let target_dir = default_config_path()
        .parent()
        .expect("default config path has parent")
        .to_path_buf();
    let rules_yaml_path = target_dir.join("rules.yaml");

    if rules_yaml_path.exists() && !force {
        eprintln!(
            "longline: {} already exists. Use --force to overwrite.",
            rules_yaml_path.display()
        );
        return 1;
    }

    if let Err(e) = std::fs::create_dir_all(&target_dir) {
        eprintln!("longline: failed to create {}: {e}", target_dir.display());
        return 1;
    }

    for (name, content) in longline::embedded_rules::all_files() {
        let file_path = target_dir.join(name);
        if let Err(e) = std::fs::write(&file_path, content) {
            eprintln!("longline: failed to write {}: {e}", file_path.display());
            return 1;
        }
    }

    println!("Rules written to {}", target_dir.display());
    println!("Edit {} to customize.", rules_yaml_path.display());

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parses_ask_ai_lenient_flag() {
        let cli = Cli::try_parse_from(["longline", "--ask-ai-lenient"]).unwrap();
        assert!(cli.ask_ai_lenient);
    }

    #[test]
    fn test_cli_parses_lenient_alias_flag() {
        let cli = Cli::try_parse_from(["longline", "--lenient"]).unwrap();
        assert!(cli.ask_ai_lenient);
    }
}
