use clap::Parser as ClapParser;
use clap::Subcommand;
use std::path::PathBuf;

use crate::adapters::claude;
use longline::config;
use longline::domain::Decision;
use longline::parser;
use longline::policy;

#[derive(ClapParser)]
#[command(name = "longline", version, about = "Safety hook for Claude Code")]
struct Cli {
    /// Path to rules YAML file
    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    /// Override trust level (minimal, standard, full)
    #[arg(long, value_name = "LEVEL", global = true)]
    trust_level: Option<TrustLevelArg>,

    /// Override safety level (critical, high, strict)
    #[arg(long, value_name = "LEVEL", global = true)]
    safety_level: Option<SafetyLevelArg>,

    /// Project directory for .claude/longline.yaml discovery (defaults to cwd)
    #[arg(long, value_name = "DIR", global = true)]
    dir: Option<PathBuf>,

    /// Profile to activate (overrides runtime default)
    #[arg(short = 'p', long)]
    profile: Option<String>,

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

#[derive(Clone, clap::ValueEnum)]
enum SafetyLevelArg {
    Critical,
    High,
    Strict,
}

impl SafetyLevelArg {
    fn to_safety_level(&self) -> policy::SafetyLevel {
        match self {
            SafetyLevelArg::Critical => policy::SafetyLevel::Critical,
            SafetyLevelArg::High => policy::SafetyLevel::High,
            SafetyLevelArg::Strict => policy::SafetyLevel::Strict,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Test commands against rules
    Check {
        /// File with one command per line (stdin if omitted)
        file: Option<PathBuf>,

        /// Show only: allow, ask, deny
        #[arg(short, long)]
        filter: Option<DecisionFilter>,

        /// Profile to activate (overrides runtime default)
        #[arg(short = 'p', long)]
        profile: Option<String>,
    },
    /// Show current rule configuration
    Rules {
        /// Show full matcher patterns and details
        #[arg(short, long)]
        verbose: bool,

        /// Filter rules/allowlist [decision:allow|ask|deny, trust:minimal|standard|full, source:builtin|global|project]
        #[arg(short, long, value_parser = clap::value_parser!(RulesFilter))]
        filter: Vec<RulesFilter>,

        /// Show only: critical, high, strict
        #[arg(short, long)]
        level: Option<LevelFilter>,

        /// Group by: decision, level
        #[arg(short, long)]
        group_by: Option<GroupBy>,

        /// Profile to activate (overrides runtime default)
        #[arg(short = 'p', long)]
        profile: Option<String>,
    },
    /// Show loaded rule files and their contents
    Files {
        /// Profile to activate (overrides runtime default)
        #[arg(short = 'p', long)]
        profile: Option<String>,
    },
    /// Extract embedded rules to ~/.config/longline/ for customization
    Init {
        /// Overwrite existing files
        #[arg(short, long)]
        force: bool,
    },
    /// Run a hook for a specific runtime (Codex or explicit Claude)
    Hook {
        /// Adapter to dispatch to
        #[arg(value_enum)]
        adapter: HookAdapter,

        /// Profile to activate (overrides runtime default)
        #[arg(short = 'p', long)]
        profile: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
enum HookAdapter {
    Claude,
    Codex,
}

#[derive(Clone, Debug)]
enum RulesFilter {
    Decision(DecisionFilter),
    Trust(policy::TrustLevel),
    Source(policy::RuleSource),
}

impl std::str::FromStr for RulesFilter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try dimension:value format first
        if let Some((dim, val)) = s.split_once(':') {
            match dim {
                "decision" => parse_decision(val).map(RulesFilter::Decision),
                "trust" => parse_trust(val).map(RulesFilter::Trust),
                "source" => parse_source(val).map(RulesFilter::Source),
                _ => Err(format!(
                    "unknown filter dimension '{}' -- valid dimensions: decision, trust, source",
                    dim
                )),
            }
        } else {
            // Bare value: try as decision (backwards compat)
            parse_decision(s).map(RulesFilter::Decision)
        }
    }
}

fn parse_decision(s: &str) -> Result<DecisionFilter, String> {
    match s {
        "allow" => Ok(DecisionFilter::Allow),
        "ask" => Ok(DecisionFilter::Ask),
        "deny" => Ok(DecisionFilter::Deny),
        _ => Err(format!(
            "invalid filter '{}' -- valid decision values: allow, ask, deny",
            s
        )),
    }
}

fn parse_trust(s: &str) -> Result<policy::TrustLevel, String> {
    match s {
        "minimal" => Ok(policy::TrustLevel::Minimal),
        "standard" => Ok(policy::TrustLevel::Standard),
        "full" => Ok(policy::TrustLevel::Full),
        _ => Err(format!(
            "invalid filter 'trust:{}' -- valid trust values: minimal, standard, full",
            s
        )),
    }
}

fn parse_source(s: &str) -> Result<policy::RuleSource, String> {
    match s {
        "builtin" => Ok(policy::RuleSource::BuiltIn),
        "global" => Ok(policy::RuleSource::Global),
        "project" => Ok(policy::RuleSource::Project),
        _ => Err(format!(
            "invalid filter 'source:{}' -- valid source values: builtin, global, project",
            s
        )),
    }
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum DecisionFilter {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum LevelFilter {
    Critical,
    High,
    Strict,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum GroupBy {
    Decision,
    Level,
}

/// Best-effort parse of Codex hook stdin for fail-open audit entries.
/// Returns (tool, cwd, command, session_id). Empty strings / None when a
/// field is absent or stdin is unparseable. Never panics.
fn parse_codex_input_fields(stdin: &str) -> (String, String, String, Option<String>) {
    let v: serde_json::Value = match serde_json::from_str(stdin) {
        Ok(v) => v,
        Err(_) => return (String::new(), String::new(), String::new(), None),
    };
    let tool = v
        .get("tool_name")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    let cwd = v
        .get("cwd")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    let command = v
        .get("tool_input")
        .and_then(|ti| ti.get("command"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    let session_id = v
        .get("session_id")
        .and_then(|s| s.as_str())
        .map(String::from);
    (tool, cwd, command, session_id)
}

fn home_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
}

/// Default config file path.
fn default_config_path() -> PathBuf {
    config::default_rules_path(&home_dir())
}

/// Global config file path (~/.config/longline/longline.yaml).
fn global_config_path() -> PathBuf {
    config::global_config_path(&home_dir())
}

/// Print global config summary if it exists.
fn print_global_config_banner() {
    match policy::load_global_config(&home_dir()) {
        Ok(Some(config)) => {
            let path = global_config_path();
            let display = path.display().to_string();
            println!("Global config: {}", yansi::Paint::blue(&display));
            if let Some(level) = config.override_safety_level {
                println!("  override_safety_level: {level}");
            }
            if let Some(level) = config.override_trust_level {
                println!("  override_trust_level: {level}");
            }
            if let Some(ref allowlists) = config.allowlists {
                if !allowlists.commands.is_empty() {
                    println!("  allowlists: {} commands", allowlists.commands.len());
                }
            }
            if let Some(ref rules) = config.rules {
                if !rules.is_empty() {
                    println!("  rules: {}", rules.len());
                }
            }
            if let Some(ref disable) = config.disable_rules {
                if !disable.is_empty() {
                    println!("  disable_rules: {}", disable.len());
                }
            }
        }
        Ok(None) => {}
        Err(e) => eprintln!("longline: global config error: {e}"),
    }
}

/// Resolve the project directory: --dir flag > process cwd > None.
fn resolve_dir(explicit: Option<&PathBuf>) -> Option<PathBuf> {
    if let Some(dir) = explicit {
        return Some(dir.clone());
    }
    std::env::current_dir().ok()
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
    if let Some(Commands::Files { .. }) = &cli.command {
        return run_files(
            cli.config.as_ref(),
            cli.trust_level.as_ref(),
            cli.dir.as_ref(),
        );
    }

    // Handle Init command early (no config needed)
    if let Some(Commands::Init { force }) = &cli.command {
        return run_init(*force);
    }

    // Codex hook mode takes a fail-open posture on rules-manifest load
    // failures (empty stdout + stderr + exit 0 + best-effort fail-open
    // JSONL audit). Every other dispatch (Claude hook, bare longline,
    // subcommands) keeps today's exit-2 behavior unchanged.
    let is_codex_hook = matches!(
        cli.command,
        Some(Commands::Hook {
            adapter: HookAdapter::Codex,
            ..
        })
    );

    let base_config = match load_config(cli.config.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            if is_codex_hook {
                // Drain stdin so Codex doesn't perceive a hung subprocess,
                // then best-effort parse it so the fail-open audit entry
                // names tool/cwd/command when available (per spec
                // §Audit Log Layout / fail-open observability).
                let mut buf = String::new();
                let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf);
                eprintln!("longline: {e}");
                let (tool, cwd, command, session_id) = parse_codex_input_fields(&buf);
                let ctx = crate::logger::EntryContext {
                    runtime: "codex",
                    profile: "unresolved".to_string(),
                };
                let entry = crate::logger::make_entry(
                    &ctx,
                    &tool,
                    &cwd,
                    &command,
                    longline::domain::Decision::Allow,
                    Vec::new(),
                    Some(format!("rules manifest load failed: {e}")),
                    false,
                    session_id,
                );
                let path = crate::runtime::codex::audit_log_path(&home_dir());
                crate::logger::log_decision_to(&entry, &path);
                return 0;
            }
            eprintln!("longline: {e}");
            return 2;
        }
    };

    let cli_trust_level = cli.trust_level.as_ref().map(TrustLevelArg::to_trust_level);
    let cli_safety_level = cli
        .safety_level
        .as_ref()
        .map(SafetyLevelArg::to_safety_level);

    // Hook mode (explicit or bare): pass base config to the adapter which
    // finalizes after reading cwd from stdin. Other subcommands resolve
    // project dir and finalize config eagerly.
    let is_hook_mode = matches!(cli.command, Some(Commands::Hook { .. }) | None);

    // Extract the subcommand-level profile override before consuming cli.command.
    // Hook and bare-form profiles are threaded separately (via HookOptions).
    let subcommand_profile: Option<String> = match &cli.command {
        Some(Commands::Check { profile, .. }) => profile.clone(),
        Some(Commands::Rules { profile, .. }) => profile.clone(),
        Some(Commands::Files { profile }) => profile.clone(),
        _ => None,
    };

    let (rules_config, project_config_path) = if is_hook_mode {
        (base_config, None)
    } else {
        let project_dir = resolve_dir(cli.dir.as_ref());
        let final_config = match config::finalize_config(
            base_config,
            &home_dir(),
            project_dir.as_deref(),
            cli_trust_level,
            cli_safety_level,
            "claude",
            subcommand_profile.as_deref(),
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("longline: {e}");
                return 2;
            }
        };
        let rules_config = final_config.rules;
        let _project_ai_prompt = final_config.project_ai_prompt;

        let pcp = project_dir.and_then(|dir| config::existing_project_config_path(&dir));
        (rules_config, pcp)
    };

    match cli.command {
        Some(Commands::Check { file, filter, .. }) => {
            run_check(&rules_config, file, filter, project_config_path.as_ref())
        }
        Some(Commands::Rules {
            verbose,
            filter,
            level,
            group_by,
            ..
        }) => run_rules(
            &rules_config,
            verbose,
            filter,
            level,
            group_by,
            project_config_path.as_ref(),
        ),
        Some(Commands::Files { .. }) => unreachable!(), // handled above
        Some(Commands::Init { .. }) => unreachable!(),  // handled above
        Some(Commands::Hook {
            adapter: HookAdapter::Codex,
            profile,
        }) => crate::adapters::codex::run_hook(
            rules_config,
            &home_dir(),
            crate::adapters::codex::HookOptions {
                ask_on_deny: cli.ask_on_deny,
                ask_ai: cli.ask_ai || cli.ask_ai_lenient,
                ask_ai_lenient: cli.ask_ai_lenient,
                cli_trust_level,
                cli_safety_level,
                profile_override: profile,
            },
        ),
        Some(Commands::Hook {
            adapter: HookAdapter::Claude,
            profile,
        }) => claude::run_hook(
            rules_config,
            &home_dir(),
            claude::HookOptions {
                ask_on_deny: cli.ask_on_deny,
                ask_ai: cli.ask_ai || cli.ask_ai_lenient,
                ask_ai_lenient: cli.ask_ai_lenient,
                cli_trust_level,
                cli_safety_level,
                profile_override: profile,
            },
        ),
        // Bare-form back-compat: route to Claude adapter using top-level --profile.
        None => claude::run_hook(
            rules_config,
            &home_dir(),
            claude::HookOptions {
                ask_on_deny: cli.ask_on_deny,
                ask_ai: cli.ask_ai || cli.ask_ai_lenient,
                ask_ai_lenient: cli.ask_ai_lenient,
                cli_trust_level,
                cli_safety_level,
                profile_override: cli.profile,
            },
        ),
    }
}

fn run_check(
    config: &policy::RulesConfig,
    file: Option<PathBuf>,
    filter: Option<DecisionFilter>,
    project_config_path: Option<&PathBuf>,
) -> i32 {
    print_global_config_banner();

    if let Some(path) = project_config_path {
        let display = path.display().to_string();
        println!("Project config: {}", yansi::Paint::cyan(&display));
    }

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
                            if result.reason == "Shell syntax is too complex to analyze safely" {
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
            let mut stdin = std::io::stdin();
            std::io::Read::read_to_string(&mut stdin, &mut buf)
                .map_err(|e| format!("Failed to read stdin: {e}"))?;
            Ok(buf)
        }
    }
}

fn run_rules(
    config: &policy::RulesConfig,
    verbose: bool,
    filters: Vec<RulesFilter>,
    level: Option<LevelFilter>,
    group_by: Option<GroupBy>,
    project_config_path: Option<&PathBuf>,
) -> i32 {
    print_global_config_banner();

    if let Some(path) = project_config_path {
        let display = path.display().to_string();
        println!("Project config: {}", yansi::Paint::cyan(&display));
    }

    // Extract filter dimensions
    // First match wins -- duplicate dimensions (e.g. --filter trust:full --filter trust:minimal) use the first value.
    let decision_filter: Option<DecisionFilter> = filters.iter().find_map(|f| match f {
        RulesFilter::Decision(d) => Some(d.clone()),
        _ => None,
    });
    let trust_filter: Option<policy::TrustLevel> = filters.iter().find_map(|f| match f {
        RulesFilter::Trust(t) => Some(*t),
        _ => None,
    });
    let source_filter: Option<policy::RuleSource> = filters.iter().find_map(|f| match f {
        RulesFilter::Source(s) => Some(*s),
        _ => None,
    });

    // Filter rules by decision, level, and source
    let rules: Vec<&policy::Rule> = config
        .rules
        .iter()
        .filter(|r| match &decision_filter {
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
        .filter(|r| match &source_filter {
            Some(s) => r.source == *s,
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

    // Filter allowlist entries by trust level (evaluation cutoff -- unchanged)
    let active_commands: Vec<policy::AllowlistEntry> = config
        .allowlists
        .commands
        .iter()
        .filter(|e| e.trust <= config.trust_level)
        .cloned()
        .collect();
    let active_count = active_commands.len();
    let total_count = config.allowlists.commands.len();

    // Further filter allowlist for display by trust tier and source
    let display_commands: Vec<policy::AllowlistEntry> = active_commands
        .iter()
        .filter(|e| match &trust_filter {
            Some(t) => e.trust == *t,
            None => true,
        })
        .filter(|e| match &source_filter {
            Some(s) => e.source == *s,
            None => true,
        })
        .cloned()
        .collect();

    // Show full allowlist when any allowlist-relevant filter is active
    let show_full_allowlist =
        matches!(&decision_filter, Some(DecisionFilter::Allow)) || trust_filter.is_some();
    if show_full_allowlist {
        println!("{}", crate::output::allowlist_table(&display_commands));
    } else {
        crate::output::print_allowlist_summary(&display_commands);
    }

    println!(
        "Safety level: {} | Trust level: {} ({}/{} allowlist active) | Default decision: {}",
        config.safety_level, config.trust_level, active_count, total_count, config.default_decision
    );

    0
}

fn run_files(
    config_path: Option<&PathBuf>,
    trust_override: Option<&TrustLevelArg>,
    dir_override: Option<&PathBuf>,
) -> i32 {
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

    // Show global config info if present
    print_global_config_banner();

    // Show project config info if present
    if let Some(dir) = resolve_dir(dir_override) {
        match policy::load_project_config(&dir) {
            Ok(Some(project_config)) => {
                if let Some(config_path) = config::existing_project_config_path(&dir) {
                    let display = config_path.display().to_string();
                    println!("\nProject config: {}", yansi::Paint::cyan(&display));
                    if let Some(level) = project_config.override_safety_level {
                        println!("  override_safety_level: {level}");
                    }
                    if let Some(level) = project_config.override_trust_level {
                        println!("  override_trust_level: {level}");
                    }
                    if let Some(ref allowlists) = project_config.allowlists {
                        println!("  allowlists: {} commands", allowlists.commands.len());
                    }
                    if let Some(ref rules) = project_config.rules {
                        println!("  rules: {}", rules.len());
                    }
                    if let Some(ref disable) = project_config.disable_rules {
                        println!("  disable_rules: {}", disable.len());
                    }
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("longline: project config error: {e}"),
        }
    }

    0
}

fn run_init(force: bool) -> i32 {
    let rules_yaml_path = default_config_path();
    let target_dir = rules_yaml_path
        .parent()
        .expect("default config path has parent")
        .to_path_buf();

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

#[cfg(test)]
mod tests {
    use super::*;

    // --- RulesFilter FromStr parsing tests ---

    #[test]
    fn test_rules_filter_parse_bare_decision() {
        let f: RulesFilter = "deny".parse().unwrap();
        assert!(matches!(f, RulesFilter::Decision(DecisionFilter::Deny)));
    }

    #[test]
    fn test_rules_filter_parse_prefixed_decision() {
        let f: RulesFilter = "decision:ask".parse().unwrap();
        assert!(matches!(f, RulesFilter::Decision(DecisionFilter::Ask)));
    }

    #[test]
    fn test_rules_filter_parse_trust() {
        let f: RulesFilter = "trust:full".parse().unwrap();
        assert!(matches!(f, RulesFilter::Trust(policy::TrustLevel::Full)));
    }

    #[test]
    fn test_rules_filter_parse_source() {
        let f: RulesFilter = "source:project".parse().unwrap();
        assert!(matches!(
            f,
            RulesFilter::Source(policy::RuleSource::Project)
        ));
    }

    #[test]
    fn test_rules_filter_parse_source_builtin() {
        let f: RulesFilter = "source:builtin".parse().unwrap();
        assert!(matches!(
            f,
            RulesFilter::Source(policy::RuleSource::BuiltIn)
        ));
    }

    #[test]
    fn test_rules_filter_parse_invalid_dimension() {
        let result: Result<RulesFilter, String> = "foo:bar".parse();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown filter dimension"));
    }

    #[test]
    fn test_rules_filter_parse_invalid_value() {
        let result: Result<RulesFilter, String> = "trust:mega".parse();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("valid trust values"));
    }

    #[test]
    fn test_rules_filter_parse_invalid_bare() {
        let result: Result<RulesFilter, String> = "banana".parse();
        assert!(result.is_err());
    }

    // --- CLI parsing tests for typed filters ---

    #[test]
    fn test_cli_parses_typed_filter() {
        let cli = Cli::try_parse_from(["longline", "rules", "--filter", "trust:full"]).unwrap();
        match cli.command {
            Some(Commands::Rules { filter, .. }) => {
                assert_eq!(filter.len(), 1);
                assert!(matches!(
                    filter[0],
                    RulesFilter::Trust(policy::TrustLevel::Full)
                ));
            }
            _ => panic!("expected Rules command"),
        }
    }

    #[test]
    fn test_cli_parses_multiple_filters() {
        let cli = Cli::try_parse_from([
            "longline",
            "rules",
            "--filter",
            "deny",
            "--filter",
            "source:project",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Rules { filter, .. }) => {
                assert_eq!(filter.len(), 2);
            }
            _ => panic!("expected Rules command"),
        }
    }

    #[test]
    fn test_cli_parses_bare_filter_backwards_compat() {
        let cli = Cli::try_parse_from(["longline", "rules", "--filter", "deny"]).unwrap();
        match cli.command {
            Some(Commands::Rules { filter, .. }) => {
                assert_eq!(filter.len(), 1);
                assert!(matches!(
                    filter[0],
                    RulesFilter::Decision(DecisionFilter::Deny)
                ));
            }
            _ => panic!("expected Rules command"),
        }
    }

    #[test]
    fn test_cli_rejects_invalid_filter() {
        let result = Cli::try_parse_from(["longline", "rules", "--filter", "trust:mega"]);
        assert!(result.is_err());
    }

    // --- Existing tests ---

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

    #[test]
    fn test_cli_parses_dir_flag() {
        let cli = Cli::try_parse_from(["longline", "--dir", "/tmp/myproject", "rules"]).unwrap();
        assert_eq!(cli.dir.unwrap(), PathBuf::from("/tmp/myproject"));
    }

    #[test]
    fn test_cli_dir_flag_is_optional() {
        let cli = Cli::try_parse_from(["longline", "rules"]).unwrap();
        assert!(cli.dir.is_none());
    }

    #[test]
    fn test_cli_parses_hook_codex() {
        let cli = Cli::try_parse_from(["longline", "hook", "codex"]).unwrap();
        match cli.command {
            Some(Commands::Hook {
                adapter: HookAdapter::Codex,
                ..
            }) => {}
            other => panic!("expected Hook(Codex), got {other:?}"),
        }
    }

    #[test]
    fn test_cli_parses_hook_claude() {
        let cli = Cli::try_parse_from(["longline", "hook", "claude"]).unwrap();
        match cli.command {
            Some(Commands::Hook {
                adapter: HookAdapter::Claude,
                ..
            }) => {}
            other => panic!("expected Hook(Claude), got {other:?}"),
        }
    }

    #[test]
    fn test_cli_bare_form_has_no_command() {
        let cli = Cli::try_parse_from(["longline"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_hook_codex_with_flags() {
        let cli = Cli::try_parse_from(["longline", "--ask-on-deny", "hook", "codex"]).unwrap();
        match cli.command {
            Some(Commands::Hook {
                adapter: HookAdapter::Codex,
                ..
            }) => {}
            other => panic!("expected Hook(Codex), got {other:?}"),
        }
        assert!(cli.ask_on_deny);
    }

    // --- --profile flag tests ---

    #[test]
    fn test_cli_parses_hook_codex_with_profile() {
        let cli =
            Cli::try_parse_from(["longline", "hook", "codex", "--profile", "strict"]).unwrap();
        match cli.command {
            Some(Commands::Hook { adapter, profile }) => {
                assert_eq!(adapter, HookAdapter::Codex);
                assert_eq!(profile.as_deref(), Some("strict"));
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn test_cli_parses_bare_form_with_profile() {
        let cli = Cli::try_parse_from(["longline", "--profile", "afterhours"]).unwrap();
        assert_eq!(cli.profile.as_deref(), Some("afterhours"));
    }

    #[test]
    fn test_cli_parses_check_with_profile() {
        let cli = Cli::try_parse_from(["longline", "check", "--profile", "strict"]).unwrap();
        match cli.command {
            Some(Commands::Check { profile, .. }) => assert_eq!(profile.as_deref(), Some("strict")),
            _ => panic!(),
        }
    }
}
