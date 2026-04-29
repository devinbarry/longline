use std::path::Path;

use longline::domain::Decision;
use longline::domain::PolicyResult;
use longline::parser;
use longline::policy;

#[cfg_attr(not(test), allow(dead_code))]
const SENSITIVE_PATH_PATTERNS: &[&str] = &["/.ssh/", "/.aws/", "/.gnupg/"];
#[cfg_attr(not(test), allow(dead_code))]
const SENSITIVE_EXACT_PATHS: &[&str] = &["/etc/shadow"];

#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Invocation {
    Shell {
        command: Option<String>,
        cwd: Option<String>,
        #[allow(dead_code)]
        session_id: Option<String>,
    },
    ReadPath {
        tool_name: String,
        path: Option<String>,
        cwd: Option<String>,
        #[allow(dead_code)]
        session_id: Option<String>,
    },
    SearchPath {
        tool_name: String,
        path: Option<String>,
        cwd: Option<String>,
        #[allow(dead_code)]
        session_id: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct EvaluationOptions {
    pub ask_on_deny: bool,
    #[allow(dead_code)]
    pub ask_ai: bool,
    #[allow(dead_code)]
    pub ask_ai_lenient: bool,
    pub cli_trust_level: Option<policy::TrustLevel>,
    pub cli_safety_level: Option<policy::SafetyLevel>,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct EvaluationOutcome {
    pub decision: Decision,
    pub reason: String,
    pub log_reason: Option<String>,
    #[allow(dead_code)]
    pub matched_rules: Vec<String>,
    #[allow(dead_code)]
    pub parse_ok: bool,
    #[allow(dead_code)]
    pub original_decision: Option<Decision>,
    #[allow(dead_code)]
    pub overridden: bool,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum EvaluationError {
    Config(String),
}

impl std::fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(message) => f.write_str(message),
        }
    }
}

pub(crate) struct FinalConfig {
    pub rules: policy::RulesConfig,
    pub project_ai_prompt: Option<String>,
}

pub(crate) fn finalize_config(
    mut config: policy::RulesConfig,
    home: &Path,
    project_dir: Option<&Path>,
    cli_trust_level: Option<policy::TrustLevel>,
    cli_safety_level: Option<policy::SafetyLevel>,
) -> Result<FinalConfig, String> {
    if let Some(global_config) = policy::load_global_config(home)? {
        policy::merge_overlay_config(&mut config, global_config, policy::RuleSource::Global);
    }

    let mut project_ai_prompt: Option<String> = None;
    if let Some(dir) = project_dir {
        if let Some(project_config) = policy::load_project_config(dir)? {
            project_ai_prompt = project_config
                .ai_judge
                .as_ref()
                .and_then(|a| a.prompt.as_ref())
                .filter(|c| !c.trim().is_empty())
                .cloned();
            policy::merge_project_config(&mut config, project_config);
        }
    }

    if let Some(level) = cli_trust_level {
        config.trust_level = level;
    }
    if let Some(level) = cli_safety_level {
        config.safety_level = level;
    }

    Ok(FinalConfig {
        rules: config,
        project_ai_prompt,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn evaluate_invocation(
    config: policy::RulesConfig,
    home: &Path,
    invocation: Invocation,
    options: EvaluationOptions,
) -> Result<EvaluationOutcome, EvaluationError> {
    let cwd = invocation.cwd().map(Path::new);
    let final_config = finalize_config(
        config,
        home,
        cwd,
        options.cli_trust_level,
        options.cli_safety_level,
    )
    .map_err(EvaluationError::Config)?;
    let rules = final_config.rules;
    let _project_ai_prompt = final_config.project_ai_prompt;

    match invocation {
        Invocation::Shell {
            command: None,
            cwd: _,
            session_id: _,
        } => Ok(EvaluationOutcome::simple(
            Decision::Allow,
            "longline: no command".to_string(),
        )),
        Invocation::Shell {
            command: Some(command),
            cwd: _,
            session_id: _,
        } => evaluate_shell_command(&rules, &command, options.ask_on_deny),
        Invocation::ReadPath {
            tool_name: _,
            path: None,
            cwd: _,
            session_id: _,
        } => Ok(EvaluationOutcome::simple(
            Decision::Allow,
            "longline: Read tool (no path)".to_string(),
        )),
        Invocation::ReadPath {
            tool_name,
            path: Some(path),
            cwd: _,
            session_id: _,
        }
        | Invocation::SearchPath {
            tool_name,
            path: Some(path),
            cwd: _,
            session_id: _,
        } => Ok(evaluate_path(&tool_name, &path)),
        Invocation::SearchPath {
            tool_name,
            path: None,
            cwd: _,
            session_id: _,
        } => Ok(EvaluationOutcome::simple(
            Decision::Allow,
            format!("longline: {tool_name} allowed (no path)"),
        )),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl Invocation {
    fn cwd(&self) -> Option<&str> {
        match self {
            Self::Shell { cwd, .. } | Self::ReadPath { cwd, .. } | Self::SearchPath { cwd, .. } => {
                cwd.as_deref()
            }
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl EvaluationOutcome {
    fn simple(decision: Decision, reason: String) -> Self {
        Self {
            decision,
            reason,
            log_reason: None,
            matched_rules: vec![],
            parse_ok: true,
            original_decision: None,
            overridden: false,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn evaluate_path(tool_name: &str, path: &str) -> EvaluationOutcome {
    for pattern in SENSITIVE_PATH_PATTERNS {
        if path.contains(pattern) {
            return EvaluationOutcome::simple(
                Decision::Ask,
                format!("longline: {tool_name} sensitive path ({pattern}): {path}"),
            );
        }
    }

    for exact in SENSITIVE_EXACT_PATHS {
        if path == *exact {
            return EvaluationOutcome::simple(
                Decision::Ask,
                format!("longline: {tool_name} sensitive path: {path}"),
            );
        }
    }

    EvaluationOutcome::simple(
        Decision::Allow,
        format!("longline: {tool_name} allowed: {path}"),
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn evaluate_shell_command(
    rules: &policy::RulesConfig,
    command: &str,
    ask_on_deny: bool,
) -> Result<EvaluationOutcome, EvaluationError> {
    let stmt = match parser::parse(command) {
        Ok(stmt) => stmt,
        Err(e) => {
            return Ok(EvaluationOutcome {
                decision: Decision::Ask,
                reason: format!("Failed to parse bash command: {e}"),
                log_reason: Some(format!("Parse error: {e}")),
                matched_rules: vec![],
                parse_ok: false,
                original_decision: None,
                overridden: false,
            });
        }
    };

    let result = policy::evaluate(rules, &stmt);
    let overridden = ask_on_deny && result.decision == Decision::Deny;
    let decision = if overridden {
        Decision::Ask
    } else {
        result.decision
    };
    let reason = match decision {
        Decision::Allow => format!("longline: {}", result.reason),
        Decision::Ask | Decision::Deny if overridden => {
            format!("[overridden] {}", format_reason(&result))
        }
        Decision::Ask | Decision::Deny => format_reason(&result),
    };

    Ok(EvaluationOutcome {
        decision,
        reason,
        log_reason: if result.reason.is_empty() {
            None
        } else {
            Some(result.reason.clone())
        },
        matched_rules: result.rule_id.clone().into_iter().collect(),
        parse_ok: true,
        original_decision: overridden.then_some(result.decision),
        overridden,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn format_reason(result: &PolicyResult) -> String {
    match &result.rule_id {
        Some(id) => format!("[{id}] {}", result.reason),
        None => result.reason.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy::SafetyLevel::*;
    use policy::TrustLevel::*;

    fn base_config() -> policy::RulesConfig {
        policy::load_embedded_rules().expect("embedded rules should load")
    }

    fn eval(invocation: Invocation) -> EvaluationOutcome {
        let home = tempfile::TempDir::new().unwrap();
        evaluate_invocation(
            base_config(),
            home.path(),
            invocation,
            EvaluationOptions::default(),
        )
        .expect("evaluation should succeed")
    }

    #[test]
    fn test_evaluate_missing_shell_command_allows_without_log() {
        let home = tempfile::TempDir::new().unwrap();
        let outcome = evaluate_invocation(
            base_config(),
            home.path(),
            Invocation::Shell {
                command: None,
                cwd: Some("/tmp".to_string()),
                session_id: Some("session-1".to_string()),
            },
            EvaluationOptions::default(),
        )
        .unwrap();

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.reason, "longline: no command");
        assert_eq!(outcome.log_reason, None);
        assert!(!home
            .path()
            .join(".claude/hooks-logs/longline.jsonl")
            .exists());
    }

    #[test]
    fn test_evaluate_sensitive_read_path_asks_without_log() {
        let home = tempfile::TempDir::new().unwrap();
        let outcome = evaluate_invocation(
            base_config(),
            home.path(),
            Invocation::ReadPath {
                tool_name: "Read".to_string(),
                path: Some("/home/user/.ssh/id_rsa".to_string()),
                cwd: Some("/tmp".to_string()),
                session_id: Some("session-1".to_string()),
            },
            EvaluationOptions::default(),
        )
        .unwrap();

        assert_eq!(outcome.decision, Decision::Ask);
        assert_eq!(
            outcome.reason,
            "longline: Read sensitive path (/.ssh/): /home/user/.ssh/id_rsa"
        );
        assert!(!home
            .path()
            .join(".claude/hooks-logs/longline.jsonl")
            .exists());
    }

    #[test]
    fn test_evaluate_safe_read_path_allows_without_log() {
        let outcome = eval(Invocation::ReadPath {
            tool_name: "Read".to_string(),
            path: Some("src/main.rs".to_string()),
            cwd: Some("/tmp".to_string()),
            session_id: Some("session-1".to_string()),
        });

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.reason, "longline: Read allowed: src/main.rs");
    }

    #[test]
    fn test_evaluate_read_no_path_allows_with_current_reason() {
        let outcome = eval(Invocation::ReadPath {
            tool_name: "Read".to_string(),
            path: None,
            cwd: Some("/tmp".to_string()),
            session_id: Some("session-1".to_string()),
        });

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.reason, "longline: Read tool (no path)");
    }

    #[test]
    fn test_evaluate_grep_no_path_allows_with_current_reason() {
        let outcome = eval(Invocation::SearchPath {
            tool_name: "Grep".to_string(),
            path: None,
            cwd: Some("/tmp".to_string()),
            session_id: Some("session-1".to_string()),
        });

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.reason, "longline: Grep allowed (no path)");
    }

    #[test]
    fn test_finalize_config_no_overlays() {
        let home = tempfile::TempDir::new().unwrap();
        let config = policy::load_embedded_rules().unwrap();
        let original_trust = config.trust_level;
        let original_safety = config.safety_level;

        let result = finalize_config(config, home.path(), None, None, None).unwrap();

        assert_eq!(result.rules.trust_level, original_trust);
        assert_eq!(result.rules.safety_level, original_safety);
    }

    #[test]
    fn test_finalize_config_global_overrides_base() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "override_trust_level: full\n",
        )
        .unwrap();

        let config = policy::load_embedded_rules().unwrap();
        let result = finalize_config(config, home.path(), None, None, None).unwrap();

        assert_eq!(result.rules.trust_level, Full);
    }

    #[test]
    fn test_finalize_config_project_overrides_global() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "override_trust_level: full\n",
        )
        .unwrap();

        let project_dir = tempfile::TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(project_dir.path())
            .output()
            .unwrap();
        let claude_dir = project_dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("longline.yaml"),
            "override_trust_level: minimal\n",
        )
        .unwrap();

        let config = policy::load_embedded_rules().unwrap();
        let result =
            finalize_config(config, home.path(), Some(project_dir.path()), None, None).unwrap();

        assert_eq!(
            result.rules.trust_level, Minimal,
            "Project config should override global config"
        );
    }

    #[test]
    fn test_finalize_config_cli_overrides_project_and_global() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "override_trust_level: full\n",
        )
        .unwrap();

        let project_dir = tempfile::TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(project_dir.path())
            .output()
            .unwrap();
        let claude_dir = project_dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("longline.yaml"),
            "override_trust_level: full\n",
        )
        .unwrap();

        let config = policy::load_embedded_rules().unwrap();
        let result = finalize_config(
            config,
            home.path(),
            Some(project_dir.path()),
            Some(Standard),
            None,
        )
        .unwrap();

        assert_eq!(
            result.rules.trust_level, Standard,
            "CLI --trust-level should override both global and project config"
        );
    }

    #[test]
    fn test_finalize_config_cli_safety_overrides_all() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "override_safety_level: strict\n",
        )
        .unwrap();

        let config = policy::load_embedded_rules().unwrap();
        let result = finalize_config(config, home.path(), None, None, Some(Critical)).unwrap();

        assert_eq!(
            result.rules.safety_level, Critical,
            "CLI --safety-level should override global config"
        );
    }

    #[test]
    fn test_finalize_config_invalid_global_config_errors() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "not_a_valid_field: oops\n",
        )
        .unwrap();

        let config = policy::load_embedded_rules().unwrap();
        let result = finalize_config(config, home.path(), None, None, None);
        assert!(result.is_err(), "Invalid global config should return error");
    }

    #[test]
    fn test_finalize_config_global_allowlist_not_duplicated() {
        let home = tempfile::TempDir::new().unwrap();
        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("longline.yaml"),
            "allowlists:\n  commands:\n    - { command: my-custom-tool, trust: minimal }\n",
        )
        .unwrap();

        let config = policy::load_embedded_rules().unwrap();
        let base_count = config.allowlists.commands.len();

        let result = finalize_config(config, home.path(), None, None, None).unwrap();

        assert_eq!(
            result.rules.allowlists.commands.len(),
            base_count + 1,
            "Global config allowlist should be merged exactly once"
        );
    }

    #[test]
    fn test_finalize_config_extracts_project_ai_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let repo = project_dir.path();
        std::fs::create_dir(repo.join(".git")).unwrap();
        std::fs::create_dir(repo.join(".claude")).unwrap();
        std::fs::write(
            repo.join(".claude").join("longline.yaml"),
            "ai_judge:\n  prompt: |\n    {language} {code} {cwd}\n",
        )
        .unwrap();
        let base = policy::RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: High,
            trust_level: Standard,
            allowlists: policy::Allowlists {
                commands: vec![],
                paths: vec![],
            },
            rules: vec![],
        };
        let result = finalize_config(base, tmp.path(), Some(repo), None, None).unwrap();
        let prompt = result.project_ai_prompt.expect("prompt should be Some");
        assert!(prompt.contains("{code}"), "got: {prompt}");
    }

    #[test]
    fn test_finalize_config_no_project_ai_prompt_when_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path();
        std::fs::create_dir(repo.join(".git")).unwrap();

        let base = policy::RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: High,
            trust_level: Standard,
            allowlists: policy::Allowlists {
                commands: vec![],
                paths: vec![],
            },
            rules: vec![],
        };
        let result = finalize_config(base, tmp.path(), Some(repo), None, None)
            .expect("finalize_config should succeed");
        assert!(result.project_ai_prompt.is_none());
    }

    #[test]
    fn test_finalize_config_empty_project_ai_prompt_is_none() {
        use std::fs;

        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path();
        fs::create_dir(repo.join(".claude")).unwrap();
        fs::write(
            repo.join(".claude").join("longline.yaml"),
            "ai_judge:\n  prompt: \"   \"\n",
        )
        .unwrap();
        fs::create_dir(repo.join(".git")).unwrap();

        let base = policy::RulesConfig {
            version: 1,
            default_decision: Decision::Ask,
            safety_level: High,
            trust_level: Standard,
            allowlists: policy::Allowlists {
                commands: vec![],
                paths: vec![],
            },
            rules: vec![],
        };
        let result = finalize_config(base, tmp.path(), Some(repo), None, None)
            .expect("finalize_config should succeed");
        assert!(
            result.project_ai_prompt.is_none(),
            "all-whitespace prompt must be filtered to None"
        );
    }
}
