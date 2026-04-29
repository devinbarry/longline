use std::path::Path;

use longline::domain::Decision;
use longline::policy;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum Invocation {
    Shell {
        command: Option<String>,
        cwd: Option<String>,
        session_id: Option<String>,
    },
    ReadPath {
        tool_name: String,
        path: Option<String>,
        cwd: Option<String>,
        session_id: Option<String>,
    },
    SearchPath {
        tool_name: String,
        path: Option<String>,
        cwd: Option<String>,
        session_id: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub(crate) struct EvaluationOptions {
    pub ask_on_deny: bool,
    pub ask_ai: bool,
    pub ask_ai_lenient: bool,
    pub cli_trust_level: Option<policy::TrustLevel>,
    pub cli_safety_level: Option<policy::SafetyLevel>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct EvaluationOutcome {
    pub decision: Decision,
    pub reason: String,
    pub log_reason: Option<String>,
    pub matched_rules: Vec<String>,
    pub parse_ok: bool,
    pub original_decision: Option<Decision>,
    pub overridden: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use policy::SafetyLevel::*;
    use policy::TrustLevel::*;

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
