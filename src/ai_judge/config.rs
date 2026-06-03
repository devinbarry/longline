use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct AiJudgeConfig {
    #[serde(default = "default_command")]
    pub command: String,
    #[serde(default = "default_fallback_command")]
    pub fallback_command: String,
    #[serde(default, rename = "timeout")]
    timeout_raw: Option<u64>,
    #[serde(default, rename = "total_budget_secs")]
    total_budget_secs_raw: Option<u64>,
    #[serde(default = "default_hedge_after_secs")]
    pub hedge_after_secs: u64,
    #[serde(default = "default_backoff_base_ms")]
    pub backoff_base_ms: u64,
    #[serde(default = "default_backoff_max_ms")]
    pub backoff_max_ms: u64,
    #[serde(default = "default_relaunch_floor_ms")]
    pub relaunch_floor_ms: u64,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_max_nonconforming")]
    pub max_nonconforming: u32,
    #[serde(default)]
    pub triggers: TriggersConfig,
    // Resolved by finalize(); not deserialized directly.
    #[serde(skip)]
    pub timeout: u64,
    #[serde(skip)]
    pub total_budget_secs: u64,
}

impl AiJudgeConfig {
    /// Resolve `timeout`/`total_budget_secs` with the back-compat rule:
    /// - neither set → 45 / 90
    /// - timeout set, budget unset → budget = timeout (preserve old ceiling)
    /// - budget set → use it; timeout defaults to 45 if unset
    pub fn finalize(mut self) -> Self {
        let timeout = self.timeout_raw.unwrap_or_else(default_timeout);
        let budget = match (self.timeout_raw, self.total_budget_secs_raw) {
            (_, Some(b)) => b,
            (Some(t), None) => t,
            (None, None) => 90,
        };
        self.timeout = timeout;
        self.total_budget_secs = budget;
        self
    }
}

#[derive(Debug, Deserialize)]
pub struct TriggersConfig {
    #[serde(default = "default_interpreters")]
    pub interpreters: Vec<InterpreterTrigger>,
    #[serde(default = "default_runners")]
    pub runners: Vec<String>,
}

impl Default for TriggersConfig {
    fn default() -> Self {
        Self {
            interpreters: default_interpreters(),
            runners: default_runners(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InterpreterTrigger {
    pub name: Vec<String>,
    pub inline_flag: String,
}

fn default_command() -> String {
    "codex exec --full-auto --ephemeral --skip-git-repo-check --enable fast_mode -m gpt-5.4 -c model_reasoning_effort=medium".to_string()
}

fn default_fallback_command() -> String {
    "claude -p --strict-mcp-config --setting-sources \"\" --settings ~/.config/longline/judge-claude-settings.json --model haiku".to_string()
}

fn default_timeout() -> u64 {
    // 45s, raised from 30s after audit-log analysis: every observed 30s
    // timeout had the judge (codex exec) still alive — either mid-stream or
    // stalled on first-token latency after an 8-15s cold start — never
    // crashed. A timeout falls back to `ask` (safe but a friction prompt),
    // so the extra headroom converts slow-but-completing runs into verdicts.
    // Overridable via `timeout:` in ~/.config/longline/ai-judge.yaml.
    45
}

fn default_hedge_after_secs() -> u64 {
    30
}

fn default_backoff_base_ms() -> u64 {
    500
}

fn default_backoff_max_ms() -> u64 {
    4000
}

fn default_relaunch_floor_ms() -> u64 {
    250
}

fn default_max_attempts() -> u32 {
    40
}

fn default_max_nonconforming() -> u32 {
    2
}

fn default_interpreters() -> Vec<InterpreterTrigger> {
    vec![
        InterpreterTrigger {
            name: vec!["python".into(), "python3".into()],
            inline_flag: "-c".into(),
        },
        InterpreterTrigger {
            name: vec!["node".into()],
            inline_flag: "-e".into(),
        },
        InterpreterTrigger {
            name: vec!["ruby".into()],
            inline_flag: "-e".into(),
        },
        InterpreterTrigger {
            name: vec!["perl".into()],
            inline_flag: "-e".into(),
        },
    ]
}

fn default_runners() -> Vec<String> {
    vec![
        "uv".to_string(),
        "poetry".to_string(),
        "pipenv".to_string(),
        "pdm".to_string(),
        "rye".to_string(),
    ]
}

fn default_config_path() -> PathBuf {
    super::home::home_dir()
        .join(".config")
        .join("longline")
        .join("ai-judge.yaml")
}

pub fn load_config() -> AiJudgeConfig {
    let path = default_config_path();
    load_config_from_path(&path)
}

fn load_config_from_path(path: &Path) -> AiJudgeConfig {
    if !path.exists() {
        return default_config();
    }
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_norway::from_str::<AiJudgeConfig>(&content) {
            Ok(cfg) => cfg.finalize(),
            Err(e) => {
                eprintln!("longline: failed to parse ai-judge config: {e}");
                default_config()
            }
        },
        Err(e) => {
            eprintln!("longline: failed to read ai-judge config: {e}");
            default_config()
        }
    }
}

pub(crate) fn default_config() -> AiJudgeConfig {
    serde_norway::from_str::<AiJudgeConfig>("{}")
        .expect("empty ai-judge config is always valid")
        .finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_deserialization() {
        let yaml = r#"
command: claude -p
timeout: 10
triggers:
  interpreters:
    - name: [python, python3]
      inline_flag: "-c"
"#;
        let config: AiJudgeConfig = serde_norway::from_str(yaml).unwrap();
        let config = config.finalize();
        assert_eq!(config.command, "claude -p");
        assert_eq!(config.timeout, 10);
        assert_eq!(config.triggers.interpreters.len(), 1);
        assert_eq!(
            config.triggers.interpreters[0].name,
            vec!["python", "python3"]
        );
        assert!(!config.triggers.runners.is_empty());
    }

    #[test]
    fn test_default_timeout_is_45s() {
        // Deliberate: raised 30→45 after audit-log analysis showed every
        // observed timeout had the judge still alive (mid-stream or stalled on
        // cold-start first-token latency), never crashed. Guards against an
        // accidental revert.
        assert_eq!(default_timeout(), 45);
    }

    #[test]
    fn test_config_defaults() {
        let yaml = "{}";
        let config: AiJudgeConfig = serde_norway::from_str(yaml).unwrap();
        let config = config.finalize();
        assert_eq!(
            config.command,
            "codex exec --full-auto --ephemeral --skip-git-repo-check --enable fast_mode -m gpt-5.4 -c model_reasoning_effort=medium"
        );
        assert_eq!(config.timeout, 45);
        assert!(!config.triggers.interpreters.is_empty());
        assert!(!config.triggers.runners.is_empty());
    }

    #[test]
    fn new_fields_have_r14_defaults() {
        let c: AiJudgeConfig = serde_norway::from_str("{}").unwrap();
        let c = c.finalize();
        assert!(c.fallback_command.starts_with("claude -p"));
        assert_eq!(c.timeout, 45);
        assert_eq!(c.total_budget_secs, 90);
        assert_eq!(c.hedge_after_secs, 30);
        assert_eq!(c.backoff_base_ms, 500);
        assert_eq!(c.backoff_max_ms, 4000);
        assert_eq!(c.relaunch_floor_ms, 250);
        assert_eq!(c.max_attempts, 40);
        assert_eq!(c.max_nonconforming, 2);
    }

    #[test]
    fn timeout_set_without_total_budget_defaults_budget_to_timeout() {
        // Back-compat: a user who set `timeout: 5` for a 5s ceiling keeps it.
        let c: AiJudgeConfig = serde_norway::from_str("timeout: 5\n").unwrap();
        let c = c.finalize();
        assert_eq!(c.timeout, 5);
        assert_eq!(c.total_budget_secs, 5);
    }

    #[test]
    fn explicit_total_budget_wins_over_timeout() {
        let c: AiJudgeConfig =
            serde_norway::from_str("timeout: 5\ntotal_budget_secs: 30\n").unwrap();
        let c = c.finalize();
        assert_eq!(c.total_budget_secs, 30);
    }

    #[test]
    fn empty_fallback_command_disables_claude() {
        let c: AiJudgeConfig = serde_norway::from_str("fallback_command: \"\"\n").unwrap();
        let c = c.finalize();
        assert_eq!(c.fallback_command, "");
    }

    #[test]
    fn test_load_config_from_path_missing_file_returns_default() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("ai-judge-config")
            .join("missing.yaml");
        let config = load_config_from_path(&path);
        assert_eq!(
            config.command,
            "codex exec --full-auto --ephemeral --skip-git-repo-check --enable fast_mode -m gpt-5.4 -c model_reasoning_effort=medium"
        );
        assert_eq!(config.timeout, 45);
        assert!(!config.triggers.interpreters.is_empty());
        assert!(!config.triggers.runners.is_empty());
    }

    #[test]
    fn test_load_config_from_path_reads_valid_yaml() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("ai-judge-config")
            .join("valid");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ai-judge.yaml");
        std::fs::write(
            &path,
            r#"
command: claude -p
timeout: 10
triggers:
  runners: [uv]
"#,
        )
        .unwrap();

        let config = load_config_from_path(&path);
        assert_eq!(config.command, "claude -p");
        assert_eq!(config.timeout, 10);
        assert_eq!(config.triggers.runners, vec!["uv"]);
        assert!(!config.triggers.interpreters.is_empty());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_load_config_from_path_invalid_yaml_falls_back_to_default() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("ai-judge-config")
            .join("invalid");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ai-judge.yaml");
        std::fs::write(&path, "timeout: [not a number]").unwrap();

        let config = load_config_from_path(&path);
        assert_eq!(
            config.command,
            "codex exec --full-auto --ephemeral --skip-git-repo-check --enable fast_mode -m gpt-5.4 -c model_reasoning_effort=medium"
        );
        assert_eq!(config.timeout, 45);
        assert!(!config.triggers.interpreters.is_empty());
        assert!(!config.triggers.runners.is_empty());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
