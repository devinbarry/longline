use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct AiJudgeConfig {
    #[serde(default = "default_command")]
    pub command: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub triggers: TriggersConfig,
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
    "codex exec -m gpt-5.1-codex-mini -c model_reasoning_effort=medium".to_string()
}

fn default_timeout() -> u64 {
    30
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
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
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
        Ok(content) => serde_norway::from_str(&content).unwrap_or_else(|e| {
            eprintln!("longline: failed to parse ai-judge config: {e}");
            default_config()
        }),
        Err(e) => {
            eprintln!("longline: failed to read ai-judge config: {e}");
            default_config()
        }
    }
}

pub(crate) fn default_config() -> AiJudgeConfig {
    AiJudgeConfig {
        command: default_command(),
        timeout: default_timeout(),
        triggers: TriggersConfig::default(),
    }
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
    fn test_config_defaults() {
        let yaml = "{}";
        let config: AiJudgeConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(
            config.command,
            "codex exec -m gpt-5.1-codex-mini -c model_reasoning_effort=medium"
        );
        assert_eq!(config.timeout, 30);
        assert!(!config.triggers.interpreters.is_empty());
        assert!(!config.triggers.runners.is_empty());
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
            "codex exec -m gpt-5.1-codex-mini -c model_reasoning_effort=medium"
        );
        assert_eq!(config.timeout, 30);
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
            "codex exec -m gpt-5.1-codex-mini -c model_reasoning_effort=medium"
        );
        assert_eq!(config.timeout, 30);
        assert!(!config.triggers.interpreters.is_empty());
        assert!(!config.triggers.runners.is_empty());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
