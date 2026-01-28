use serde::Deserialize;
use std::path::PathBuf;

use crate::parser::Statement;
use crate::types::Decision;

// ── Config types ────────────────────────────────────────────────

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
}

impl Default for TriggersConfig {
    fn default() -> Self {
        Self {
            interpreters: default_interpreters(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InterpreterTrigger {
    pub name: Vec<String>,
    pub inline_flag: String,
}

fn default_command() -> String {
    "codex exec".to_string()
}

fn default_timeout() -> u64 {
    15
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

// ── Config loading ──────────────────────────────────────────────

fn default_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".config")
        .join("longline")
        .join("ai-judge.yaml")
}

pub fn load_config() -> AiJudgeConfig {
    let path = default_config_path();
    if !path.exists() {
        return default_config();
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_yaml::from_str(&content).unwrap_or_else(|e| {
            eprintln!("longline: failed to parse ai-judge config: {e}");
            default_config()
        }),
        Err(e) => {
            eprintln!("longline: failed to read ai-judge config: {e}");
            default_config()
        }
    }
}

fn default_config() -> AiJudgeConfig {
    AiJudgeConfig {
        command: default_command(),
        timeout: default_timeout(),
        triggers: TriggersConfig::default(),
    }
}

// ── Trigger detection ───────────────────────────────────────────

/// Check if a statement is an interpreter with inline code.
/// Returns (language, code) if matched.
pub fn extract_inline_code(stmt: &Statement, config: &AiJudgeConfig) -> Option<(String, String)> {
    let cmd = match stmt {
        Statement::SimpleCommand(cmd) => cmd,
        _ => return None,
    };

    let cmd_name = cmd.name.as_deref()?;

    for trigger in &config.triggers.interpreters {
        if !trigger.name.iter().any(|n| n == cmd_name) {
            continue;
        }
        let flag_pos = cmd.argv.iter().position(|a| a == &trigger.inline_flag)?;
        let code = cmd.argv.get(flag_pos + 1)?;
        return Some((cmd_name.to_string(), code.clone()));
    }

    None
}

// ── Prompt ──────────────────────────────────────────────────────

const PROMPT_TEMPLATE: &str = r#"Security evaluation of inline {language} code to be executed on a developer's machine.

Working directory: {cwd}

```{language}
{code}
```

Evaluate safety. Respond with EXACTLY one line, no other output:

ALLOW: <brief reason>
— Code only does: computation, data formatting, printing output, reading/writing
  files in the working directory or temp directories (/tmp, $TMPDIR, tempfile
  module), string/regex operations, JSON/YAML/CSV parsing, encoding, hashing,
  math, type checking, or version queries.

ASK: <brief reason>
— Code does ANY of: write/delete/move/rename files outside temp dirs or the
  working directory, network requests, subprocess or shell execution (os.system,
  subprocess), access secrets or credentials (.env, SSH keys, tokens), modify
  system configuration, install packages, or access sensitive paths outside the
  working directory."#;

pub fn build_prompt(language: &str, code: &str, cwd: &str) -> String {
    PROMPT_TEMPLATE
        .replace("{language}", language)
        .replace("{code}", code)
        .replace("{cwd}", cwd)
}

// ── Response parsing ────────────────────────────────────────────

pub fn parse_response(output: &str) -> Decision {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ALLOW:") {
            return Decision::Allow;
        }
        if trimmed.starts_with("ASK:") {
            return Decision::Ask;
        }
    }
    Decision::Ask
}

// ── LLM invocation ─────────────────────────────────────────────

pub fn evaluate(config: &AiJudgeConfig, language: &str, code: &str, cwd: &str) -> Decision {
    let prompt = build_prompt(language, code, cwd);

    let parts: Vec<String> = config
        .command
        .split_whitespace()
        .map(String::from)
        .collect();
    if parts.is_empty() {
        eprintln!("longline: ai-judge command is empty");
        return Decision::Ask;
    }

    let timeout = std::time::Duration::from_secs(config.timeout);
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let result = std::process::Command::new(&parts[0])
            .args(&parts[1..])
            .arg(&prompt)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output();
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_response(&stdout)
        }
        Ok(Err(e)) => {
            eprintln!("longline: ai-judge process error: {e}");
            Decision::Ask
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            eprintln!("longline: ai-judge timed out after {}s", config.timeout);
            Decision::Ask
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            eprintln!("longline: ai-judge thread error");
            Decision::Ask
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    fn test_config() -> AiJudgeConfig {
        default_config()
    }

    #[test]
    fn test_extract_python_c() {
        let stmt = parser::parse("python3 -c 'print(1)'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some());
        let (lang, code) = result.unwrap();
        assert_eq!(lang, "python3");
        assert_eq!(code, "print(1)");
    }

    #[test]
    fn test_extract_node_e() {
        let stmt = parser::parse("node -e 'console.log(1)'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some());
        let (lang, code) = result.unwrap();
        assert_eq!(lang, "node");
        assert_eq!(code, "console.log(1)");
    }

    #[test]
    fn test_extract_ruby_e() {
        let stmt = parser::parse("ruby -e 'puts 1'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some());
        let (lang, code) = result.unwrap();
        assert_eq!(lang, "ruby");
        assert_eq!(code, "puts 1");
    }

    #[test]
    fn test_no_extract_for_script() {
        let stmt = parser::parse("python3 script.py").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_none(), "script.py should not match -c trigger");
    }

    #[test]
    fn test_no_extract_for_version() {
        let stmt = parser::parse("python3 --version").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_none(), "--version should not match -c trigger");
    }

    #[test]
    fn test_no_extract_for_non_interpreter() {
        let stmt = parser::parse("ls -la").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_no_extract_for_pipeline() {
        let stmt = parser::parse("echo hello | python3 -c 'import sys'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_prompt() {
        let prompt = build_prompt("python3", "print(1)", "/home/user/project");
        assert!(prompt.contains("python3"));
        assert!(prompt.contains("print(1)"));
        assert!(prompt.contains("/home/user/project"));
        assert!(prompt.contains("ALLOW:"));
        assert!(prompt.contains("ASK:"));
    }

    #[test]
    fn test_parse_response_allow() {
        assert_eq!(parse_response("ALLOW: safe computation"), Decision::Allow);
    }

    #[test]
    fn test_parse_response_ask() {
        assert_eq!(
            parse_response("ASK: network access detected"),
            Decision::Ask
        );
    }

    #[test]
    fn test_parse_response_with_noise() {
        let output = "OpenAI Codex v0.84.0\n--------\nALLOW: safe computation\ntokens used\n";
        assert_eq!(parse_response(output), Decision::Allow);
    }

    #[test]
    fn test_parse_response_unparseable() {
        assert_eq!(parse_response("something unexpected"), Decision::Ask);
    }

    #[test]
    fn test_parse_response_empty() {
        assert_eq!(parse_response(""), Decision::Ask);
    }

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
        let config: AiJudgeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.command, "claude -p");
        assert_eq!(config.timeout, 10);
        assert_eq!(config.triggers.interpreters.len(), 1);
        assert_eq!(
            config.triggers.interpreters[0].name,
            vec!["python", "python3"]
        );
    }

    #[test]
    fn test_config_defaults() {
        let yaml = "{}";
        let config: AiJudgeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.command, "codex exec");
        assert_eq!(config.timeout, 15);
        assert!(!config.triggers.interpreters.is_empty());
    }
}
