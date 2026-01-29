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

/// Check if a statement contains an interpreter with inline code.
/// Returns (language, code) if matched.
/// Recurses into Pipeline, List, Subshell, and CommandSubstitution to find interpreter stages.
pub fn extract_inline_code(stmt: &Statement, config: &AiJudgeConfig) -> Option<(String, String)> {
    match stmt {
        Statement::SimpleCommand(cmd) => {
            // First check embedded substitutions
            for sub in &cmd.embedded_substitutions {
                if let Some(result) = extract_inline_code(sub, config) {
                    return Some(result);
                }
            }
            // Then check the command itself
            extract_from_simple_command(cmd, config)
        }
        Statement::Pipeline(pipeline) => {
            for stage in &pipeline.stages {
                if let Some(result) = extract_inline_code(stage, config) {
                    return Some(result);
                }
            }
            None
        }
        Statement::List(list) => {
            if let Some(result) = extract_inline_code(&list.first, config) {
                return Some(result);
            }
            for (_, stmt) in &list.rest {
                if let Some(result) = extract_inline_code(stmt, config) {
                    return Some(result);
                }
            }
            None
        }
        Statement::Subshell(inner) | Statement::CommandSubstitution(inner) => {
            extract_inline_code(inner, config)
        }
        Statement::Opaque(_) => None,
    }
}

/// Extract inline code from a simple command if it matches a trigger.
fn extract_from_simple_command(
    cmd: &crate::parser::SimpleCommand,
    config: &AiJudgeConfig,
) -> Option<(String, String)> {
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

/// Parse the AI judge response, returning both the decision and the full reason line.
pub fn parse_response_with_reason(output: &str) -> (Decision, String) {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ALLOW:") {
            return (Decision::Allow, trimmed.to_string());
        }
        if trimmed.starts_with("ASK:") {
            return (Decision::Ask, trimmed.to_string());
        }
    }
    (Decision::Ask, "AI judge: unparseable response".to_string())
}

// ── LLM invocation ─────────────────────────────────────────────

/// Evaluate inline code using the AI judge.
/// Returns (decision, reason) where reason is the AI's assessment.
pub fn evaluate(
    config: &AiJudgeConfig,
    language: &str,
    code: &str,
    cwd: &str,
) -> (Decision, String) {
    let prompt = build_prompt(language, code, cwd);

    let parts: Vec<String> = config
        .command
        .split_whitespace()
        .map(String::from)
        .collect();
    if parts.is_empty() {
        let reason = "AI judge error: command is empty".to_string();
        eprintln!("longline: ai-judge command is empty");
        return (Decision::Ask, reason);
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
            parse_response_with_reason(&stdout)
        }
        Ok(Err(e)) => {
            let reason = format!("AI judge error: {e}");
            eprintln!("longline: ai-judge process error: {e}");
            (Decision::Ask, reason)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let reason = format!("AI judge error: timed out after {}s", config.timeout);
            eprintln!("longline: ai-judge timed out after {}s", config.timeout);
            (Decision::Ask, reason)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            let reason = "AI judge error: thread error".to_string();
            eprintln!("longline: ai-judge thread error");
            (Decision::Ask, reason)
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

    // ============================================================
    // Pipeline extraction tests
    // ============================================================

    #[test]
    fn test_extract_from_pipeline_end() {
        let stmt = parser::parse("grep foo | python3 -c 'print(1)'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from pipeline end");
        let (lang, code) = result.unwrap();
        assert_eq!(lang, "python3");
        assert_eq!(code, "print(1)");
    }

    #[test]
    fn test_extract_from_pipeline_start() {
        let stmt = parser::parse("python3 -c 'print(1)' | grep 1").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from pipeline start");
        let (lang, code) = result.unwrap();
        assert_eq!(lang, "python3");
        assert_eq!(code, "print(1)");
    }

    #[test]
    fn test_extract_from_pipeline_middle() {
        let stmt = parser::parse("echo x | python3 -c 'print(1)' | cat").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from pipeline middle");
    }

    #[test]
    fn test_extract_from_multi_stage_pipeline() {
        let stmt = parser::parse("grep a | sort | uniq | python3 -c 'print(1)'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from multi-stage pipeline");
    }

    #[test]
    fn test_no_extract_from_pipeline_without_interpreter() {
        let stmt = parser::parse("grep foo | sort | uniq").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(
            result.is_none(),
            "Should not extract from pipeline without interpreter"
        );
    }

    // ============================================================
    // List extraction tests
    // ============================================================

    #[test]
    fn test_extract_from_and_list() {
        let stmt = parser::parse("echo ok && python3 -c 'print(1)'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from && list");
    }

    #[test]
    fn test_extract_from_or_list() {
        let stmt = parser::parse("false || python3 -c 'print(1)'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from || list");
    }

    #[test]
    fn test_extract_from_semicolon_list() {
        let stmt = parser::parse("echo a; python3 -c 'print(1)'").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from ; list");
    }

    #[test]
    fn test_extract_from_list_first_element() {
        let stmt = parser::parse("python3 -c 'print(1)' && echo done").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from list first element");
    }

    // ============================================================
    // Subshell extraction tests
    // ============================================================

    #[test]
    fn test_extract_from_subshell() {
        let stmt = parser::parse("(python3 -c 'print(1)')").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from subshell");
    }

    // ============================================================
    // Command substitution extraction tests
    // ============================================================

    #[test]
    fn test_extract_from_command_substitution() {
        let stmt = parser::parse("echo $(python3 -c 'print(1)')").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from command substitution");
    }

    #[test]
    fn test_extract_from_backtick_substitution() {
        let stmt = parser::parse("echo `python3 -c 'print(1)'`").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(
            result.is_some(),
            "Should extract from backtick substitution"
        );
    }

    // ============================================================
    // Complex nested tests
    // ============================================================

    #[test]
    fn test_extract_from_pipeline_in_subshell() {
        let stmt = parser::parse("(grep foo | python3 -c 'print(1)')").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_some(), "Should extract from pipeline in subshell");
    }

    // ============================================================
    // Negative tests - should NOT extract
    // ============================================================

    #[test]
    fn test_no_extract_for_module() {
        let stmt = parser::parse("python3 -m pytest").unwrap();
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_none(), "Should not extract for -m flag");
    }

    #[test]
    fn test_no_extract_for_opaque() {
        let stmt = Statement::Opaque("some complex thing".to_string());
        let config = test_config();
        let result = extract_inline_code(&stmt, &config);
        assert!(result.is_none(), "Should not extract from Opaque");
    }

    // ============================================================
    // Response parsing with reason tests
    // ============================================================

    #[test]
    fn test_parse_response_with_reason_allow() {
        let (decision, reason) = parse_response_with_reason("ALLOW: safe computation only");
        assert_eq!(decision, Decision::Allow);
        assert_eq!(reason, "ALLOW: safe computation only");
    }

    #[test]
    fn test_parse_response_with_reason_ask() {
        let (decision, reason) = parse_response_with_reason("ASK: accesses files outside cwd");
        assert_eq!(decision, Decision::Ask);
        assert_eq!(reason, "ASK: accesses files outside cwd");
    }

    #[test]
    fn test_parse_response_with_noise_before() {
        let output = "Loading model...\nALLOW: safe computation";
        let (decision, reason) = parse_response_with_reason(output);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(reason, "ALLOW: safe computation");
    }

    #[test]
    fn test_parse_response_with_noise_after() {
        let output = "ASK: network access\nTokens used: 150";
        let (decision, reason) = parse_response_with_reason(output);
        assert_eq!(decision, Decision::Ask);
        assert_eq!(reason, "ASK: network access");
    }

    #[test]
    fn test_parse_response_with_reason_unparseable() {
        let (decision, reason) = parse_response_with_reason("something random");
        assert_eq!(decision, Decision::Ask);
        assert!(
            reason.contains("unparseable"),
            "Reason should indicate unparseable: {}",
            reason
        );
    }

    #[test]
    fn test_parse_response_with_reason_empty() {
        let (decision, reason) = parse_response_with_reason("");
        assert_eq!(decision, Decision::Ask);
        assert!(reason.contains("unparseable") || reason.contains("AI judge"));
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
        let (decision, _) = parse_response_with_reason("ALLOW: safe computation");
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_parse_response_ask() {
        let (decision, _) = parse_response_with_reason("ASK: network access detected");
        assert_eq!(decision, Decision::Ask);
    }

    #[test]
    fn test_parse_response_with_noise() {
        let output = "OpenAI Codex v0.84.0\n--------\nALLOW: safe computation\ntokens used\n";
        let (decision, _) = parse_response_with_reason(output);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_parse_response_unparseable() {
        let (decision, _) = parse_response_with_reason("something unexpected");
        assert_eq!(decision, Decision::Ask);
    }

    #[test]
    fn test_parse_response_empty() {
        let (decision, _) = parse_response_with_reason("");
        assert_eq!(decision, Decision::Ask);
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
