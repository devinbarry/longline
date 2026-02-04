use crate::types::Decision;

use super::config::AiJudgeConfig;
use super::prompt::build_prompt;
use super::response::parse_response_with_reason;

/// Evaluate inline code using the AI judge.
/// Returns (decision, reason) where reason is the AI's assessment.
pub fn evaluate(
    config: &AiJudgeConfig,
    language: &str,
    code: &str,
    cwd: &str,
    context: Option<&str>,
) -> (Decision, String) {
    let prompt = build_prompt(language, code, cwd, context);

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

    #[test]
    fn test_evaluate_empty_command_returns_ask() {
        let config = AiJudgeConfig {
            command: String::new(),
            timeout: 1,
            triggers: super::super::config::TriggersConfig::default(),
        };
        let (decision, reason) = evaluate(&config, "python3", "print(1)", "/tmp", None);
        assert_eq!(decision, Decision::Ask);
        assert_eq!(reason, "AI judge error: command is empty");
    }

    #[test]
    fn test_evaluate_missing_command_returns_ask_with_error_prefix() {
        let config = AiJudgeConfig {
            command: "/definitely-not-a-real-ai-judge-command-12345".to_string(),
            timeout: 1,
            triggers: super::super::config::TriggersConfig::default(),
        };
        let (decision, reason) = evaluate(&config, "python3", "print(1)", "/tmp", None);
        assert_eq!(decision, Decision::Ask);
        assert!(
            reason.starts_with("AI judge error:"),
            "Expected error prefix, got: {reason}"
        );
    }

    #[cfg(unix)]
    fn make_executable_script(name: &str, contents: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;

        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("ai-judge-invoke");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn test_evaluate_parses_allow_from_command_output() {
        let script = make_executable_script(
            "allow.sh",
            r#"#!/bin/sh
if [ "$#" -ne 1 ]; then
  echo "ASK: missing prompt arg"
  exit 0
fi
echo "ALLOW: safe computation"
"#,
        );
        let config = AiJudgeConfig {
            command: script.to_string_lossy().to_string(),
            timeout: 2,
            triggers: super::super::config::TriggersConfig::default(),
        };

        let (decision, reason) = evaluate(&config, "python3", "print(1)", "/tmp", None);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(reason, "ALLOW: safe computation");

        let _ = std::fs::remove_file(&script);
    }

    #[cfg(unix)]
    #[test]
    fn test_evaluate_times_out() {
        let script = make_executable_script(
            "sleep.sh",
            r#"#!/bin/sh
sleep 2
echo "ALLOW: safe computation"
"#,
        );
        let config = AiJudgeConfig {
            command: script.to_string_lossy().to_string(),
            timeout: 0,
            triggers: super::super::config::TriggersConfig::default(),
        };

        let (decision, reason) = evaluate(&config, "python3", "print(1)", "/tmp", None);
        assert_eq!(decision, Decision::Ask);
        assert_eq!(reason, "AI judge error: timed out after 0s");

        let _ = std::fs::remove_file(&script);
    }
}
