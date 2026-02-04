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
