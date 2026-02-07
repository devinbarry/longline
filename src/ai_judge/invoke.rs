use crate::types::Decision;

use super::config::AiJudgeConfig;
use super::prompt::{build_prompt, build_prompt_lenient};
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
    evaluate_with_prompt(config, prompt)
}

/// Evaluate inline code using the AI judge with a lenient prompt.
/// Returns (decision, reason) where reason is the AI's assessment.
pub fn evaluate_lenient(
    config: &AiJudgeConfig,
    language: &str,
    code: &str,
    cwd: &str,
    context: Option<&str>,
) -> (Decision, String) {
    let prompt = build_prompt_lenient(language, code, cwd, context);
    evaluate_with_prompt(config, prompt)
}

#[cfg(unix)]
fn kill_process_group(pid: u32) {
    if pid == 0 {
        return;
    }
    // Ignore errors (process may have already exited).
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}

fn evaluate_with_prompt(config: &AiJudgeConfig, prompt: String) -> (Decision, String) {
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

    let mut cmd = std::process::Command::new(&parts[0]);
    cmd.args(&parts[1..])
        .arg(&prompt)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let reason = format!("AI judge error: {e}");
            eprintln!("longline: ai-judge process error: {e}");
            return (Decision::Ask, reason);
        }
    };

    let child_pid = child.id();
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let reason = "AI judge error: failed to capture stdout".to_string();
            eprintln!("longline: ai-judge failed to capture stdout");
            return (Decision::Ask, reason);
        }
    };
    let stderr = match child.stderr.take() {
        Some(s) => s,
        None => {
            let reason = "AI judge error: failed to capture stderr".to_string();
            eprintln!("longline: ai-judge failed to capture stderr");
            return (Decision::Ask, reason);
        }
    };

    let stdout_handle = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut reader = stdout;
        let _ = reader.read_to_end(&mut buf);
        buf
    });
    let stderr_handle = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut reader = stderr;
        let _ = reader.read_to_end(&mut buf);
        buf
    });

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {}
            Err(e) => {
                let reason = format!("AI judge error: {e}");
                eprintln!("longline: ai-judge process error: {e}");
                #[cfg(unix)]
                kill_process_group(child_pid);
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return (Decision::Ask, reason);
            }
        }

        if start.elapsed() >= timeout {
            #[cfg(unix)]
            kill_process_group(child_pid);
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            let reason = format!("AI judge error: timed out after {}s", config.timeout);
            eprintln!("longline: ai-judge timed out after {}s", config.timeout);
            return (Decision::Ask, reason);
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let stdout = stdout_handle.join().unwrap_or_default();
    let _stderr = stderr_handle.join().unwrap_or_default();
    let stdout = String::from_utf8_lossy(&stdout);
    parse_response_with_reason(&stdout)
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

        // Use both process ID and thread ID for unique filenames across parallel tests
        let unique_name = format!(
            "{}-{:?}-{}",
            name,
            std::thread::current().id(),
            std::process::id()
        );
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("ai-judge-invoke");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(unique_name);
        std::fs::write(&path, contents).unwrap();
        // Ensure file is synced to disk before setting permissions
        std::fs::File::open(&path).unwrap().sync_all().unwrap();
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
            // Use generous timeout (10s) to avoid flakiness under CI load
            timeout: 10,
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
sleep 10
echo "ALLOW: safe computation"
"#,
        );
        let config = AiJudgeConfig {
            command: script.to_string_lossy().to_string(),
            // Use 1s timeout with 10s sleep to reliably trigger timeout
            timeout: 1,
            triggers: super::super::config::TriggersConfig::default(),
        };

        let (decision, reason) = evaluate(&config, "python3", "print(1)", "/tmp", None);
        assert_eq!(decision, Decision::Ask);
        assert_eq!(reason, "AI judge error: timed out after 1s");

        let _ = std::fs::remove_file(&script);
    }
}
