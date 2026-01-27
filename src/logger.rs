use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use crate::types::Decision;

#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub ts: String,
    pub tool: String,
    pub cwd: String,
    pub command: String,
    pub decision: Decision,
    pub matched_rules: Vec<String>,
    pub reason: Option<String>,
    pub parse_ok: bool,
    pub session_id: Option<String>,
}

/// Default log directory.
fn default_log_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".claude").join("hooks-logs")
}

/// Default log file path.
fn log_file_path() -> PathBuf {
    default_log_dir().join("longline.jsonl")
}

/// Write a log entry. Errors are printed to stderr but do not fail the process.
pub fn log_decision(entry: &LogEntry) {
    log_decision_to(entry, &log_file_path());
}

/// Write a log entry to a specific path (for testing).
pub fn log_decision_to(entry: &LogEntry, path: &PathBuf) {
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("longline: failed to create log directory: {e}");
            return;
        }
    }

    let json = match serde_json::to_string(entry) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("longline: failed to serialize log entry: {e}");
            return;
        }
    };

    let mut file = match OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("longline: failed to open log file: {e}");
            return;
        }
    };

    if let Err(e) = writeln!(file, "{json}") {
        eprintln!("longline: failed to write log entry: {e}");
    }
}

/// Create a log entry from evaluation results.
pub fn make_entry(
    tool: &str,
    cwd: &str,
    command: &str,
    decision: Decision,
    matched_rules: Vec<String>,
    reason: Option<String>,
    parse_ok: bool,
    session_id: Option<String>,
) -> LogEntry {
    let truncated_command = if command.len() > 1024 {
        format!("{}...", &command[..1024])
    } else {
        command.to_string()
    };

    LogEntry {
        ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        tool: tool.to_string(),
        cwd: cwd.to_string(),
        command: truncated_command,
        decision,
        matched_rules,
        reason,
        parse_ok,
        session_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_make_entry_truncates_long_command() {
        let long_cmd = "x".repeat(2000);
        let entry = make_entry("Bash", "/tmp", &long_cmd, Decision::Allow, vec![], None, true, None);
        assert!(entry.command.len() <= 1028); // 1024 + "..."
        assert!(entry.command.ends_with("..."));
    }

    #[test]
    fn test_make_entry_short_command() {
        let entry = make_entry("Bash", "/tmp", "ls", Decision::Allow, vec![], None, true, None);
        assert_eq!(entry.command, "ls");
    }

    #[test]
    fn test_log_entry_serialization() {
        let entry = make_entry(
            "Bash",
            "/home/user",
            "rm -rf /",
            Decision::Deny,
            vec!["rm-recursive-root".into()],
            Some("Recursive delete".into()),
            true,
            Some("session-123".into()),
        );
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"decision\":\"deny\""));
        assert!(json.contains("\"rm-recursive-root\""));
        assert!(json.contains("\"session_id\":\"session-123\""));
    }

    #[test]
    fn test_log_decision_to_file() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-logs");
        let path = dir.join("test.jsonl");
        // Clean up from previous runs
        let _ = fs::remove_file(&path);

        let entry = make_entry("Bash", "/tmp", "ls", Decision::Allow, vec![], None, true, None);
        log_decision_to(&entry, &path);

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"command\":\"ls\""));
        assert!(content.contains("\"decision\":\"allow\""));

        // Clean up
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
