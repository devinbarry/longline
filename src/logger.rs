use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use longline::types::Decision;

const DEFAULT_MAX_LOG_FILE_BYTES: u64 = 25 * 1024 * 1024;
const MAX_ROTATED_LOG_FILES: usize = 10;
const LOG_MAX_BYTES_ENV: &str = "LONGLINE_LOG_MAX_BYTES";

#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub version: &'static str,
    pub ts: String,
    pub tool: String,
    pub cwd: String,
    pub command: String,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_decision: Option<Decision>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub overridden: bool,
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
pub fn log_decision_to(entry: &LogEntry, path: &Path) {
    log_decision_to_with_rotation(
        entry,
        path,
        configured_max_log_file_bytes(),
        MAX_ROTATED_LOG_FILES,
    );
}

fn configured_max_log_file_bytes() -> u64 {
    std::env::var(LOG_MAX_BYTES_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(DEFAULT_MAX_LOG_FILE_BYTES)
}

fn rotated_log_path(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn rotate_logs(path: &Path, keep_files: usize) -> io::Result<()> {
    if keep_files == 0 {
        return Ok(());
    }

    let oldest = rotated_log_path(path, keep_files);
    if oldest.exists() {
        fs::remove_file(oldest)?;
    }

    for index in (1..keep_files).rev() {
        let src = rotated_log_path(path, index);
        if src.exists() {
            let dst = rotated_log_path(path, index + 1);
            fs::rename(src, dst)?;
        }
    }

    if path.exists() {
        fs::rename(path, rotated_log_path(path, 1))?;
    }

    Ok(())
}

fn maybe_rotate_before_append(
    path: &Path,
    next_entry_len: usize,
    max_bytes: u64,
    keep_files: usize,
) -> io::Result<()> {
    if max_bytes == 0 {
        return Ok(());
    }

    let current_bytes = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e),
    };

    let projected = current_bytes
        .saturating_add(next_entry_len as u64)
        .saturating_add(1);
    if projected > max_bytes {
        rotate_logs(path, keep_files)?;
    }

    Ok(())
}

fn log_decision_to_with_rotation(entry: &LogEntry, path: &Path, max_bytes: u64, keep_files: usize) {
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

    if let Err(e) = maybe_rotate_before_append(path, json.len(), max_bytes, keep_files) {
        eprintln!("longline: failed to rotate log files: {e}");
    }

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
#[allow(clippy::too_many_arguments)]
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
    LogEntry {
        version: env!("CARGO_PKG_VERSION"),
        ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        tool: tool.to_string(),
        cwd: cwd.to_string(),
        command: command.to_string(),
        decision,
        original_decision: None,
        overridden: false,
        matched_rules,
        reason,
        parse_ok,
        session_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("test-logs-{label}-{nanos}"))
    }

    #[test]
    fn test_make_entry_does_not_truncate_long_command() {
        let long_cmd = "x".repeat(2000);
        let entry = make_entry(
            "Bash",
            "/tmp",
            &long_cmd,
            Decision::Allow,
            vec![],
            None,
            true,
            None,
        );
        assert_eq!(entry.command.len(), 2000);
        assert_eq!(entry.command, long_cmd);
    }

    #[test]
    fn test_make_entry_short_command() {
        let entry = make_entry(
            "Bash",
            "/tmp",
            "ls",
            Decision::Allow,
            vec![],
            None,
            true,
            None,
        );
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
        assert!(json.contains("\"version\":\""));
        assert!(json.contains("\"decision\":\"deny\""));
        assert!(json.contains("\"rm-recursive-root\""));
        assert!(json.contains("\"session_id\":\"session-123\""));
    }

    #[test]
    fn test_log_decision_to_file() {
        let dir = unique_test_dir("basic-write");
        let path = dir.join("test.jsonl");

        let entry = make_entry(
            "Bash",
            "/tmp",
            "ls",
            Decision::Allow,
            vec![],
            None,
            true,
            None,
        );
        log_decision_to(&entry, &path);

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"command\":\"ls\""));
        assert!(content.contains("\"decision\":\"allow\""));

        // Clean up
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rotation_when_projected_size_exceeds_max() {
        let dir = unique_test_dir("rotation-threshold");
        let path = dir.join("test.jsonl");

        let first = make_entry(
            "Bash",
            "/tmp",
            "first-command",
            Decision::Allow,
            vec![],
            None,
            true,
            None,
        );
        let second = make_entry(
            "Bash",
            "/tmp",
            "second-command",
            Decision::Allow,
            vec![],
            None,
            true,
            None,
        );

        let first_len = serde_json::to_string(&first).unwrap().len() as u64;
        let max_bytes = first_len + 5;

        log_decision_to_with_rotation(&first, &path, max_bytes, 10);
        log_decision_to_with_rotation(&second, &path, max_bytes, 10);

        let current = fs::read_to_string(&path).unwrap();
        let rotated = fs::read_to_string(rotated_log_path(&path, 1)).unwrap();
        assert!(current.contains("\"command\":\"second-command\""));
        assert!(rotated.contains("\"command\":\"first-command\""));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rotation_keeps_most_recent_10_files() {
        let dir = unique_test_dir("rotation-retention");
        let path = dir.join("test.jsonl");

        for i in 1..=12 {
            let entry = make_entry(
                "Bash",
                "/tmp",
                &format!("cmd-{i}"),
                Decision::Allow,
                vec![],
                None,
                true,
                None,
            );
            log_decision_to_with_rotation(&entry, &path, 1, 10);
        }

        for index in 1..=10 {
            assert!(rotated_log_path(&path, index).exists());
        }
        assert!(!rotated_log_path(&path, 11).exists());

        let current = fs::read_to_string(&path).unwrap();
        let newest_rotated = fs::read_to_string(rotated_log_path(&path, 1)).unwrap();
        let oldest_rotated = fs::read_to_string(rotated_log_path(&path, 10)).unwrap();
        assert!(current.contains("\"command\":\"cmd-12\""));
        assert!(newest_rotated.contains("\"command\":\"cmd-11\""));
        assert!(oldest_rotated.contains("\"command\":\"cmd-2\""));

        let _ = fs::remove_dir_all(&dir);
    }
}
