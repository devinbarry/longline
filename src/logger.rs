use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use longline::domain::Decision;

const DEFAULT_MAX_LOG_FILE_BYTES: u64 = 25 * 1024 * 1024;
const MAX_ROTATED_LOG_FILES: usize = 10;
const LOG_MAX_BYTES_ENV: &str = "LONGLINE_LOG_MAX_BYTES";

#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub version: &'static str,
    pub runtime: &'static str,
    pub profile: String,
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

/// Context carried into every audit log entry. Single constructor seam
/// per CLAUDE.md "one constructor only".
#[derive(Debug)]
pub struct EntryContext {
    pub runtime: &'static str,
    pub profile: String,
}

/// Write a log entry to a specific path.
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

    // Build the entire record (JSON + newline) and emit it via a single write_all.
    // writeln! issues two separate write() syscalls (content, then '\n'); under
    // concurrent invocations on an O_APPEND file this lets two records interleave
    // as `{json_a}{json_b}\n\n`, producing JSONL parse errors. write_all over a
    // pre-joined buffer is expected to complete as a single OS write for these
    // small regular-file appends on Linux/macOS, in which case POSIX.1-2017 §2.9.7
    // guarantees the kernel atomically seeks to EOF and appends in one operation.
    // write_all may still loop after a short write under exceptional conditions
    // (quota/ENOSPC/RLIMIT_FSIZE/signal-after-progress), but those are outside the
    // observed corruption mode and would produce a different failure signature.
    let mut record = json;
    record.push('\n');
    if let Err(e) = file.write_all(record.as_bytes()) {
        eprintln!("longline: failed to write log entry: {e}");
    }
}

/// Create a log entry from evaluation results.
#[allow(clippy::too_many_arguments)]
pub fn make_entry(
    ctx: &EntryContext,
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
        runtime: ctx.runtime,
        profile: ctx.profile.clone(),
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
        let ctx = EntryContext {
            runtime: "claude",
            profile: "default".into(),
        };
        let entry = make_entry(
            &ctx,
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
        let ctx = EntryContext {
            runtime: "claude",
            profile: "default".into(),
        };
        let entry = make_entry(
            &ctx,
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
        let ctx = EntryContext {
            runtime: "claude",
            profile: "default".into(),
        };
        let entry = make_entry(
            &ctx,
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
        assert!(json.contains("\"runtime\":\"claude\""));
        assert!(json.contains("\"decision\":\"deny\""));
        assert!(json.contains("\"rm-recursive-root\""));
        assert!(json.contains("\"session_id\":\"session-123\""));
    }

    #[test]
    fn test_make_entry_with_runtime_serializes_runtime_field() {
        let ctx = EntryContext {
            runtime: "claude",
            profile: "default".into(),
        };
        let entry = make_entry(
            &ctx,
            "Bash",
            "/tmp",
            "ls",
            Decision::Allow,
            vec![],
            None,
            true,
            None,
        );
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"runtime\":\"claude\""), "got: {json}");
    }

    #[test]
    fn test_make_entry_with_runtime_codex() {
        let ctx = EntryContext {
            runtime: "codex",
            profile: "default".into(),
        };
        let entry = make_entry(
            &ctx,
            "Bash",
            "/tmp",
            "rm -rf /",
            Decision::Deny,
            vec!["rm-recursive-root".into()],
            Some("recursive delete".into()),
            true,
            None,
        );
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"runtime\":\"codex\""), "got: {json}");
        assert!(json.contains("\"decision\":\"deny\""), "got: {json}");
    }

    #[test]
    fn test_make_entry_serializes_profile_field() {
        let ctx = EntryContext {
            runtime: "codex",
            profile: "strict".into(),
        };
        let entry = make_entry(
            &ctx,
            "Bash",
            "/tmp",
            "ls",
            Decision::Allow,
            vec![],
            None,
            true,
            None,
        );
        let j = serde_json::to_string(&entry).unwrap();
        assert!(j.contains("\"runtime\":\"codex\""));
        assert!(j.contains("\"profile\":\"strict\""));
    }

    #[test]
    fn test_make_entry_profile_default_string() {
        let ctx = EntryContext {
            runtime: "claude",
            profile: "default".into(),
        };
        let entry = make_entry(
            &ctx,
            "Bash",
            "/tmp",
            "ls",
            Decision::Allow,
            vec![],
            None,
            true,
            None,
        );
        let j = serde_json::to_string(&entry).unwrap();
        assert!(j.contains("\"profile\":\"default\""));
    }

    #[test]
    fn test_make_entry_unresolved_sentinel_serializes() {
        let ctx = EntryContext {
            runtime: "codex",
            profile: "unresolved".into(),
        };
        let entry = make_entry(
            &ctx,
            "Bash",
            "",
            "",
            Decision::Allow,
            vec![],
            None,
            false,
            None,
        );
        let j = serde_json::to_string(&entry).unwrap();
        assert!(j.contains("\"profile\":\"unresolved\""));
    }

    #[test]
    fn test_each_appended_record_is_one_jsonl_line() {
        // Line-shape guard: every call to log_decision_to must produce exactly
        // one newline-terminated, well-formed JSON line. This does NOT catch
        // the original concurrent-append regression — a serial writeln! on an
        // unbuffered File would still yield well-shaped lines because there is
        // no interleaving to observe — but it does pin the per-record output
        // contract (one record == one line, no stray blank lines, no truncated
        // tail, valid JSON), so unrelated changes that drop the trailing
        // newline or emit empty records still fail loudly.
        let dir = unique_test_dir("jsonl-shape");
        let path = dir.join("test.jsonl");

        let n = 100;
        for i in 0..n {
            let ctx = EntryContext {
                runtime: "codex",
                profile: "default".into(),
            };
            let entry = make_entry(
                &ctx,
                "Bash",
                "/tmp",
                &format!("cmd-{i}"),
                Decision::Allow,
                vec![],
                None,
                true,
                None,
            );
            log_decision_to(&entry, &path);
        }

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.split_inclusive('\n').collect();
        assert_eq!(lines.len(), n, "expected {n} lines, got {}", lines.len());
        for (idx, line) in lines.iter().enumerate() {
            assert!(line.ends_with('\n'), "line {idx} missing trailing newline");
            let trimmed = line.trim_end_matches('\n');
            assert!(!trimmed.is_empty(), "line {idx} is blank");
            let parsed: serde_json::Value = serde_json::from_str(trimmed)
                .unwrap_or_else(|e| panic!("line {idx} not valid JSON: {e}: {trimmed}"));
            assert_eq!(parsed["command"], format!("cmd-{idx}"));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_log_decision_to_file() {
        let dir = unique_test_dir("basic-write");
        let path = dir.join("test.jsonl");

        let ctx = EntryContext {
            runtime: "claude",
            profile: "default".into(),
        };
        let entry = make_entry(
            &ctx,
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

        let ctx = EntryContext {
            runtime: "claude",
            profile: "default".into(),
        };
        let first = make_entry(
            &ctx,
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
            &ctx,
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
            let ctx = EntryContext {
                runtime: "claude",
                profile: "default".into(),
            };
            let entry = make_entry(
                &ctx,
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
