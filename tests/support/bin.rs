use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::result::RunResult;

/// Path to the compiled longline binary.
pub fn longline_bin() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_longline") {
        return PathBuf::from(path);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join("longline")
}

pub fn run_longline(args: &[&str], home: &Path, stdin: Option<&str>) -> RunResult {
    let stdin_mode = if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    };

    let mut child = Command::new(longline_bin())
        .args(args)
        .env("HOME", home)
        .stdin(stdin_mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin should be piped")
            .write_all(input.as_bytes())
            .expect("write stdin");
    }

    let output = child.wait_with_output().expect("wait for longline");
    RunResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

pub fn run_longline_allow_stdin_write_error(args: &[&str], home: &Path, stdin: &str) -> RunResult {
    let mut child = Command::new(longline_bin())
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    let _ = child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(stdin.as_bytes());

    let output = child.wait_with_output().expect("wait for longline");
    RunResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}
