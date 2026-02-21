//! Shared test harness for longline integration tests.
//!
//! Provides two patterns:
//! 1. `TestEnv` builder -- isolated HOME/project dirs, no --config flag (uses embedded defaults)
//! 2. Standalone helper functions -- shared static HOME, uses --config pointing to rules/rules.yaml

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// RunResult
// ---------------------------------------------------------------------------

/// Captures exit code, stdout, and stderr from a longline invocation.
pub struct RunResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl RunResult {
    /// Parse hook JSON stdout and return the permissionDecision value.
    pub fn decision(&self) -> String {
        let parsed: serde_json::Value = serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "Failed to parse stdout as JSON: {e}\nstdout: {}\nstderr: {}",
                self.stdout, self.stderr
            )
        });
        parsed["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "Missing hookSpecificOutput.permissionDecision in: {}",
                    self.stdout
                )
            })
            .to_string()
    }

    /// Parse hook JSON stdout and return the permissionDecisionReason value.
    pub fn reason(&self) -> String {
        let parsed: serde_json::Value = serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "Failed to parse stdout as JSON: {e}\nstdout: {}\nstderr: {}",
                self.stdout, self.stderr
            )
        });
        parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "Missing hookSpecificOutput.permissionDecisionReason in: {}",
                    self.stdout
                )
            })
            .to_string()
    }

    /// Assert that the decision matches `expected`, with a descriptive panic on failure.
    pub fn assert_decision(&self, expected: &str) {
        let actual = self.decision();
        assert_eq!(
            actual, expected,
            "Expected decision '{}' but got '{}'\nstdout: {}\nstderr: {}",
            expected, actual, self.stdout, self.stderr
        );
    }

    /// Assert that the reason contains `substring`.
    pub fn assert_reason_contains(&self, substring: &str) {
        let reason = self.reason();
        assert!(
            reason.contains(substring),
            "Expected reason to contain '{}' but got: {}\nstdout: {}\nstderr: {}",
            substring,
            reason,
            self.stdout,
            self.stderr
        );
    }

    /// Assert that the reason does NOT contain `substring`.
    pub fn assert_reason_not_contains(&self, substring: &str) {
        let reason = self.reason();
        assert!(
            !reason.contains(substring),
            "Expected reason to NOT contain '{}' but got: {}\nstdout: {}\nstderr: {}",
            substring,
            reason,
            self.stdout,
            self.stderr
        );
    }
}

// ---------------------------------------------------------------------------
// TestEnv builder
// ---------------------------------------------------------------------------

/// Builder for constructing a `TestEnv` with optional project/global configs.
pub struct TestEnvBuilder {
    project_config: Option<String>,
    global_config: Option<String>,
}

/// An isolated test environment with its own HOME (and optionally a project dir).
/// Temp directories are cleaned up on drop.
pub struct TestEnv {
    home_dir: tempfile::TempDir,
    project_dir: Option<tempfile::TempDir>,
}

impl TestEnv {
    /// Start building a new test environment.
    pub fn new() -> TestEnvBuilder {
        TestEnvBuilder {
            project_config: None,
            global_config: None,
        }
    }

    /// Run the longline binary in hook mode (no --config flag, uses embedded defaults).
    /// Sends a Bash tool hook JSON on stdin.
    pub fn run_hook(&self, command: &str) -> RunResult {
        self.run_hook_with_flags(command, &[])
    }

    /// Run the longline binary in hook mode with extra CLI flags.
    pub fn run_hook_with_flags(&self, command: &str, extra_args: &[&str]) -> RunResult {
        let cwd = self
            .project_dir
            .as_ref()
            .map(|d| d.path().to_string_lossy().to_string())
            .unwrap_or_else(|| "/tmp".to_string());

        let input = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "session_id": "test-session",
            "cwd": cwd
        });

        let home = self.home_dir.path().to_string_lossy().to_string();
        let mut child = Command::new(longline_bin())
            .args(extra_args)
            .env("HOME", &home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn longline");

        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();

        let output = child.wait_with_output().unwrap();
        RunResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }

    /// Run the longline binary in hook mode for a non-Bash tool.
    pub fn run_hook_tool(&self, tool_name: &str, command: &str) -> RunResult {
        let cwd = self
            .project_dir
            .as_ref()
            .map(|d| d.path().to_string_lossy().to_string())
            .unwrap_or_else(|| "/tmp".to_string());

        let input = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": { "command": command },
            "session_id": "test-session",
            "cwd": cwd
        });

        let home = self.home_dir.path().to_string_lossy().to_string();
        let mut child = Command::new(longline_bin())
            .env("HOME", &home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn longline");

        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();

        let output = child.wait_with_output().unwrap();
        RunResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }

    /// Run a longline subcommand (rules, check, files, etc.).
    /// If a project dir exists and no --dir is in args, auto-adds --dir.
    pub fn run_subcommand(&self, args: &[&str]) -> RunResult {
        let home = self.home_dir.path().to_string_lossy().to_string();
        let has_dir_flag = args.iter().any(|a| *a == "--dir");

        let mut full_args: Vec<&str> = args.to_vec();

        // We need to own the string so the borrow lives long enough
        let project_path_str;
        if !has_dir_flag {
            if let Some(ref project) = self.project_dir {
                project_path_str = project.path().to_string_lossy().to_string();
                full_args.push("--dir");
                full_args.push(&project_path_str);
            }
        }

        let child = Command::new(longline_bin())
            .args(&full_args)
            .env("HOME", &home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn longline");

        let output = child.wait_with_output().unwrap();
        RunResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }

    /// Returns the project directory path (panics if no project dir was configured).
    pub fn project_path(&self) -> &Path {
        self.project_dir
            .as_ref()
            .expect("No project directory configured for this TestEnv")
            .path()
    }

    /// Returns the HOME directory path.
    pub fn home_path(&self) -> &Path {
        self.home_dir.path()
    }
}

impl TestEnvBuilder {
    /// Set the project config content (written to `.claude/longline.yaml`).
    pub fn with_project_config(mut self, yaml: &str) -> Self {
        self.project_config = Some(yaml.to_string());
        self
    }

    /// Set the global config content (written to `~/.config/longline/longline.yaml`).
    pub fn with_global_config(mut self, yaml: &str) -> Self {
        self.global_config = Some(yaml.to_string());
        self
    }

    /// Build the test environment, creating temp dirs and writing config files.
    pub fn build(self) -> TestEnv {
        // Create HOME temp dir
        let home_dir = tempfile::TempDir::new().expect("Failed to create temp HOME dir");

        // Always create fake AI judge config so tests never invoke a real AI judge
        let config_dir = home_dir.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("ai-judge.yaml"),
            "command: /definitely-not-a-real-ai-judge-command-12345\ntimeout: 1\n",
        )
        .unwrap();

        // Write global config if provided
        if let Some(ref yaml) = self.global_config {
            std::fs::write(config_dir.join("longline.yaml"), yaml).unwrap();
        }

        // Create project dir if project config was provided
        let project_dir = if let Some(ref yaml) = self.project_config {
            let dir = tempfile::TempDir::new().expect("Failed to create temp project dir");
            std::fs::create_dir_all(dir.path().join(".git")).unwrap();
            let claude_dir = dir.path().join(".claude");
            std::fs::create_dir_all(&claude_dir).unwrap();
            std::fs::write(claude_dir.join("longline.yaml"), yaml).unwrap();
            Some(dir)
        } else {
            None
        };

        TestEnv {
            home_dir,
            project_dir,
        }
    }
}

// ---------------------------------------------------------------------------
// Standalone helper functions (shared static HOME, uses --config)
// ---------------------------------------------------------------------------

/// Path to the compiled longline binary.
pub fn longline_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join("longline")
}

/// Path to the rules/rules.yaml file in the repo.
pub fn rules_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("rules")
        .join("rules.yaml")
        .to_string_lossy()
        .to_string()
}

/// Shared static HOME directory with a fake AI judge config.
/// Re-used across tests that don't need config isolation.
pub fn static_test_home() -> &'static PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("common-home");
        std::fs::create_dir_all(&dir).unwrap();

        let config_dir = dir.join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("ai-judge.yaml"),
            "command: /definitely-not-a-real-ai-judge-command-12345\ntimeout: 1\n",
        )
        .unwrap();

        dir
    })
}

/// Run longline in hook mode with --config pointing to rules/rules.yaml.
pub fn run_hook(tool_name: &str, command: &str) -> RunResult {
    run_hook_with_flags(tool_name, command, &[])
}

/// Run longline in hook mode with --config and extra CLI flags.
pub fn run_hook_with_flags(tool_name: &str, command: &str, extra_args: &[&str]) -> RunResult {
    let input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": { "command": command },
        "session_id": "test-session",
        "cwd": "/tmp"
    });

    let config = rules_path();
    let mut args = vec!["--config", &config];
    args.extend_from_slice(extra_args);

    let home = static_test_home().to_string_lossy().to_string();
    let mut child = Command::new(longline_bin())
        .args(&args)
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    RunResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Run longline in hook mode with a specific config file path.
pub fn run_hook_with_config(tool_name: &str, command: &str, config: &str) -> RunResult {
    let input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": { "command": command },
        "session_id": "test-session",
        "cwd": "/tmp"
    });

    let home = static_test_home().to_string_lossy().to_string();
    let mut child = Command::new(longline_bin())
        .args(["--config", config])
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    RunResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Run a longline subcommand with the shared static HOME.
pub fn run_subcommand(args: &[&str]) -> RunResult {
    let home = static_test_home().to_string_lossy().to_string();
    run_subcommand_with_home(args, &home)
}

/// Run a longline subcommand with a specific HOME directory.
pub fn run_subcommand_with_home(args: &[&str], home: &str) -> RunResult {
    let child = Command::new(longline_bin())
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    let output = child.wait_with_output().unwrap();
    RunResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}
