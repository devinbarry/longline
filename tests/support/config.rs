use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::bin::run_longline;
use super::result::RunResult;

/// Builder for constructing a `TestEnv` with optional project/global configs.
pub struct TestEnvBuilder {
    project_config: Option<String>,
    global_config: Option<String>,
    /// Optional fake AI-judge response. When set, a real shell stub is
    /// written into the test HOME and `ai-judge.yaml` points at it. The
    /// stub prints exactly this response to stdout. The string should be
    /// in the format the longline AI judge parser expects, e.g.
    /// "ALLOW: reason" or "DENY: reason" or "ASK: reason".
    fake_ai_judge_response: Option<String>,
}

/// An isolated test environment with its own HOME (and optionally a project dir).
/// Temp directories are cleaned up on drop.
pub struct TestEnv {
    home_dir: tempfile::TempDir,
    project_dir: Option<tempfile::TempDir>,
}

impl TestEnv {
    /// Start building a new test environment.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> TestEnvBuilder {
        TestEnvBuilder {
            project_config: None,
            global_config: None,
            fake_ai_judge_response: None,
        }
    }

    /// Run a longline subcommand (rules, check, files, etc.).
    /// If a project dir exists and no --dir is in args, auto-adds --dir.
    pub fn run_subcommand(&self, args: &[&str]) -> RunResult {
        let has_dir_flag = args.contains(&"--dir");
        let mut full_args: Vec<&str> = args.to_vec();

        let project_path_str;
        if !has_dir_flag {
            if let Some(ref project) = self.project_dir {
                project_path_str = project.path().to_string_lossy().to_string();
                full_args.push("--dir");
                full_args.push(&project_path_str);
            }
        }

        run_longline(&full_args, self.home_dir.path(), None)
    }

    /// Returns the project directory path (panics if no project dir was configured).
    pub fn project_path(&self) -> &Path {
        self.project_dir
            .as_ref()
            .expect("No project directory configured for this TestEnv")
            .path()
    }

    /// Returns the optional project directory path.
    pub fn project_path_opt(&self) -> Option<&Path> {
        self.project_dir.as_ref().map(|dir| dir.path())
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

    /// Set a fake AI-judge response. A real shell stub will be staged in
    /// the test HOME and the `ai-judge.yaml` pointer will reference it.
    pub fn with_fake_ai_judge_response(mut self, response: &str) -> Self {
        self.fake_ai_judge_response = Some(response.to_string());
        self
    }

    /// Build the test environment, creating temp dirs and writing config files.
    pub fn build(self) -> TestEnv {
        let home_dir = tempfile::TempDir::new().expect("Failed to create temp HOME dir");

        let config_dir = home_dir.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        if let Some(ref response) = self.fake_ai_judge_response {
            // Stage a real shell stub that prints the configured response
            // and exits 0. The longline AI judge parser then reads it as
            // the model's verdict.
            let script_path = home_dir.path().join("fake-ai-judge.sh");
            let script = format!(
                "#!/bin/sh\nprintf '%s\\n' '{}'\n",
                response.replace('\'', "'\\''")
            );
            std::fs::write(&script_path, script).unwrap();
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
            std::fs::write(
                config_dir.join("ai-judge.yaml"),
                format!("command: {}\ntimeout: 10\n", script_path.display()),
            )
            .unwrap();
        } else {
            std::fs::write(
                config_dir.join("ai-judge.yaml"),
                "command: /definitely-not-a-real-ai-judge-command-12345\ntimeout: 1\n",
            )
            .unwrap();
        }

        if let Some(ref yaml) = self.global_config {
            std::fs::write(config_dir.join("longline.yaml"), yaml).unwrap();
        }

        let project_dir = if let Some(ref yaml) = self.project_config {
            let dir = tempfile::TempDir::new().expect("Failed to create temp project dir");
            std::fs::create_dir_all(dir.path().join(".git")).unwrap();
            let config_dir = dir.path().join(".claude");
            std::fs::create_dir_all(&config_dir).unwrap();
            std::fs::write(config_dir.join("longline.yaml"), yaml).unwrap();
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
