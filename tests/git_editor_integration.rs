mod support;

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use longline::domain::{Decision, PolicyResult};

fn evaluate_policy(command: &str) -> PolicyResult {
    let rules_path = support::paths::rules_path();
    let config = longline::policy::load_rules(Path::new(&rules_path))
        .unwrap_or_else(|error| panic!("failed to load rules: {error}"));
    let statement = longline::parser::parse(command)
        .unwrap_or_else(|error| panic!("failed to parse {command:?}: {error}"));
    longline::policy::evaluate(&config, &statement)
}

struct GitFixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    xdg_config_home: PathBuf,
    sentinel: PathBuf,
    sentinel_marker: PathBuf,
    path: OsString,
}

impl GitFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("create fixture directory");
        let repo = temp.path().join("repo");
        let home = temp.path().join("home");
        let xdg_config_home = temp.path().join("xdg");
        fs::create_dir_all(&repo).expect("create repository directory");
        fs::create_dir_all(&home).expect("create temporary HOME");
        fs::create_dir_all(&xdg_config_home).expect("create temporary XDG_CONFIG_HOME");

        let sentinel = temp.path().join("failing-editor");
        let sentinel_marker = temp.path().join("failing-editor.invoked");
        fs::write(&sentinel, "#!/bin/sh\n: > \"$0.invoked\"\nexit 97\n")
            .expect("write editor sentinel");
        let mut permissions = fs::metadata(&sentinel)
            .expect("stat editor sentinel")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&sentinel, permissions).expect("make editor sentinel executable");

        let fixture = Self {
            _temp: temp,
            repo,
            home,
            xdg_config_home,
            sentinel,
            sentinel_marker,
            path: std::env::var_os("PATH").expect("test process PATH must be set"),
        };
        fixture.assert_git_success(
            fixture.git(&["init", "--quiet", "--initial-branch=main"], &[]),
            "initialize repository",
        );
        fixture
    }

    fn git(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut command = Command::new("git");
        command
            .args(args)
            .current_dir(&self.repo)
            .env_clear()
            .env("PATH", &self.path)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg_config_home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "Longline Test Author")
            .env("GIT_AUTHOR_EMAIL", "author@longline.invalid")
            .env("GIT_COMMITTER_NAME", "Longline Test Committer")
            .env("GIT_COMMITTER_EMAIL", "committer@longline.invalid")
            .env("GIT_AUTHOR_DATE", "2001-01-01T00:00:00+0000")
            .env("GIT_COMMITTER_DATE", "2001-01-01T00:00:00+0000")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in extra_env {
            command.env(name, value);
        }
        command
            .output()
            .unwrap_or_else(|error| panic!("failed to run git {args:?}: {error}"))
    }

    fn assert_git_success(&self, output: Output, operation: &str) {
        assert!(
            output.status.success(),
            "{operation} failed with status {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn commit_file(&self, contents: &str, message: &str) {
        fs::write(self.repo.join("shared.txt"), contents).expect("write shared.txt");
        self.assert_git_success(self.git(&["add", "shared.txt"], &[]), "stage shared.txt");
        self.assert_git_success(
            self.git(&["commit", "--quiet", "-m", message], &[]),
            "commit shared.txt",
        );
    }

    fn configure_editor(&self, key: &str) {
        let sentinel = self.sentinel.to_string_lossy();
        self.assert_git_success(
            self.git(&["config", key, sentinel.as_ref()], &[]),
            "configure failing editor sentinel",
        );
    }

    fn sentinel_invoked(&self) -> bool {
        self.sentinel_marker.exists()
    }

    fn assert_no_rebase_state(&self) {
        for state_dir in ["rebase-merge", "rebase-apply"] {
            assert!(
                !self.repo.join(".git").join(state_dir).exists(),
                "unexpected {state_dir} state after successful rebase"
            );
        }
    }

    fn rev_list_count(&self, revision: &str) -> usize {
        let output = self.git(&["rev-list", "--count", revision], &[]);
        self.assert_git_success(output.clone(), "count commits");
        String::from_utf8(output.stdout)
            .expect("rev-list output is UTF-8")
            .trim()
            .parse()
            .expect("rev-list count is numeric")
    }

    fn assert_clean(&self) {
        let output = self.git(&["status", "--porcelain"], &[]);
        self.assert_git_success(output.clone(), "inspect worktree status");
        assert!(
            output.stdout.is_empty(),
            "worktree is not clean: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

struct ConflictRebaseFixture {
    git: GitFixture,
}

impl ConflictRebaseFixture {
    fn new() -> Self {
        let git = GitFixture::new();
        git.commit_file("base\n", "base");
        git.assert_git_success(
            git.git(&["switch", "--quiet", "-c", "topic"], &[]),
            "create topic",
        );
        git.commit_file("topic\n", "topic change");
        git.assert_git_success(
            git.git(&["switch", "--quiet", "main"], &[]),
            "switch to main",
        );
        git.commit_file("main\n", "main change");
        git.assert_git_success(
            git.git(&["switch", "--quiet", "topic"], &[]),
            "switch to topic",
        );

        let conflict = git.git(&["rebase", "main"], &[]);
        assert!(
            !conflict.status.success(),
            "fixture rebase must stop on a conflict"
        );
        fs::write(git.repo.join("shared.txt"), "resolved\n").expect("resolve conflict");
        git.assert_git_success(
            git.git(&["add", "shared.txt"], &[]),
            "stage conflict resolution",
        );
        git.configure_editor("core.editor");
        Self { git }
    }

    fn continue_rebase(&self, extra_env: &[(&str, &str)]) -> Output {
        self.git.git(&["rebase", "--continue"], extra_env)
    }

    fn continue_rebase_with_args(&self, args: &[&str]) -> Output {
        self.git.git(args, &[])
    }

    fn sentinel_invoked(&self) -> bool {
        self.git.sentinel_invoked()
    }

    fn assert_completed_without_sentinel(&self) {
        assert!(
            !self.sentinel_invoked(),
            "safe override unexpectedly invoked the configured editor sentinel"
        );
        self.git.assert_no_rebase_state();
        self.git.assert_clean();
        assert_eq!(self.git.rev_list_count("HEAD"), 3);
        assert_eq!(self.git.rev_list_count("main..HEAD"), 1);
        self.git.assert_git_success(
            self.git
                .git(&["merge-base", "--is-ancestor", "main", "HEAD"], &[]),
            "verify rebased topic descends from main",
        );
    }
}

struct SequenceRebaseFixture {
    git: GitFixture,
}

impl SequenceRebaseFixture {
    fn new() -> Self {
        let git = GitFixture::new();
        git.commit_file("one\n", "one");
        git.commit_file("two\n", "two");
        git.commit_file("three\n", "three");
        git.configure_editor("sequence.editor");
        Self { git }
    }

    fn interactive_rebase(&self, extra_env: &[(&str, &str)]) -> Output {
        self.git.git(&["rebase", "-i", "HEAD~2"], extra_env)
    }

    fn interactive_rebase_with_args(&self, args: &[&str]) -> Output {
        self.git.git(args, &[])
    }

    fn sentinel_invoked(&self) -> bool {
        self.git.sentinel_invoked()
    }

    fn assert_completed_without_sentinel(&self) {
        assert!(
            !self.sentinel_invoked(),
            "safe override unexpectedly invoked the sequence editor sentinel"
        );
        self.git.assert_no_rebase_state();
        self.git.assert_clean();
        assert_eq!(self.git.rev_list_count("HEAD"), 3);
        assert_eq!(self.git.rev_list_count("HEAD~2..HEAD"), 2);
    }
}

#[test]
fn accepted_editor_override_rebases_remain_ask_gated() {
    let commands = [
        "GIT_EDITOR=true git rebase --continue",
        "git -c core.editor=true rebase --continue",
        "GIT_SEQUENCE_EDITOR=true git rebase -i HEAD~2",
        "git -c sequence.editor=true rebase -i HEAD~2",
    ];

    for command in commands {
        let result = evaluate_policy(command);
        assert_eq!(result.decision, Decision::Ask, "command: {command}");
        assert_eq!(result.rule_id.as_deref(), Some("git-rebase"), "{command}");
    }
}

#[test]
fn malformed_editor_override_rebases_remain_fail_closed_without_execution() {
    let denied = [
        "git -c core.editor rebase --continue",
        "git -c sequence.editor rebase -i HEAD~2",
    ];
    for command in denied {
        let result = evaluate_policy(command);
        assert_eq!(result.decision, Decision::Deny, "command: {command}");
        assert_eq!(
            result.rule_id.as_deref(),
            Some("git-c-editor-program"),
            "command: {command}"
        );
    }

    let invalid_joined = [
        "git -ccore.editor=true rebase --continue",
        "git -csequence.editor=true rebase -i HEAD~2",
    ];
    for command in invalid_joined {
        let result = evaluate_policy(command);
        assert_eq!(result.decision, Decision::Ask, "command: {command}");
    }
}

#[test]
fn safe_commit_editor_overrides_complete_conflict_rebase_without_sentinel() {
    let control = ConflictRebaseFixture::new();
    let result = control.continue_rebase(&[]);
    assert!(!result.status.success(), "control unexpectedly succeeded");
    assert!(
        control.sentinel_invoked(),
        "control did not invoke sentinel"
    );

    let env_override = ConflictRebaseFixture::new();
    let result = env_override.continue_rebase(&[("GIT_EDITOR", "true")]);
    assert!(
        result.status.success(),
        "GIT_EDITOR=true continuation failed"
    );
    env_override.assert_completed_without_sentinel();

    let config_override = ConflictRebaseFixture::new();
    let result = config_override.continue_rebase_with_args(&[
        "-c",
        "core.editor=true",
        "rebase",
        "--continue",
    ]);
    assert!(
        result.status.success(),
        "core.editor=true continuation failed"
    );
    config_override.assert_completed_without_sentinel();
}

#[test]
fn safe_sequence_editor_overrides_complete_interactive_rebase_without_sentinel() {
    let control = SequenceRebaseFixture::new();
    let result = control.interactive_rebase(&[]);
    assert!(!result.status.success(), "control unexpectedly succeeded");
    assert!(
        control.sentinel_invoked(),
        "control did not invoke sentinel"
    );

    let env_override = SequenceRebaseFixture::new();
    let result = env_override.interactive_rebase(&[("GIT_SEQUENCE_EDITOR", "true")]);
    assert!(
        result.status.success(),
        "GIT_SEQUENCE_EDITOR=true interactive rebase failed"
    );
    env_override.assert_completed_without_sentinel();

    let config_override = SequenceRebaseFixture::new();
    let result = config_override.interactive_rebase_with_args(&[
        "-c",
        "sequence.editor=true",
        "rebase",
        "-i",
        "HEAD~2",
    ]);
    assert!(
        result.status.success(),
        "sequence.editor=true interactive rebase failed"
    );
    config_override.assert_completed_without_sentinel();
}
