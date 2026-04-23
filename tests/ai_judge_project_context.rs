//! End-to-end tests for per-repo ai_judge.context.
//!
//! Approach: override ai_judge.command via $HOME/.config/longline/ai-judge.yaml
//! to point at a shell script that writes the prompt argv to a capture file
//! and returns "ALLOW: fake-judge captured prompt". Then assert on the captured
//! text to verify the rendered prompt shape.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

fn longline_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_longline"))
}

fn make_project(ai_judge_context: Option<&str>) -> (tempfile::TempDir, std::path::PathBuf) {
    let td = tempfile::tempdir().unwrap();
    let repo = td.path().to_path_buf();
    fs::create_dir(repo.join(".git")).unwrap();
    fs::create_dir(repo.join(".claude")).unwrap();
    let yaml = match ai_judge_context {
        Some(ctx) => format!("ai_judge:\n  context: |\n    {ctx}\n"),
        None => String::new(),
    };
    fs::write(repo.join(".claude").join("longline.yaml"), yaml).unwrap();
    (td, repo)
}

fn setup_fake_judge(home: &std::path::Path, capture_path: &std::path::Path) {
    let script_path = home.join("fake-judge.sh");
    let script = format!(
        "#!/bin/sh\nprintf '%s' \"$@\" > '{}'\necho 'ALLOW: fake-judge captured prompt'\n",
        capture_path.display()
    );
    fs::write(&script_path, script).unwrap();
    let mut perms = fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).unwrap();

    let config_dir = home.join(".config").join("longline");
    fs::create_dir_all(&config_dir).unwrap();
    let ai_yaml = format!("command: {}\ntimeout: 10\n", script_path.display());
    fs::write(config_dir.join("ai-judge.yaml"), ai_yaml).unwrap();
}

fn run_longline_hook(
    repo: &std::path::Path,
    home: &std::path::Path,
    command: &str,
) -> std::process::Output {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "session_id": "test",
        "cwd": repo.display().to_string(),
    });
    let mut child = Command::new(longline_bin())
        .arg("--ask-ai-lenient")
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn longline");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait")
}

#[test]
fn test_project_context_appears_in_prompt() {
    let home_td = tempfile::tempdir().unwrap();
    let capture = home_td.path().join("captured-prompt.txt");
    setup_fake_judge(home_td.path(), &capture);

    let (repo_td, repo) = make_project(Some(
        "Domain: polymarket analysis. Expected httpx to polymarket.com.",
    ));

    let output = run_longline_hook(
        &repo,
        home_td.path(),
        "uv run python -c 'import json; print(json.dumps({}))'",
    );

    // Keep tempdirs alive until after assertions:
    let _hold = (&home_td, &repo_td);

    assert!(
        output.status.success(),
        "longline exit {}: stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let prompt = fs::read_to_string(&capture).expect("fake judge should have captured the prompt");
    assert!(
        prompt.contains("<project_context_"),
        "prompt should contain project_context wrapper:\n{prompt}"
    );
    assert!(
        prompt.contains("Domain: polymarket analysis."),
        "prompt should contain the user-supplied context:\n{prompt}"
    );
    assert!(
        prompt.contains("secrets or credentials"),
        "prompt should restate the safety floor:\n{prompt}"
    );
}

#[test]
fn test_no_project_context_preserves_current_prompt_shape() {
    let home_td = tempfile::tempdir().unwrap();
    let capture = home_td.path().join("captured-prompt.txt");
    setup_fake_judge(home_td.path(), &capture);

    let (repo_td, repo) = make_project(None);

    let output = run_longline_hook(&repo, home_td.path(), "uv run python -c 'print(1)'");
    let _hold = (&home_td, &repo_td);
    assert!(output.status.success());

    let prompt = fs::read_to_string(&capture).expect("prompt captured");
    assert!(
        !prompt.contains("<project_context_"),
        "prompt should NOT contain project_context wrapper without ai_judge.context:\n{prompt}"
    );
}
