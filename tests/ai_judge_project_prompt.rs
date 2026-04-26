//! End-to-end tests for per-repo ai_judge.prompt override.
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

fn make_project(ai_judge_prompt: Option<&str>) -> (tempfile::TempDir, std::path::PathBuf) {
    let td = tempfile::tempdir().unwrap();
    let repo = td.path().to_path_buf();
    fs::create_dir(repo.join(".git")).unwrap();
    fs::create_dir(repo.join(".claude")).unwrap();
    let yaml = match ai_judge_prompt {
        Some(p) => {
            let indented = p
                .lines()
                .map(|l| format!("    {l}"))
                .collect::<Vec<_>>()
                .join("\n");
            format!("ai_judge:\n  prompt: |\n{indented}\n")
        }
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
fn test_path_a_uses_project_prompt_verbatim_and_omits_builtin_text() {
    let user_prompt = "PROJECT-PROMPT-MARKER {language} {code} {cwd}";
    let (repo_td, repo) = make_project(Some(user_prompt));
    let home_td = tempfile::tempdir().unwrap();
    let capture = home_td.path().join("captured-prompt.txt");
    setup_fake_judge(home_td.path(), &capture);

    let output = run_longline_hook(&repo, home_td.path(), r#"python -c "print(1)""#);
    let _hold = (&repo_td, &home_td);
    assert!(
        output.status.success(),
        "longline failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let captured = fs::read_to_string(&capture).expect("fake judge should write capture");
    assert!(
        captured.contains("PROJECT-PROMPT-MARKER python print(1)"),
        "captured prompt missing project marker / substituted placeholders. got: {captured}"
    );
    assert!(
        captured.contains("Respond with EXACTLY one line"),
        "captured prompt missing response-format suffix. got: {captured}"
    );
    assert!(
        !captured.contains("Mode: lenient"),
        "captured prompt should not contain built-in lenient text. got: {captured}"
    );
    assert!(
        !captured.contains("Security evaluation"),
        "captured prompt should not contain built-in template header. got: {captured}"
    );
}

#[test]
fn test_path_a_single_pass_substitution_preserves_code_with_cwd_token() {
    // Regression: chained `.replace()` substitution would replace {cwd} inside
    // the {code} value. Single-pass must preserve it.
    let user_prompt = "Lang: {language}\nCode:\n{code}\nCwd: {cwd}";
    let (repo_td, repo) = make_project(Some(user_prompt));
    let home_td = tempfile::tempdir().unwrap();
    let capture = home_td.path().join("captured-prompt.txt");
    setup_fake_judge(home_td.path(), &capture);

    let output = run_longline_hook(&repo, home_td.path(), r#"python -c "print('{cwd}')""#);
    let _hold = (&repo_td, &home_td);
    assert!(
        output.status.success(),
        "longline failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let captured = fs::read_to_string(&capture).expect("fake judge should write capture");
    // Code value contains literal `{cwd}` — must survive substitution.
    assert!(
        captured.contains("print('{cwd}')"),
        "code value's literal {{cwd}} was incorrectly re-substituted. got: {captured}"
    );
    // The standalone {cwd} placeholder in the user prompt's "Cwd:" line is
    // substituted with the actual cwd from the hook input — assert that
    // line is NOT the literal `Cwd: {cwd}` after substitution.
    let cwd_line = captured
        .lines()
        .find(|l| l.starts_with("Cwd: "))
        .expect("Cwd: line");
    assert!(
        cwd_line != "Cwd: {cwd}",
        "Cwd: line should have the substituted path, not literal {{cwd}}. got: {cwd_line}"
    );
}

#[test]
fn test_global_config_rejects_ai_judge_prompt() {
    // Set up a temp HOME with a global config that includes ai_judge.prompt.
    // The longline binary should exit with code 2 and a precise error to stderr.
    let home_td = tempfile::tempdir().unwrap();
    let global_dir = home_td.path().join(".config").join("longline");
    fs::create_dir_all(&global_dir).unwrap();
    fs::write(
        global_dir.join("longline.yaml"),
        "ai_judge:\n  prompt: |\n    {language} {code} {cwd}\n",
    )
    .unwrap();

    let (repo_td, repo) = make_project(None); // no project config

    let output = run_longline_hook(&repo, home_td.path(), "ls");
    let _hold = (&repo_td, &home_td);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2, got {:?}, stderr: {stderr}",
        output.status.code()
    );
    assert!(
        stderr.contains("ai_judge.prompt is not allowed in global config"),
        "missing rejection error. stderr: {stderr}"
    );
}
