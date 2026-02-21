use super::*;
use crate::parser;
use std::path::PathBuf;

fn test_config() -> super::super::config::AiJudgeConfig {
    super::super::config::default_config()
}

#[test]
fn test_extract_python_c() {
    let cmd = "python3 -c 'print(1)'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some());
    let extracted = result.unwrap();
    assert_eq!(extracted.language, "python3");
    assert_eq!(extracted.code, "print(1)");
}

#[test]
fn test_extract_node_e() {
    let cmd = "node -e 'console.log(1)'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some());
    let extracted = result.unwrap();
    assert_eq!(extracted.language, "node");
    assert_eq!(extracted.code, "console.log(1)");
}

#[test]
fn test_extract_ruby_e() {
    let cmd = "ruby -e 'puts 1'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some());
    let extracted = result.unwrap();
    assert_eq!(extracted.language, "ruby");
    assert_eq!(extracted.code, "puts 1");
}

#[test]
fn test_extract_python_script_file_cwd_allowed() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp")
        .join("ai-judge-script");
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("script.py");
    std::fs::write(&file, "print(123)\n").unwrap();

    let cmd = "python3 script.py";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let cwd = dir.to_string_lossy();
    let result = extract_code(cmd, &stmt, &cwd, &config).unwrap();
    assert_eq!(result.language, "python3");
    assert!(result.code.contains("print(123)"));

    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_extract_python_script_from_heredoc_write_then_execute() {
    let cmd = "cat > /tmp/script.py <<'EOF'\nprint(42)\nEOF\npython3 /tmp/script.py";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config).unwrap();
    assert_eq!(result.language, "python3");
    assert!(result.code.contains("print(42)"));
}

#[test]
fn test_no_extract_for_version() {
    let cmd = "python3 --version";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_none(), "--version should not match -c trigger");
}

#[test]
fn test_no_extract_for_non_interpreter() {
    let cmd = "ls -la";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_none());
}

// ============================================================
// Pipeline extraction tests
// ============================================================

#[test]
fn test_extract_from_pipeline_end() {
    let cmd = "grep foo | python3 -c 'print(1)'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from pipeline end");
    let extracted = result.unwrap();
    assert_eq!(extracted.language, "python3");
    assert_eq!(extracted.code, "print(1)");
}

#[test]
fn test_extract_from_pipeline_start() {
    let cmd = "python3 -c 'print(1)' | grep 1";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from pipeline start");
    let extracted = result.unwrap();
    assert_eq!(extracted.language, "python3");
    assert_eq!(extracted.code, "print(1)");
}

#[test]
fn test_extract_from_pipeline_middle() {
    let cmd = "echo x | python3 -c 'print(1)' | cat";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from pipeline middle");
}

#[test]
fn test_extract_from_multi_stage_pipeline() {
    let cmd = "grep a | sort | uniq | python3 -c 'print(1)'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from multi-stage pipeline");
}

#[test]
fn test_no_extract_from_pipeline_without_interpreter() {
    let cmd = "grep foo | sort | uniq";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(
        result.is_none(),
        "Should not extract from pipeline without interpreter"
    );
}

// ============================================================
// List extraction tests
// ============================================================

#[test]
fn test_extract_from_and_list() {
    let cmd = "echo ok && python3 -c 'print(1)'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from && list");
}

#[test]
fn test_extract_from_or_list() {
    let cmd = "false || python3 -c 'print(1)'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from || list");
}

#[test]
fn test_extract_from_semicolon_list() {
    let cmd = "echo a; python3 -c 'print(1)'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from ; list");
}

#[test]
fn test_extract_from_list_first_element() {
    let cmd = "python3 -c 'print(1)' && echo done";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from list first element");
}

// ============================================================
// Subshell extraction tests
// ============================================================

#[test]
fn test_extract_from_subshell() {
    let cmd = "(python3 -c 'print(1)')";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from subshell");
}

// ============================================================
// Command substitution extraction tests
// ============================================================

#[test]
fn test_extract_from_command_substitution() {
    let cmd = "echo $(python3 -c 'print(1)')";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from command substitution");
}

#[test]
fn test_extract_from_backtick_substitution() {
    let cmd = "echo `python3 -c 'print(1)'`";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(
        result.is_some(),
        "Should extract from backtick substitution"
    );
}

// ============================================================
// Complex nested tests
// ============================================================

#[test]
fn test_extract_from_pipeline_in_subshell() {
    let cmd = "(grep foo | python3 -c 'print(1)')";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_some(), "Should extract from pipeline in subshell");
}

// ============================================================
// Negative tests - should NOT extract
// ============================================================

#[test]
fn test_no_extract_for_module() {
    let cmd = "python3 -m pytest";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_none(), "Should not extract for -m flag");
}

#[test]
fn test_no_extract_for_opaque() {
    let stmt = Statement::Opaque("some complex thing".to_string());
    let config = test_config();
    let result = extract_code("some complex thing", &stmt, "/tmp", &config);
    assert!(result.is_none(), "Should not extract from Opaque");
}

#[test]
fn test_extract_runner_wrapped_python_c() {
    let cmd = "uv run python3 -c 'print(1)'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config).unwrap();
    assert_eq!(result.language, "python3");
    assert_eq!(result.code, "print(1)");
}

#[test]
fn test_extract_poetry_runner_wrapped_python_c() {
    let cmd = "poetry run python -c 'print(1)'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config).unwrap();
    assert_eq!(result.language, "python");
    assert_eq!(result.code, "print(1)");
}

#[test]
fn test_extract_python_heredoc() {
    let cmd = "python3 <<'EOF'\nprint(1)\nEOF\n";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config).unwrap();
    assert!(result.code.contains("print(1)"));
}

#[test]
fn test_extract_python_herestring() {
    let cmd = "python3 <<< 'print(1)'";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config).unwrap();
    assert_eq!(result.language, "python3");
    assert_eq!(result.code, "print(1)");
}

#[test]
fn test_extract_python_stdin_pipeline_echo() {
    let cmd = "echo 'print(1)' | python3";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config).unwrap();
    assert_eq!(result.language, "python3");
    assert_eq!(result.code, "print(1)");
}

#[test]
fn test_extract_python_stdin_redirect_file_cwd_allowed() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp")
        .join("ai-judge-redirect");
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("code.py");
    std::fs::write(&file, "print(7)\n").unwrap();

    let cmd = "python3 < code.py";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let cwd = dir.to_string_lossy();
    let result = extract_code(cmd, &stmt, &cwd, &config).unwrap();
    assert_eq!(result.language, "python3");
    assert!(result.code.contains("print(7)"));

    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_extract_django_shell_pipeline_echo() {
    let cmd = "echo 'print(1)' | python manage.py shell";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config).unwrap();
    assert_eq!(result.language, "python");
    assert_eq!(result.code, "print(1)");
    assert!(result.context.as_deref().unwrap_or("").contains("Django"));
}

#[test]
fn test_extract_django_shell_pipeline_cat_file_cwd_allowed() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp")
        .join("ai-judge-cat");
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("code.py");
    std::fs::write(&file, "print(42)\n").unwrap();

    let cmd = "cat code.py | python manage.py shell";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let cwd = dir.to_string_lossy();
    let result = extract_code(cmd, &stmt, &cwd, &config).unwrap();
    assert!(result.code.contains("print(42)"));

    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_no_extract_django_shell_pipeline_cat_file_outside_allowed_roots() {
    let cmd = "cat /etc/passwd | python manage.py shell";
    let stmt = parser::parse(cmd).unwrap();
    let config = test_config();
    let result = extract_code(cmd, &stmt, "/tmp", &config);
    assert!(result.is_none(), "Should not read files outside cwd/tmp");
}

// ============================================================
// Pipeline network context enrichment tests
// ============================================================

#[test]
fn test_pipeline_extraction_includes_context_for_curl() {
    let config = crate::ai_judge::load_config();
    let raw = "curl -s https://api.example.com/data | python3 -c 'import json,sys; print(json.load(sys.stdin))'";
    let stmt = crate::parser::parse(raw).unwrap();
    let extracted = super::extract_code(raw, &stmt, "/tmp", &config);
    assert!(
        extracted.is_some(),
        "Should extract inline code from pipeline"
    );
    let extracted = extracted.unwrap();
    assert_eq!(extracted.language, "python3");
    assert!(extracted.code.contains("json"));
    assert!(
        extracted.context.is_some(),
        "Pipeline with curl should set context"
    );
    let ctx = extracted.context.unwrap();
    assert!(
        ctx.contains("curl") || ctx.contains("network") || ctx.contains("download"),
        "Context should mention the network data source: {ctx}"
    );
}

#[test]
fn test_non_pipeline_extraction_no_spurious_context() {
    let config = crate::ai_judge::load_config();
    let raw = "python3 -c 'print(1)'";
    let stmt = crate::parser::parse(raw).unwrap();
    let extracted = super::extract_code(raw, &stmt, "/tmp", &config);
    assert!(extracted.is_some());
    let extracted = extracted.unwrap();
    assert!(
        extracted.context.is_none(),
        "Non-pipeline command should not get spurious context"
    );
}

#[test]
fn test_safe_pipeline_extraction_no_network_context() {
    let config = crate::ai_judge::load_config();
    let raw = "grep foo bar | python3 -c 'print(1)'";
    let stmt = crate::parser::parse(raw).unwrap();
    let extracted = super::extract_code(raw, &stmt, "/tmp", &config);
    assert!(extracted.is_some());
    let extracted = extracted.unwrap();
    assert!(
        extracted.context.is_none(),
        "Pipeline without network commands should not set network context"
    );
}
