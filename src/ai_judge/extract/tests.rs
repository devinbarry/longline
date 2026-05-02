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

// ============================================================
// Shell-c composition tests (Change C)
// ============================================================

#[test]
fn extract_code_finds_inner_python_c_via_shell_c_unwrap() {
    // bash -c "python -c 'print(1)'" — the inner python -c lives in
    // extract_inner_commands output. Change C (CLI composition) iterates
    // extras through extract_code.
    use crate::parser::wrappers;
    let command = "bash -c \"python -c 'print(1)'\"";
    let stmt = parser::parse(command).unwrap();
    let config = test_config();
    // Primary: no python -c on the outer bash stmt (it's inside the string).
    assert!(extract_code(command, &stmt, "/tmp", &config).is_none());
    // Composition: scan extra_stmts.
    let extras = wrappers::extract_inner_commands(&stmt);
    let extracted = extras
        .iter()
        .find_map(|s| extract_code(command, s, "/tmp", &config));
    let ec = extracted.expect("inner python -c must be extracted");
    assert_eq!(ec.language, "python");
    assert_eq!(ec.code.trim(), "print(1)");
}

#[test]
fn extract_code_does_not_spuriously_extract_from_unsafe_shell_c() {
    // bash -c "python -c \"$VAR\"" — outer arg is UnsafeString (has $VAR).
    // shell-c refuses re-parse; extras contains Opaque, not a python -c
    // SimpleCommand. Composition must NOT falsely extract.
    use crate::parser::wrappers;
    let command = "bash -c \"python -c \\\"$VAR\\\"\"";
    let stmt = parser::parse(command).unwrap();
    let config = test_config();
    assert!(extract_code(command, &stmt, "/tmp", &config).is_none());
    let extras = wrappers::extract_inner_commands(&stmt);
    let extracted = extras
        .iter()
        .find_map(|s| extract_code(command, s, "/tmp", &config));
    assert!(extracted.is_none());
}

// ============================================================
// `python -m foo.bar` module resolution (spec 2026-05-02)
// ============================================================
//
// Each test stages its own fixture directory under
// `target/test-tmp/ai-judge-module/<unique>/` so cargo's parallel
// runner doesn't race. Tests clean up at the end on the success path.

mod module_resolution {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn unique_root(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("ai-judge-module")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &std::path::Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    #[test]
    fn single_segment_module_resolves_to_foo_py() {
        let dir = unique_root("single-segment");
        write(&dir.join("foo.py"), "print('foo')\n");
        let cmd = "python -m foo";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        let result = extract_code(cmd, &stmt, &cwd, &test_config()).unwrap();
        assert_eq!(result.language, "python");
        assert!(result.code.contains("print('foo')"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dotted_module_resolves_to_foo_bar_py() {
        let dir = unique_root("dotted");
        write(&dir.join("foo").join("bar.py"), "print('bar')\n");
        let cmd = "python -m foo.bar";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        let result = extract_code(cmd, &stmt, &cwd, &test_config()).unwrap();
        assert!(result.code.contains("print('bar')"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dotted_module_resolves_to_main_when_only_main_exists() {
        let dir = unique_root("main-only");
        write(
            &dir.join("foo").join("bar").join("__main__.py"),
            "print('main')\n",
        );
        let cmd = "python -m foo.bar";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        let result = extract_code(cmd, &stmt, &cwd, &test_config()).unwrap();
        assert!(result.code.contains("print('main')"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dotted_module_resolves_under_src_layout() {
        let dir = unique_root("src-layout");
        write(
            &dir.join("src").join("foo").join("bar.py"),
            "print('src bar')\n",
        );
        let cmd = "python -m foo.bar";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        let result = extract_code(cmd, &stmt, &cwd, &test_config()).unwrap();
        assert!(result.code.contains("print('src bar')"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dotted_module_resolves_to_main_under_src_layout() {
        let dir = unique_root("src-main");
        write(
            &dir.join("src").join("foo").join("bar").join("__main__.py"),
            "print('src main')\n",
        );
        let cmd = "python -m foo.bar";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        let result = extract_code(cmd, &stmt, &cwd, &test_config()).unwrap();
        assert!(result.code.contains("print('src main')"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_first_when_both_foo_py_and_foo_main_exist() {
        // Documented divergence from Python's loader: file beats package.
        let dir = unique_root("file-first");
        write(&dir.join("foo.py"), "print('the file')\n");
        write(
            &dir.join("foo").join("__main__.py"),
            "print('the package')\n",
        );
        let cmd = "python -m foo";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        let result = extract_code(cmd, &stmt, &cwd, &test_config()).unwrap();
        assert!(result.code.contains("the file"));
        assert!(!result.code.contains("the package"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_log_case_tests_fixtures_fake_codex_server() {
        let dir = unique_root("log-case");
        write(
            &dir.join("tests")
                .join("fixtures")
                .join("fake_codex_server.py"),
            "# fake server stub\nimport sys\nsys.exit(0)\n",
        );
        let cmd = "python3 -m tests.fixtures.fake_codex_server";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        let result = extract_code(cmd, &stmt, &cwd, &test_config()).unwrap();
        assert_eq!(result.language, "python3");
        assert!(result.code.contains("fake server stub"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn runner_wrapped_uv_run_python_m() {
        let dir = unique_root("uv-wrapped");
        write(&dir.join("tests").join("foo.py"), "print('uv wrap')\n");
        let cmd = "uv run python -m tests.foo";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        let result = extract_code(cmd, &stmt, &cwd, &test_config()).unwrap();
        assert!(result.code.contains("uv wrap"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipeline_with_python_m_at_end() {
        let dir = unique_root("pipeline");
        write(&dir.join("tests").join("foo.py"), "print('pipe')\n");
        let cmd = "echo x | python -m tests.foo";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        let result = extract_code(cmd, &stmt, &cwd, &test_config()).unwrap();
        assert!(result.code.contains("pipe"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_dunder_main_in_dotted_path_resolves_via_main_candidate() {
        // `python -m tests.fixtures.fake_codex_server.__main__` — Python
        // accepts this; we should not crash. Resolution lands on the
        // `<cwd>/tests/fixtures/fake_codex_server/__main__/__main__.py`
        // candidate (file form) or the package-`__main__` form.
        // Build the package layout so the file-form candidate hits.
        let dir = unique_root("explicit-main");
        let path = dir
            .join("tests")
            .join("fixtures")
            .join("fake_codex_server")
            .join("__main__.py");
        write(&path, "print('main path')\n");
        // Resolution order tries `<cwd>/tests/fixtures/fake_codex_server/__main__.py`
        // (segment "__main__" → file `__main__.py`) — same path we wrote.
        let cmd = "python -m tests.fixtures.fake_codex_server.__main__";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        let result = extract_code(cmd, &stmt, &cwd, &test_config()).unwrap();
        assert!(result.code.contains("main path"));
        let _ = fs::remove_dir_all(&dir);
    }

    // ── Negative tests: extraction returns None, judge gives up ──

    #[test]
    fn unknown_module_returns_none() {
        let dir = unique_root("unknown");
        let cmd = "python -m totally.unknown.module";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        assert!(extract_code(cmd, &stmt, &cwd, &test_config()).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn installed_package_pip_returns_none() {
        let dir = unique_root("pip-installed");
        let cmd = "python -m pip install evil";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        assert!(extract_code(cmd, &stmt, &cwd, &test_config()).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_traversal_module_name_rejected() {
        let dir = unique_root("traversal");
        // Slash in module → fails is_valid_module_name regex.
        let cmd = "python -m ../etc/passwd";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        assert!(extract_code(cmd, &stmt, &cwd, &test_config()).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_module_names_rejected() {
        let dir = unique_root("malformed-names");
        let cwd = dir.to_string_lossy();
        let bad = [
            "python -m foo..bar",
            "python -m .foo",
            "python -m foo.",
            "python -m 1foo",
            "python -m foo-bar",
            "python -m \"\"",
        ];
        for cmd in bad {
            let stmt = parser::parse(cmd).unwrap();
            assert!(
                extract_code(cmd, &stmt, &cwd, &test_config()).is_none(),
                "must reject: {cmd}"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dash_m_with_no_following_arg_returns_none() {
        let dir = unique_root("no-arg");
        let cmd = "python -m";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        assert!(extract_code(cmd, &stmt, &cwd, &test_config()).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_module_file_returns_none() {
        // read_safe_code_file caps at 32 KiB. Write 64 KiB and confirm
        // extraction declines (judge falls through to ask).
        let dir = unique_root("oversized");
        let big = "x".repeat(64 * 1024);
        write(&dir.join("big.py"), &big);
        let cmd = "python -m big";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        assert!(extract_code(cmd, &stmt, &cwd, &test_config()).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn module_path_outside_cwd_via_symlink_rejected() {
        // Symlink from inside cwd to outside; canonicalize follows it
        // and read_safe_code_file's confinement check rejects.
        // Skip on platforms where symlinks aren't supported in /tmp.
        let dir = unique_root("symlink-escape");
        let outside = dir.parent().unwrap().join("outside.py");
        fs::write(&outside, "print('outside')\n").unwrap();
        // Now try to symlink dir/foo.py → outside.py.
        let link = dir.join("foo.py");
        if std::os::unix::fs::symlink(&outside, &link).is_err() {
            let _ = fs::remove_file(&outside);
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        let cmd = "python -m foo";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        assert!(extract_code(cmd, &stmt, &cwd, &test_config()).is_none());
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn module_segment_collides_with_existing_file_resolution_falls_through() {
        // `python -m foo.bar` where `<cwd>/foo` exists as a regular file
        // (not a directory). cwd.join("foo").join("bar.py") yields a
        // path that doesn't exist; subsequent candidates also miss.
        let dir = unique_root("file-collision");
        write(&dir.join("foo"), "not a directory\n");
        let cmd = "python -m foo.bar";
        let stmt = parser::parse(cmd).unwrap();
        let cwd = dir.to_string_lossy();
        assert!(extract_code(cmd, &stmt, &cwd, &test_config()).is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
