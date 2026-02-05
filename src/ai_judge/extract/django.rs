use crate::parser::Statement;

use super::super::config::AiJudgeConfig;
use super::fs::read_safe_code_file;
use super::utils::{
    extract_echo_output, extract_printf_output, extract_single_cat_path,
    tokens_from_simple_command, unwrap_runner_chain,
};
use super::{ExtractedCode, MAX_EXTRACTED_CODE_BYTES};

pub(super) fn extract_from_django_shell_pipeline(
    stmt: &Statement,
    cwd: &str,
    config: &AiJudgeConfig,
) -> Option<ExtractedCode> {
    match stmt {
        Statement::Pipeline(pipeline) => {
            for i in 0..pipeline.stages.len() {
                let stage = pipeline.stages.get(i)?;
                let Statement::SimpleCommand(consumer_cmd) = stage else {
                    continue;
                };

                if i == 0 {
                    continue;
                }

                let consumer_tokens = tokens_from_simple_command(consumer_cmd)?;
                let consumer_unwrapped =
                    unwrap_runner_chain(&consumer_tokens, &config.triggers.runners);

                if !is_django_shell_consumer(&consumer_unwrapped) {
                    continue;
                }
                if has_django_shell_inline_flag(&consumer_unwrapped) {
                    continue;
                }

                let prev_stage = pipeline.stages.get(i - 1)?;
                let Statement::SimpleCommand(source_cmd) = prev_stage else {
                    continue;
                };

                let source_tokens = tokens_from_simple_command(source_cmd)?;
                let source_name = source_tokens.first()?.as_str();
                let source_argv = &source_tokens[1..];

                if source_name == "echo" {
                    let code = extract_echo_output(source_argv)?;
                    if code.len() > MAX_EXTRACTED_CODE_BYTES {
                        return None;
                    }
                    return Some(ExtractedCode {
                        language: "python".to_string(),
                        code,
                        context: Some(django_context("stdin from echo".to_string())),
                    });
                }

                if source_name == "printf" {
                    let code = extract_printf_output(source_argv)?;
                    if code.len() > MAX_EXTRACTED_CODE_BYTES {
                        return None;
                    }
                    return Some(ExtractedCode {
                        language: "python".to_string(),
                        code,
                        context: Some(django_context("stdin from printf".to_string())),
                    });
                }

                if source_name == "cat" {
                    let path = extract_single_cat_path(source_argv)?;
                    let code = read_safe_code_file(&path, cwd)?;
                    return Some(ExtractedCode {
                        language: "python".to_string(),
                        code,
                        context: Some(django_context(format!("stdin from cat {}", path))),
                    });
                }
            }
            None
        }
        Statement::List(list) => {
            if let Some(extracted) = extract_from_django_shell_pipeline(&list.first, cwd, config) {
                return Some(extracted);
            }
            for (_, stmt) in &list.rest {
                if let Some(extracted) = extract_from_django_shell_pipeline(stmt, cwd, config) {
                    return Some(extracted);
                }
            }
            None
        }
        Statement::Subshell(inner) | Statement::CommandSubstitution(inner) => {
            extract_from_django_shell_pipeline(inner, cwd, config)
        }
        Statement::SimpleCommand(cmd) => {
            for sub in &cmd.embedded_substitutions {
                if let Some(extracted) = extract_from_django_shell_pipeline(sub, cwd, config) {
                    return Some(extracted);
                }
            }
            None
        }
        Statement::Opaque(_) | Statement::Empty => None,
    }
}

pub(super) fn is_manage_py_path(arg: &str) -> bool {
    if arg == "manage.py" {
        return true;
    }
    let p = std::path::Path::new(arg);
    p.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s == "manage.py")
        .unwrap_or(false)
}

pub(super) fn is_django_shell_consumer(tokens: &[String]) -> bool {
    let manage_pos = tokens.iter().position(|t| is_manage_py_path(t));
    let Some(manage_pos) = manage_pos else {
        return false;
    };
    let shell_pos = manage_pos + 1;
    let Some(shell_cmd) = tokens.get(shell_pos) else {
        return false;
    };
    shell_cmd == "shell" || shell_cmd == "shell_plus"
}

fn has_django_shell_inline_flag(tokens: &[String]) -> bool {
    let manage_pos = tokens.iter().position(|t| is_manage_py_path(t));
    let Some(manage_pos) = manage_pos else {
        return false;
    };
    let shell_pos = manage_pos + 1;
    if shell_pos >= tokens.len() {
        return false;
    }
    if tokens.get(shell_pos).map(|s| s.as_str()) != Some("shell")
        && tokens.get(shell_pos).map(|s| s.as_str()) != Some("shell_plus")
    {
        return false;
    }
    for tok in tokens.iter().skip(shell_pos + 1) {
        if tok == "-c" || tok == "--command" || tok.starts_with("--command=") {
            return true;
        }
    }
    false
}

pub(super) fn django_context(code_source: String) -> String {
    format!(
        "Execution context: Django manage.py shell (can access the database and Django settings). Code source: {code_source}. Guidance: ALLOW only read-only ORM queries/printing; ASK on any data writes/deletes/migrations, secrets, network, or subprocess execution."
    )
}
