use crate::parser::Statement;

use super::super::config::AiJudgeConfig;
use super::django::{django_context, is_manage_py_path};
use super::utils::{command_name_matches, tokens_from_simple_command, unwrap_runner_chain};
use super::{ExtractedCode, MAX_EXTRACTED_CODE_BYTES};

pub(super) fn extract_inline_code_from_stmt(
    stmt: &Statement,
    config: &AiJudgeConfig,
) -> Option<ExtractedCode> {
    match stmt {
        Statement::SimpleCommand(cmd) => {
            for sub in &cmd.embedded_substitutions {
                if let Some(result) = extract_inline_code_from_stmt(sub, config) {
                    return Some(result);
                }
            }
            extract_from_simple_command(cmd, config)
        }
        Statement::Pipeline(pipeline) => {
            for stage in &pipeline.stages {
                if let Some(result) = extract_inline_code_from_stmt(stage, config) {
                    return Some(result);
                }
            }
            None
        }
        Statement::List(list) => {
            if let Some(result) = extract_inline_code_from_stmt(&list.first, config) {
                return Some(result);
            }
            for (_, stmt) in &list.rest {
                if let Some(result) = extract_inline_code_from_stmt(stmt, config) {
                    return Some(result);
                }
            }
            None
        }
        Statement::Subshell(inner) | Statement::CommandSubstitution(inner) => {
            extract_inline_code_from_stmt(inner, config)
        }
        Statement::Opaque(_) => None,
    }
}

fn extract_from_simple_command(
    cmd: &crate::parser::SimpleCommand,
    config: &AiJudgeConfig,
) -> Option<ExtractedCode> {
    let tokens = tokens_from_simple_command(cmd)?;
    let unwrapped = unwrap_runner_chain(&tokens, &config.triggers.runners);

    // Prefer Django shell inline flags to avoid misclassifying `manage.py shell -c` as `python -c`.
    if let Some(extracted) = extract_django_shell_inline(&unwrapped) {
        return Some(extracted);
    }

    extract_interpreter_inline(&unwrapped, config)
}

fn extract_interpreter_inline(tokens: &[String], config: &AiJudgeConfig) -> Option<ExtractedCode> {
    let cmd_name = tokens.first()?;
    let argv = &tokens[1..];

    for trigger in &config.triggers.interpreters {
        if !trigger
            .name
            .iter()
            .any(|n| command_name_matches(n, cmd_name))
        {
            continue;
        }

        let flag_pos = argv.iter().position(|a| a == &trigger.inline_flag)?;
        let code = argv.get(flag_pos + 1)?;
        if code.len() > MAX_EXTRACTED_CODE_BYTES {
            return None;
        }
        return Some(ExtractedCode {
            language: cmd_name.to_string(),
            code: code.clone(),
            context: None,
        });
    }

    None
}

fn extract_django_shell_inline(tokens: &[String]) -> Option<ExtractedCode> {
    // python manage.py shell -c "..."
    // python manage.py shell --command "..."
    // python manage.py shell --command="..."
    let manage_pos = tokens.iter().position(|t| is_manage_py_path(t))?;
    let shell_pos = manage_pos.checked_add(1)?;
    let shell_cmd = tokens.get(shell_pos)?.as_str();
    if shell_cmd != "shell" && shell_cmd != "shell_plus" {
        return None;
    }

    for i in (shell_pos + 1)..tokens.len() {
        let tok = tokens.get(i)?;
        if tok == "-c" {
            let code = tokens.get(i + 1)?;
            return Some(ExtractedCode {
                language: "python".to_string(),
                code: code.clone(),
                context: Some(django_context("inline -c/--command".to_string())),
            });
        }
        if tok == "--command" {
            let code = tokens.get(i + 1)?;
            return Some(ExtractedCode {
                language: "python".to_string(),
                code: code.clone(),
                context: Some(django_context("inline -c/--command".to_string())),
            });
        }
        if let Some(rest) = tok.strip_prefix("--command=") {
            return Some(ExtractedCode {
                language: "python".to_string(),
                code: rest.to_string(),
                context: Some(django_context("inline -c/--command".to_string())),
            });
        }
    }

    None
}
