use crate::parser::Statement;

use super::super::config::AiJudgeConfig;
use super::django::{is_django_shell_consumer, is_manage_py_path};
use super::fs::read_safe_code_file;
use super::heredoc::extract_heredoc_written_script;
use super::utils::{
    command_name_matches, extract_echo_output, extract_printf_output, extract_single_cat_path,
    tokens_from_simple_command, unwrap_runner_chain,
};
use super::{ExtractedCode, MAX_EXTRACTED_CODE_BYTES};

pub(super) fn extract_from_python_stdin_pipeline(
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

                if is_django_shell_consumer(&consumer_unwrapped) {
                    continue;
                }

                let consumer_name = consumer_unwrapped.first()?.as_str();
                if !command_name_matches("python", consumer_name) {
                    continue;
                }
                if consumer_unwrapped.iter().any(|a| a == "-c" || a == "-m") {
                    continue;
                }
                if extract_python_script_path(&consumer_unwrapped[1..]).is_some() {
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
                        language: consumer_name.to_string(),
                        code,
                        context: None,
                    });
                }

                if source_name == "printf" {
                    let code = extract_printf_output(source_argv)?;
                    if code.len() > MAX_EXTRACTED_CODE_BYTES {
                        return None;
                    }
                    return Some(ExtractedCode {
                        language: consumer_name.to_string(),
                        code,
                        context: None,
                    });
                }

                if source_name == "cat" {
                    let path = extract_single_cat_path(source_argv)?;
                    let code = read_safe_code_file(&path, cwd)?;
                    return Some(ExtractedCode {
                        language: consumer_name.to_string(),
                        code,
                        context: None,
                    });
                }
            }
            None
        }
        Statement::List(list) => {
            if let Some(extracted) = extract_from_python_stdin_pipeline(&list.first, cwd, config) {
                return Some(extracted);
            }
            for (_, stmt) in &list.rest {
                if let Some(extracted) = extract_from_python_stdin_pipeline(stmt, cwd, config) {
                    return Some(extracted);
                }
            }
            None
        }
        Statement::Subshell(inner) | Statement::CommandSubstitution(inner) => {
            extract_from_python_stdin_pipeline(inner, cwd, config)
        }
        Statement::SimpleCommand(cmd) => {
            for sub in &cmd.embedded_substitutions {
                if let Some(extracted) = extract_from_python_stdin_pipeline(sub, cwd, config) {
                    return Some(extracted);
                }
            }
            None
        }
        Statement::Opaque(_) | Statement::Empty => None,
    }
}

pub(super) fn extract_python_script_execution(
    raw_command: &str,
    stmt: &Statement,
    cwd: &str,
    config: &AiJudgeConfig,
) -> Option<ExtractedCode> {
    match stmt {
        Statement::SimpleCommand(cmd) => {
            for sub in &cmd.embedded_substitutions {
                if let Some(result) = extract_python_script_execution(raw_command, sub, cwd, config)
                {
                    return Some(result);
                }
            }
            extract_python_script_from_simple_command(raw_command, cmd, cwd, config)
        }
        Statement::Pipeline(pipeline) => {
            for stage in &pipeline.stages {
                if let Some(result) =
                    extract_python_script_execution(raw_command, stage, cwd, config)
                {
                    return Some(result);
                }
            }
            None
        }
        Statement::List(list) => {
            if let Some(result) =
                extract_python_script_execution(raw_command, &list.first, cwd, config)
            {
                return Some(result);
            }
            for (_, stmt) in &list.rest {
                if let Some(result) =
                    extract_python_script_execution(raw_command, stmt, cwd, config)
                {
                    return Some(result);
                }
            }
            None
        }
        Statement::Subshell(inner) | Statement::CommandSubstitution(inner) => {
            extract_python_script_execution(raw_command, inner, cwd, config)
        }
        Statement::Opaque(_) | Statement::Empty => None,
    }
}

fn extract_python_script_from_simple_command(
    raw_command: &str,
    cmd: &crate::parser::SimpleCommand,
    cwd: &str,
    config: &AiJudgeConfig,
) -> Option<ExtractedCode> {
    let tokens = tokens_from_simple_command(cmd)?;
    let unwrapped = unwrap_runner_chain(&tokens, &config.triggers.runners);
    let cmd_name = unwrapped.first()?.as_str();
    let argv = &unwrapped[1..];

    if !command_name_matches("python", cmd_name) {
        return None;
    }
    if argv.iter().any(|a| a == "-c" || a == "-m") {
        return None;
    }

    if is_django_shell_consumer(&unwrapped) {
        return None;
    }

    if let Some(script_path) = extract_python_script_path(argv) {
        if is_manage_py_path(script_path) {
            return None;
        }

        if let Some(code) = extract_heredoc_written_script(raw_command, script_path) {
            return Some(ExtractedCode {
                language: cmd_name.to_string(),
                code,
                context: None,
            });
        }

        let code = read_safe_code_file(script_path, cwd)?;
        return Some(ExtractedCode {
            language: cmd_name.to_string(),
            code,
            context: None,
        });
    }

    // No script path: try `python < file.py`
    let mut read_targets: Vec<&str> = cmd
        .redirects
        .iter()
        .filter_map(|r| match r.op {
            crate::parser::RedirectOp::Read => Some(r.target.as_str()),
            _ => None,
        })
        .collect();
    read_targets.dedup();
    if read_targets.len() != 1 {
        return None;
    }
    let code = read_safe_code_file(read_targets[0], cwd)?;
    Some(ExtractedCode {
        language: cmd_name.to_string(),
        code,
        context: None,
    })
}

fn extract_python_script_path(argv: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < argv.len() {
        let arg = argv.get(i)?.as_str();
        if arg == "--" {
            return argv.get(i + 1).map(|s| s.as_str());
        }
        if arg == "-c" || arg == "-m" {
            return None;
        }
        // Flags with an accompanying value
        if arg == "-W" || arg == "-X" {
            i += 2;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        return Some(arg);
    }
    None
}
