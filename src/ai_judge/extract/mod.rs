use crate::parser::Statement;

use super::config::AiJudgeConfig;

mod django;
mod fs;
mod heredoc;
mod inline;
mod python;
mod utils;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedCode {
    pub language: String,
    pub code: String,
    pub context: Option<String>,
}

const MAX_EXTRACTED_CODE_BYTES: usize = 32 * 1024;

/// Extract runnable code from a bash statement, if possible.
///
/// Precedence:
/// 1) Inline flags (`python -c`, `node -e`, etc), including runner-wrapped commands.
/// 2) Heredoc / here-string to python or Django shell (from raw command text).
/// 3) Pipelines feeding Django shell from `echo`/`printf`/`cat <file>` (CWD+/tmp only).
/// 4) Python script execution (`python script.py`, heredoc-created scripts, or `python < file.py`)
///    when the script contents can be safely extracted (CWD+/tmp only).
pub fn extract_code(
    raw_command: &str,
    stmt: &Statement,
    cwd: &str,
    config: &AiJudgeConfig,
) -> Option<ExtractedCode> {
    if let Some(mut extracted) = inline::extract_inline_code_from_stmt(stmt, config) {
        // If the code was extracted from within a pipeline that has a network
        // source (curl/wget), add context so the AI judge knows the data source.
        if extracted.context.is_none() && has_network_source_pipeline(stmt) {
            extracted.context = Some(format!(
                "Execution context: stdin piped from network download\nFull command: {raw_command}"
            ));
        }
        return Some(extracted);
    }

    if let Some(extracted) = heredoc::extract_from_heredoc_or_herestring(raw_command) {
        if extracted.code.len() <= MAX_EXTRACTED_CODE_BYTES {
            return Some(extracted);
        }
    }

    if let Some(extracted) = django::extract_from_django_shell_pipeline(stmt, cwd, config) {
        return Some(extracted);
    }

    if let Some(extracted) = python::extract_from_python_stdin_pipeline(stmt, cwd, config) {
        return Some(extracted);
    }

    if let Some(extracted) = python::extract_python_script_execution(raw_command, stmt, cwd, config)
    {
        return Some(extracted);
    }

    None
}

/// Check if the statement contains a pipeline with a network download command (curl/wget)
/// as one of its stages.
fn has_network_source_pipeline(stmt: &Statement) -> bool {
    match stmt {
        Statement::Pipeline(pipeline) => pipeline.stages.iter().any(|stage| {
            if let Statement::SimpleCommand(cmd) = stage {
                if let Some(ref name) = cmd.name {
                    let basename = name.rsplit('/').next().unwrap_or(name);
                    return basename == "curl" || basename == "wget";
                }
            }
            false
        }),
        Statement::List(list) => {
            has_network_source_pipeline(&list.first)
                || list
                    .rest
                    .iter()
                    .any(|(_, s)| has_network_source_pipeline(s))
        }
        Statement::Subshell(inner) | Statement::CommandSubstitution(inner) => {
            has_network_source_pipeline(inner)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
