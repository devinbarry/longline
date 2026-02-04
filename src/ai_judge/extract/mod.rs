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
    if let Some(extracted) = inline::extract_inline_code_from_stmt(stmt, config) {
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

#[cfg(test)]
mod tests;
