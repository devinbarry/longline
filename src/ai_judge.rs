use serde::Deserialize;
use std::path::PathBuf;

use crate::parser::Statement;
use crate::types::Decision;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedCode {
    pub language: String,
    pub code: String,
    pub context: Option<String>,
}

// ── Config types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AiJudgeConfig {
    #[serde(default = "default_command")]
    pub command: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub triggers: TriggersConfig,
}

#[derive(Debug, Deserialize)]
pub struct TriggersConfig {
    #[serde(default = "default_interpreters")]
    pub interpreters: Vec<InterpreterTrigger>,
    #[serde(default = "default_runners")]
    pub runners: Vec<String>,
}

impl Default for TriggersConfig {
    fn default() -> Self {
        Self {
            interpreters: default_interpreters(),
            runners: default_runners(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InterpreterTrigger {
    pub name: Vec<String>,
    pub inline_flag: String,
}

fn default_command() -> String {
    "codex exec".to_string()
}

fn default_timeout() -> u64 {
    15
}

fn default_interpreters() -> Vec<InterpreterTrigger> {
    vec![
        InterpreterTrigger {
            name: vec!["python".into(), "python3".into()],
            inline_flag: "-c".into(),
        },
        InterpreterTrigger {
            name: vec!["node".into()],
            inline_flag: "-e".into(),
        },
        InterpreterTrigger {
            name: vec!["ruby".into()],
            inline_flag: "-e".into(),
        },
        InterpreterTrigger {
            name: vec!["perl".into()],
            inline_flag: "-e".into(),
        },
    ]
}

fn default_runners() -> Vec<String> {
    vec![
        "uv".to_string(),
        "poetry".to_string(),
        "pipenv".to_string(),
        "pdm".to_string(),
        "rye".to_string(),
    ]
}

// ── Config loading ──────────────────────────────────────────────

fn default_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".config")
        .join("longline")
        .join("ai-judge.yaml")
}

pub fn load_config() -> AiJudgeConfig {
    let path = default_config_path();
    if !path.exists() {
        return default_config();
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_yaml::from_str(&content).unwrap_or_else(|e| {
            eprintln!("longline: failed to parse ai-judge config: {e}");
            default_config()
        }),
        Err(e) => {
            eprintln!("longline: failed to read ai-judge config: {e}");
            default_config()
        }
    }
}

fn default_config() -> AiJudgeConfig {
    AiJudgeConfig {
        command: default_command(),
        timeout: default_timeout(),
        triggers: TriggersConfig::default(),
    }
}

// ── Trigger detection ───────────────────────────────────────────

const MAX_EXTRACTED_CODE_BYTES: usize = 32 * 1024;

/// Extract runnable Python code from a bash statement, if possible.
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
    if let Some(extracted) = extract_inline_code_from_stmt(stmt, config) {
        return Some(extracted);
    }

    if let Some(extracted) = extract_from_heredoc_or_herestring(raw_command) {
        if extracted.code.len() <= MAX_EXTRACTED_CODE_BYTES {
            return Some(extracted);
        }
    }

    if let Some(extracted) = extract_from_django_shell_pipeline(stmt, cwd, config) {
        return Some(extracted);
    }

    if let Some(extracted) = extract_from_python_stdin_pipeline(stmt, cwd, config) {
        return Some(extracted);
    }

    if let Some(extracted) = extract_python_script_execution(raw_command, stmt, cwd, config) {
        return Some(extracted);
    }

    None
}

fn extract_inline_code_from_stmt(
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

fn extract_from_django_shell_pipeline(
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
        Statement::Opaque(_) => None,
    }
}

fn extract_from_python_stdin_pipeline(
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
        Statement::Opaque(_) => None,
    }
}

fn extract_echo_output(argv: &[String]) -> Option<String> {
    // Handle common echo flags (-n/-e/-E), then join remaining words.
    let mut idx = 0;
    while idx < argv.len() {
        match argv[idx].as_str() {
            "-n" | "-e" | "-E" => idx += 1,
            _ => break,
        }
    }
    let rest = argv.get(idx..)?;
    if rest.is_empty() {
        return Some(String::new());
    }
    Some(rest.join(" "))
}

fn extract_printf_output(argv: &[String]) -> Option<String> {
    // Conservatively support `printf 'code'` and `printf \"%s\" \"code\"`.
    if argv.is_empty() {
        return Some(String::new());
    }
    if argv[0] == "-v" {
        return None;
    }
    if argv.len() == 1 {
        return Some(argv[0].clone());
    }
    if argv[0] == "%s" && argv.len() == 2 {
        return Some(argv[1].clone());
    }
    None
}

fn extract_single_cat_path(argv: &[String]) -> Option<String> {
    if argv.len() != 1 {
        return None;
    }
    let path = argv[0].as_str();
    if path.starts_with('-') {
        return None;
    }
    Some(path.to_string())
}

fn extract_python_script_execution(
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
        Statement::Opaque(_) => None,
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

fn read_safe_code_file(path: &str, cwd: &str) -> Option<String> {
    let path = expand_tilde(path)?;

    let cwd_root = std::fs::canonicalize(cwd).ok()?;
    let candidate = if std::path::Path::new(&path).is_absolute() {
        std::path::PathBuf::from(path)
    } else {
        cwd_root.join(path)
    };

    let candidate = std::fs::canonicalize(candidate).ok()?;
    if !is_under_allowed_root(&candidate, &cwd_root) && !is_under_temp_root(&candidate) {
        return None;
    }

    let meta = std::fs::metadata(&candidate).ok()?;
    if !meta.is_file() || meta.len() as usize > MAX_EXTRACTED_CODE_BYTES {
        return None;
    }
    let bytes = std::fs::read(&candidate).ok()?;
    if bytes.len() > MAX_EXTRACTED_CODE_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn is_under_allowed_root(path: &std::path::Path, root: &std::path::Path) -> bool {
    path.starts_with(root)
}

fn is_under_temp_root(path: &std::path::Path) -> bool {
    if path.starts_with(std::path::Path::new("/tmp")) {
        return true;
    }
    if let Ok(tmp) = std::fs::canonicalize("/tmp") {
        if path.starts_with(&tmp) {
            return true;
        }
    }
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        if let Ok(tmpdir) = std::fs::canonicalize(tmpdir) {
            if path.starts_with(&tmpdir) {
                return true;
            }
        }
    }
    false
}

fn expand_tilde(path: &str) -> Option<String> {
    if path == "~" {
        return std::env::var("HOME").ok();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").ok()?;
        return Some(
            std::path::Path::new(&home)
                .join(rest)
                .to_string_lossy()
                .to_string(),
        );
    }
    Some(path.to_string())
}

fn is_manage_py_path(arg: &str) -> bool {
    if arg == "manage.py" {
        return true;
    }
    let p = std::path::Path::new(arg);
    p.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s == "manage.py")
        .unwrap_or(false)
}

fn is_django_shell_consumer(tokens: &[String]) -> bool {
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

fn tokens_from_simple_command(cmd: &crate::parser::SimpleCommand) -> Option<Vec<String>> {
    let name = cmd.name.as_ref()?;
    let mut out = Vec::with_capacity(1 + cmd.argv.len());
    out.push(basename(name).to_string());
    out.extend(cmd.argv.iter().cloned());
    Some(out)
}

fn basename(cmd_name: &str) -> &str {
    std::path::Path::new(cmd_name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(cmd_name)
}

fn unwrap_runner_chain(tokens: &[String], runners: &[String]) -> Vec<String> {
    let mut current = tokens.to_vec();
    for _ in 0..4 {
        let Some(next) = unwrap_runner_once(&current, runners) else {
            break;
        };
        current = next;
    }
    current
}

fn unwrap_runner_once(tokens: &[String], runners: &[String]) -> Option<Vec<String>> {
    let name = tokens.first().map(|s| s.as_str())?;
    if !runners.iter().any(|r| r == name) {
        return None;
    }
    let run_pos = tokens.iter().position(|t| t == "run")?;
    let mut start = run_pos + 1;
    if start < tokens.len() && tokens[start] == "--" {
        start += 1;
    }
    if start >= tokens.len() {
        return None;
    }
    let mut out = tokens[start..].to_vec();
    if let Some(first) = out.first_mut() {
        *first = basename(first).to_string();
    }
    Some(out)
}

fn command_name_matches(expected: &str, actual: &str) -> bool {
    if expected == actual {
        return true;
    }
    if !matches!(expected, "python" | "python3") {
        return false;
    }
    actual.strip_prefix(expected).is_some_and(|rest| {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit() || c == '.')
    })
}

fn django_context(code_source: String) -> String {
    format!(
        "Execution context: Django manage.py shell (can access the database and Django settings). Code source: {code_source}. Guidance: ALLOW only read-only ORM queries/printing; ASK on any data writes/deletes/migrations, secrets, network, or subprocess execution."
    )
}

fn extract_heredoc_written_script(raw_command: &str, script_path: &str) -> Option<String> {
    // Support `cat > script.py <<'EOF' ... EOF` and `cat <<'EOF' > script.py`.
    // Only triggers when we can confidently associate the heredoc with the script path.
    let mut candidates: Vec<&str> = vec![script_path];
    if let Some(rest) = script_path.strip_prefix("./") {
        candidates.push(rest);
    }

    let lines: Vec<&str> = raw_command.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let Some((op_idx, op_kind)) = find_heredoc_op_outside_quotes(line) else {
            continue;
        };
        let (delim, strip_tabs) = parse_heredoc_delim(&line[op_idx..], op_kind)?;

        // Must be a heredoc that writes to the same path the python invocation executes.
        if !candidates.iter().any(|p| line.contains(p)) {
            continue;
        }

        let before = line[..op_idx].trim_start();
        let consumer = before.split_whitespace().next().map(basename)?;
        if consumer != "cat" && consumer != "tee" {
            continue;
        }

        let mut body = Vec::new();
        for line in lines.iter().skip(i + 1) {
            let mut candidate = line.trim_end_matches('\r');
            if strip_tabs {
                candidate = candidate.trim_start_matches('\t');
            }
            if candidate == delim {
                let code = body.join("\n");
                if code.len() > MAX_EXTRACTED_CODE_BYTES {
                    return None;
                }
                return Some(code);
            }
            body.push(line.trim_end_matches('\r').to_string());
            if body.iter().map(|s| s.len() + 1).sum::<usize>() > MAX_EXTRACTED_CODE_BYTES {
                return None;
            }
        }
    }
    None
}

fn extract_from_heredoc_or_herestring(raw_command: &str) -> Option<ExtractedCode> {
    let (heredoc, language, context) = extract_heredoc(raw_command)?;
    Some(ExtractedCode {
        language,
        code: heredoc,
        context,
    })
}

fn extract_heredoc(raw_command: &str) -> Option<(String, String, Option<String>)> {
    let lines: Vec<&str> = raw_command.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let Some((op_idx, op_kind)) = find_heredoc_op_outside_quotes(line) else {
            continue;
        };
        let (delim, strip_tabs) = parse_heredoc_delim(&line[op_idx..], op_kind)?;
        let before = &line[..op_idx];
        let (language, context) = classify_heredoc_consumer(before)?;

        let mut body = Vec::new();
        for line in lines.iter().skip(i + 1) {
            let mut candidate = line.trim_end_matches('\r');
            if strip_tabs {
                candidate = candidate.trim_start_matches('\t');
            }
            if candidate == delim {
                let code = body.join("\n");
                return Some((code, language, context));
            }
            body.push(line.trim_end_matches('\r').to_string());
            if body.iter().map(|s| s.len() + 1).sum::<usize>() > MAX_EXTRACTED_CODE_BYTES {
                return None;
            }
        }
    }

    extract_herestring(raw_command)
}

fn extract_herestring(raw_command: &str) -> Option<(String, String, Option<String>)> {
    for line in raw_command.lines() {
        let Some((op_idx, op_kind)) = find_herestring_op_outside_quotes(line) else {
            continue;
        };
        let before = &line[..op_idx];
        let (language, context) = classify_heredoc_consumer(before)?;
        let code = parse_herestring_payload(&line[op_idx..], op_kind)?;
        if code.len() > MAX_EXTRACTED_CODE_BYTES {
            return None;
        }
        return Some((code, language, context));
    }
    None
}

fn classify_heredoc_consumer(before_op: &str) -> Option<(String, Option<String>)> {
    // Very small heuristic parser: only treat heredocs feeding python or Django shell.
    let before = before_op;
    if before.contains("manage.py") && (before.contains(" shell") || before.contains(" shell_plus"))
    {
        return Some((
            "python".to_string(),
            Some(django_context("heredoc/here-string stdin".to_string())),
        ));
    }
    if before.contains("python3") {
        return Some(("python3".to_string(), None));
    }
    if before.contains("python") {
        return Some(("python".to_string(), None));
    }
    None
}

enum HereOpKind {
    HereDoc { strip_tabs: bool },
    HereString,
}

fn find_heredoc_op_outside_quotes(line: &str) -> Option<(usize, HereOpKind)> {
    find_here_op_outside_quotes(line, false)
}

fn find_herestring_op_outside_quotes(line: &str) -> Option<(usize, HereOpKind)> {
    find_here_op_outside_quotes(line, true)
}

fn find_here_op_outside_quotes(line: &str, want_herestring: bool) -> Option<(usize, HereOpKind)> {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\'' if !in_double => {
                in_single = !in_single;
                i += 1;
                continue;
            }
            b'"' if !in_single => {
                in_double = !in_double;
                i += 1;
                continue;
            }
            b'\\' if in_double => {
                i += 2;
                continue;
            }
            _ => {}
        }
        if !in_single && !in_double {
            if want_herestring {
                if i + 3 <= bytes.len() && &bytes[i..i + 3] == b"<<<" {
                    return Some((i, HereOpKind::HereString));
                }
            } else if i + 2 <= bytes.len() && &bytes[i..i + 2] == b"<<" {
                if i + 2 < bytes.len() && bytes[i + 2] == b'<' {
                    // Here-string (<<<) - don't treat as heredoc.
                    i += 3;
                    continue;
                }
                let strip_tabs = i + 3 <= bytes.len() && &bytes[i..i + 3] == b"<<-";
                return Some((i, HereOpKind::HereDoc { strip_tabs }));
            }
        }
        i += 1;
    }
    None
}

fn parse_heredoc_delim(op_and_rest: &str, kind: HereOpKind) -> Option<(&str, bool)> {
    let HereOpKind::HereDoc { strip_tabs } = kind else {
        return None;
    };
    let mut rest = op_and_rest;
    if rest.starts_with("<<-") {
        rest = &rest[3..];
    } else if rest.starts_with("<<") {
        rest = &rest[2..];
    } else {
        return None;
    }
    rest = rest.trim_start();
    if rest.is_empty() {
        return None;
    }
    if let Some(inner) = rest.strip_prefix('\'') {
        let end = inner.find('\'')?;
        let delim = &inner[..end];
        return Some((delim, strip_tabs));
    }
    if let Some(inner) = rest.strip_prefix('"') {
        let end = inner.find('"')?;
        let delim = &inner[..end];
        return Some((delim, strip_tabs));
    }
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ';' || c == '&' || c == '|')
        .unwrap_or(rest.len());
    let delim = &rest[..end];
    if delim.is_empty() {
        return None;
    }
    Some((delim, strip_tabs))
}

fn parse_herestring_payload(op_and_rest: &str, kind: HereOpKind) -> Option<String> {
    if !matches!(kind, HereOpKind::HereString) {
        return None;
    }
    let mut rest = op_and_rest;
    if !rest.starts_with("<<<") {
        return None;
    }
    rest = &rest[3..];
    rest = rest.trim_start();
    if let Some(inner) = rest.strip_prefix('\'') {
        let end = inner.find('\'')?;
        let payload = &inner[..end];
        return Some(payload.to_string());
    }
    if let Some(inner) = rest.strip_prefix('"') {
        // Skip dynamic double-quoted here-strings (variable expansion/substitution)
        let end = inner.find('"')?;
        let payload = &inner[..end];
        if payload.contains('$') || payload.contains('`') {
            return None;
        }
        return Some(payload.to_string());
    }
    None
}

// ── Prompt ──────────────────────────────────────────────────────

const PROMPT_TEMPLATE: &str = r#"Security evaluation of {language} code to be executed on a developer's machine.

Working directory: {cwd}
{context_block}

```{language}
{code}
```

Evaluate safety. Respond with EXACTLY one line, no other output:

ALLOW: <brief reason>
— Code only does: computation, data formatting, printing output, reading/writing
  files in the working directory or temp directories (/tmp, $TMPDIR, tempfile
  module), string/regex operations, JSON/YAML/CSV parsing, encoding, hashing,
  math, type checking, or version queries.

ASK: <brief reason>
— Code does ANY of: write/delete/move/rename files outside temp dirs or the
  working directory, network requests, subprocess or shell execution (os.system,
  subprocess), access secrets or credentials (.env, SSH keys, tokens), modify
  system configuration, install packages, or access sensitive paths outside the
  working directory."#;

pub fn build_prompt(language: &str, code: &str, cwd: &str, context: Option<&str>) -> String {
    let context_block = match context {
        Some(c) if !c.trim().is_empty() => format!("\n{c}\n"),
        _ => String::new(),
    };
    PROMPT_TEMPLATE
        .replace("{language}", language)
        .replace("{code}", code)
        .replace("{cwd}", cwd)
        .replace("{context_block}", &context_block)
}

// ── Response parsing ────────────────────────────────────────────

/// Parse the AI judge response, returning both the decision and the full reason line.
pub fn parse_response_with_reason(output: &str) -> (Decision, String) {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ALLOW:") {
            return (Decision::Allow, trimmed.to_string());
        }
        if trimmed.starts_with("ASK:") {
            return (Decision::Ask, trimmed.to_string());
        }
    }
    (Decision::Ask, "AI judge: unparseable response".to_string())
}

// ── LLM invocation ─────────────────────────────────────────────

/// Evaluate inline code using the AI judge.
/// Returns (decision, reason) where reason is the AI's assessment.
pub fn evaluate(
    config: &AiJudgeConfig,
    language: &str,
    code: &str,
    cwd: &str,
    context: Option<&str>,
) -> (Decision, String) {
    let prompt = build_prompt(language, code, cwd, context);

    let parts: Vec<String> = config
        .command
        .split_whitespace()
        .map(String::from)
        .collect();
    if parts.is_empty() {
        let reason = "AI judge error: command is empty".to_string();
        eprintln!("longline: ai-judge command is empty");
        return (Decision::Ask, reason);
    }

    let timeout = std::time::Duration::from_secs(config.timeout);
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let result = std::process::Command::new(&parts[0])
            .args(&parts[1..])
            .arg(&prompt)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output();
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_response_with_reason(&stdout)
        }
        Ok(Err(e)) => {
            let reason = format!("AI judge error: {e}");
            eprintln!("longline: ai-judge process error: {e}");
            (Decision::Ask, reason)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let reason = format!("AI judge error: timed out after {}s", config.timeout);
            eprintln!("longline: ai-judge timed out after {}s", config.timeout);
            (Decision::Ask, reason)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            let reason = "AI judge error: thread error".to_string();
            eprintln!("longline: ai-judge thread error");
            (Decision::Ask, reason)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;
    use std::path::PathBuf;

    fn test_config() -> AiJudgeConfig {
        default_config()
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
    // Response parsing with reason tests
    // ============================================================

    #[test]
    fn test_parse_response_with_reason_allow() {
        let (decision, reason) = parse_response_with_reason("ALLOW: safe computation only");
        assert_eq!(decision, Decision::Allow);
        assert_eq!(reason, "ALLOW: safe computation only");
    }

    #[test]
    fn test_parse_response_with_reason_ask() {
        let (decision, reason) = parse_response_with_reason("ASK: accesses files outside cwd");
        assert_eq!(decision, Decision::Ask);
        assert_eq!(reason, "ASK: accesses files outside cwd");
    }

    #[test]
    fn test_parse_response_with_noise_before() {
        let output = "Loading model...\nALLOW: safe computation";
        let (decision, reason) = parse_response_with_reason(output);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(reason, "ALLOW: safe computation");
    }

    #[test]
    fn test_parse_response_with_noise_after() {
        let output = "ASK: network access\nTokens used: 150";
        let (decision, reason) = parse_response_with_reason(output);
        assert_eq!(decision, Decision::Ask);
        assert_eq!(reason, "ASK: network access");
    }

    #[test]
    fn test_parse_response_with_reason_unparseable() {
        let (decision, reason) = parse_response_with_reason("something random");
        assert_eq!(decision, Decision::Ask);
        assert!(
            reason.contains("unparseable"),
            "Reason should indicate unparseable: {}",
            reason
        );
    }

    #[test]
    fn test_parse_response_with_reason_empty() {
        let (decision, reason) = parse_response_with_reason("");
        assert_eq!(decision, Decision::Ask);
        assert!(reason.contains("unparseable") || reason.contains("AI judge"));
    }

    #[test]
    fn test_build_prompt() {
        let prompt = build_prompt(
            "python3",
            "print(1)",
            "/home/user/project",
            Some("Execution context: Django shell"),
        );
        assert!(prompt.contains("python3"));
        assert!(prompt.contains("print(1)"));
        assert!(prompt.contains("/home/user/project"));
        assert!(prompt.contains("Execution context"));
        assert!(prompt.contains("ALLOW:"));
        assert!(prompt.contains("ASK:"));
    }

    #[test]
    fn test_parse_response_allow() {
        let (decision, _) = parse_response_with_reason("ALLOW: safe computation");
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_parse_response_ask() {
        let (decision, _) = parse_response_with_reason("ASK: network access detected");
        assert_eq!(decision, Decision::Ask);
    }

    #[test]
    fn test_parse_response_with_noise() {
        let output = "OpenAI Codex v0.84.0\n--------\nALLOW: safe computation\ntokens used\n";
        let (decision, _) = parse_response_with_reason(output);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_parse_response_unparseable() {
        let (decision, _) = parse_response_with_reason("something unexpected");
        assert_eq!(decision, Decision::Ask);
    }

    #[test]
    fn test_parse_response_empty() {
        let (decision, _) = parse_response_with_reason("");
        assert_eq!(decision, Decision::Ask);
    }

    #[test]
    fn test_config_deserialization() {
        let yaml = r#"
command: claude -p
timeout: 10
triggers:
  interpreters:
    - name: [python, python3]
      inline_flag: "-c"
"#;
        let config: AiJudgeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.command, "claude -p");
        assert_eq!(config.timeout, 10);
        assert_eq!(config.triggers.interpreters.len(), 1);
        assert_eq!(
            config.triggers.interpreters[0].name,
            vec!["python", "python3"]
        );
        assert!(!config.triggers.runners.is_empty());
    }

    #[test]
    fn test_config_defaults() {
        let yaml = "{}";
        let config: AiJudgeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.command, "codex exec");
        assert_eq!(config.timeout, 15);
        assert!(!config.triggers.interpreters.is_empty());
        assert!(!config.triggers.runners.is_empty());
    }
}
