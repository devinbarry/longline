use crate::parser::SimpleCommand;

pub(super) fn extract_echo_output(argv: &[String]) -> Option<String> {
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

pub(super) fn extract_printf_output(argv: &[String]) -> Option<String> {
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

pub(super) fn extract_single_cat_path(argv: &[String]) -> Option<String> {
    if argv.len() != 1 {
        return None;
    }
    let path = argv[0].as_str();
    if path.starts_with('-') {
        return None;
    }
    Some(path.to_string())
}

pub(super) fn tokens_from_simple_command(cmd: &SimpleCommand) -> Option<Vec<String>> {
    let name = cmd.name.as_ref()?;
    let mut out = Vec::with_capacity(1 + cmd.argv.len());
    out.push(basename(name).to_string());
    out.extend(cmd.argv.iter().cloned());
    Some(out)
}

pub(super) fn basename(cmd_name: &str) -> &str {
    std::path::Path::new(cmd_name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(cmd_name)
}

pub(super) fn unwrap_runner_chain(tokens: &[String], runners: &[String]) -> Vec<String> {
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

pub(super) fn command_name_matches(expected: &str, actual: &str) -> bool {
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
