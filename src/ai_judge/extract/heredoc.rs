use super::django::django_context;
use super::utils::basename;
use super::{ExtractedCode, MAX_EXTRACTED_CODE_BYTES};

pub(super) fn extract_heredoc_written_script(
    raw_command: &str,
    script_path: &str,
) -> Option<String> {
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

pub(super) fn extract_from_heredoc_or_herestring(raw_command: &str) -> Option<ExtractedCode> {
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
