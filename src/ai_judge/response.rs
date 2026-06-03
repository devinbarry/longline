/// Binary judge verdict. I1: there is deliberately no `Deny` — the AI-judge
/// contract is ALLOW/ASK only (lift-or-preserve, never strengthen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Ask,
}

/// Classification of a provider's stdout, before exit status is consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedOutput {
    /// A conforming `ALLOW:`/`ASK:` line (the full trimmed line is the reason).
    Verdict(Verdict, String),
    /// Stdout was empty or all-whitespace (the codex `last_agent_message: null` bug).
    EmptyOutput,
    /// Non-empty stdout with no verdict line (includes a `DENY:` line — see I1).
    NonConforming { snippet: String },
}

const SNIPPET_MAX: usize = 200;

/// Scan stdout for the first conforming verdict line; otherwise classify as
/// empty vs non-conforming. Exit status is NOT considered here (the
/// runner/orchestrator combine this with exit status, verdict-first).
pub fn parse_output(output: &str) -> ParsedOutput {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ALLOW:") {
            return ParsedOutput::Verdict(Verdict::Allow, trimmed.to_string());
        }
        if trimmed.starts_with("ASK:") {
            return ParsedOutput::Verdict(Verdict::Ask, trimmed.to_string());
        }
    }
    if output.trim().is_empty() {
        ParsedOutput::EmptyOutput
    } else {
        let snippet: String = output.trim().chars().take(SNIPPET_MAX).collect();
        ParsedOutput::NonConforming { snippet }
    }
}

/// Compatibility shim for `invoke.rs` (production caller) until Task 11 rewrites it.
/// Must be non-test because invoke.rs calls this from production (non-test) code.
#[allow(dead_code)]
pub fn parse_response_with_reason(o: &str) -> (crate::domain::Decision, String) {
    match parse_output(o) {
        ParsedOutput::Verdict(Verdict::Allow, r) => (crate::domain::Decision::Allow, r),
        ParsedOutput::Verdict(Verdict::Ask, r) => (crate::domain::Decision::Ask, r),
        _ => (
            crate::domain::Decision::Ask,
            "AI judge: unparseable response".into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_line_is_verdict_allow() {
        match parse_output("ALLOW: safe computation only") {
            ParsedOutput::Verdict(Verdict::Allow, r) => {
                assert_eq!(r, "ALLOW: safe computation only")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ask_line_is_verdict_ask() {
        match parse_output("noise\nASK: network access\ntokens: 5") {
            ParsedOutput::Verdict(Verdict::Ask, r) => assert_eq!(r, "ASK: network access"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn empty_and_whitespace_are_empty_output() {
        assert!(matches!(parse_output(""), ParsedOutput::EmptyOutput));
        assert!(matches!(
            parse_output("   \n\t  \n"),
            ParsedOutput::EmptyOutput
        ));
    }

    #[test]
    fn deny_line_is_nonconforming_never_a_verdict() {
        // I1: there is no Deny verdict. A DENY: line is just non-conforming text.
        match parse_output("DENY: this should not be representable") {
            ParsedOutput::NonConforming { snippet } => assert!(snippet.contains("DENY")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn nonempty_without_verdict_is_nonconforming_with_snippet() {
        match parse_output("I think this is fine, allow it") {
            ParsedOutput::NonConforming { snippet } => assert!(!snippet.is_empty()),
            other => panic!("{other:?}"),
        }
    }
}
