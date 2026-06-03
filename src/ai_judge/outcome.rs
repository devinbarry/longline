use crate::ai_judge::response::{ParsedOutput, Verdict};

/// Outcome of a single attempt. See design §"Failure taxonomy".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// A real ALLOW/ASK verdict — success, returns immediately (incl. a legit ASK).
    Verdict(Verdict, String),
    /// Empty stdout, zero exit — the transient codex bug. Retry.
    EmptyOutput,
    /// Killed at per-attempt timeout. Retry (transient, expensive).
    Timeout { elapsed_ms: u64 },
    /// Produced text but no verdict line. Retry, capped at `max_nonconforming`.
    NonConforming { snippet: String },
    /// No verdict AND nonzero exit (auth/CLI error). Disable provider.
    ExitError { status: i32, stderr_snippet: String },
    /// Binary missing / OS spawn error. Disable provider.
    SpawnError { msg: String },
}

impl AttemptOutcome {
    #[allow(dead_code)]
    pub fn is_verdict(&self) -> bool {
        matches!(self, AttemptOutcome::Verdict(..))
    }

    /// Transient blips worth a retry within budget.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            AttemptOutcome::EmptyOutput
                | AttemptOutcome::Timeout { .. }
                | AttemptOutcome::NonConforming { .. }
        )
    }

    /// Outcomes that permanently disable the provider for this invocation.
    /// (NonConforming disables only via the per-provider COUNT cap, handled in
    /// the orchestrator — a single NonConforming does not disable.)
    pub fn disables_provider(&self) -> bool {
        matches!(
            self,
            AttemptOutcome::ExitError { .. } | AttemptOutcome::SpawnError { .. }
        )
    }
}

/// Combine parsed stdout with exit status, VERDICT-FIRST. `exit_status` is the
/// raw `code()` (None for signal-killed; treat as nonzero-no-verdict).
pub fn classify(parsed: ParsedOutput, exit_status: Option<i32>) -> AttemptOutcome {
    match parsed {
        ParsedOutput::Verdict(v, r) => AttemptOutcome::Verdict(v, r),
        ParsedOutput::EmptyOutput => match exit_status {
            Some(0) => AttemptOutcome::EmptyOutput,
            Some(code) => AttemptOutcome::ExitError {
                status: code,
                stderr_snippet: String::new(),
            },
            None => AttemptOutcome::ExitError {
                status: -1,
                stderr_snippet: String::new(),
            },
        },
        ParsedOutput::NonConforming { snippet } => match exit_status {
            Some(0) => AttemptOutcome::NonConforming { snippet },
            Some(code) => AttemptOutcome::ExitError {
                status: code,
                stderr_snippet: snippet,
            },
            None => AttemptOutcome::ExitError {
                status: -1,
                stderr_snippet: snippet,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_judge::response::{ParsedOutput, Verdict};

    // verdict-first: a valid ALLOW line wins even on nonzero exit.
    #[test]
    fn verdict_wins_over_nonzero_exit() {
        let o = classify(
            ParsedOutput::Verdict(Verdict::Allow, "ALLOW: ok".into()),
            Some(1),
        );
        assert!(matches!(o, AttemptOutcome::Verdict(Verdict::Allow, _)));
    }

    #[test]
    fn empty_stdout_zero_exit_is_empty_output() {
        let o = classify(ParsedOutput::EmptyOutput, Some(0));
        assert!(matches!(o, AttemptOutcome::EmptyOutput));
    }

    #[test]
    fn empty_stdout_nonzero_exit_is_exit_error_not_retryable() {
        // "Not logged in" trap: empty stdout + nonzero exit disables, never retries.
        let o = classify(ParsedOutput::EmptyOutput, Some(1));
        assert!(matches!(o, AttemptOutcome::ExitError { .. }));
        assert!(!o.is_retryable());
        assert!(o.disables_provider());
    }

    #[test]
    fn nonverdict_text_zero_exit_is_nonconforming() {
        let o = classify(
            ParsedOutput::NonConforming {
                snippet: "blah".into(),
            },
            Some(0),
        );
        assert!(matches!(o, AttemptOutcome::NonConforming { .. }));
    }

    #[test]
    fn nonverdict_text_nonzero_exit_is_exit_error() {
        let o = classify(
            ParsedOutput::NonConforming {
                snippet: "usage: ...".into(),
            },
            Some(1),
        );
        assert!(matches!(o, AttemptOutcome::ExitError { .. }));
    }

    #[test]
    fn empty_output_and_timeout_are_retryable_transient() {
        assert!(AttemptOutcome::EmptyOutput.is_retryable());
        assert!(AttemptOutcome::Timeout { elapsed_ms: 45000 }.is_retryable());
        assert!(!AttemptOutcome::EmptyOutput.disables_provider());
    }

    #[test]
    fn spawn_error_disables_and_does_not_retry() {
        let o = AttemptOutcome::SpawnError {
            msg: "No such file".into(),
        };
        assert!(!o.is_retryable());
        assert!(o.disables_provider());
    }
}
