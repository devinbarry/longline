use crate::ai_judge::response::{ParsedOutput, Verdict};
use serde::Serialize;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Phase1,
    Hedge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportOutcome {
    Verdict,
    Exhausted,
}

/// One row per launched attempt (incl. launched-then-cancelled, which carry a
/// log-only `cancelled_winner`/`cancelled_deadline` outcome).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttemptRecord {
    pub provider: String,
    pub outcome: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JudgeReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_final: Option<String>,
    pub outcome: ReportOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_mode: Option<String>,
    pub phase_reached: Phase,
    pub total_latency_ms: u64,
    pub attempts: Vec<AttemptRecord>,
}

/// Canonical short tag for an outcome, used both in `AttemptRecord.outcome` and
/// in the failure-mode tally. Keep this the single source of these strings.
pub fn outcome_tag(o: &AttemptOutcome) -> &'static str {
    match o {
        AttemptOutcome::Verdict(..) => "verdict",
        AttemptOutcome::EmptyOutput => "empty_output",
        AttemptOutcome::Timeout { .. } => "timeout",
        AttemptOutcome::NonConforming { .. } => "nonconforming",
        AttemptOutcome::ExitError { .. } => "exit_error",
        AttemptOutcome::SpawnError { .. } => "spawn_error",
    }
}

impl JudgeReport {
    /// Derived flat reason. For a verdict, pass the verdict line; for exhausted,
    /// pass None and summarize the tallies.
    pub fn render_reason(&self, verdict_line: Option<&str>) -> String {
        match self.outcome {
            ReportOutcome::Verdict => verdict_line.unwrap_or("ALLOW:").to_string(),
            ReportOutcome::Exhausted => {
                let secs = self.total_latency_ms / 1000;
                let n = self.attempts.len();
                let summary = humanize_failure_mode(self.failure_mode.as_deref());
                format!("AI judge: no verdict after {n} attempts in {secs}s ({summary})")
            }
        }
    }
}

/// Build the compact tally string, e.g. `codex:7empty,1exit;claude:2nonconforming`.
/// `cancelled_*` outcomes are excluded. Returns `no_providers` when the provider
/// set was empty/malformed.
pub fn derive_failure_mode(attempts: &[AttemptRecord], empty_provider_set: bool) -> Option<String> {
    if empty_provider_set {
        return Some("no_providers".to_string());
    }
    use std::collections::BTreeMap;
    // provider -> (empty, timeout, nonconforming, exit, spawn)
    let mut by: BTreeMap<&str, [u32; 5]> = BTreeMap::new();
    for a in attempts {
        let idx = match a.outcome.as_str() {
            "empty_output" => 0,
            "timeout" => 1,
            "nonconforming" => 2,
            "exit_error" => 3,
            "spawn_error" => 4,
            _ => continue, // verdict / cancelled_* excluded
        };
        by.entry(&a.provider).or_default()[idx] += 1;
    }
    if by.is_empty() {
        return None;
    }
    let labels = ["empty", "timeout", "nonconforming", "exit", "spawn"];
    let parts: Vec<String> = by
        .iter()
        .map(|(prov, counts)| {
            let inner: Vec<String> = counts
                .iter()
                .enumerate()
                .filter(|(_, c)| **c > 0)
                .map(|(i, c)| format!("{c}{}", labels[i]))
                .collect();
            format!("{prov}:{}", inner.join(","))
        })
        .collect();
    Some(parts.join(";"))
}

fn humanize_failure_mode(fm: Option<&str>) -> String {
    fm.unwrap_or("no attempts").to_string()
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

#[cfg(test)]
mod report_tests {
    use super::*;

    fn rec(p: &str, o: &str, ms: u64) -> AttemptRecord {
        AttemptRecord {
            provider: p.into(),
            outcome: o.into(),
            latency_ms: ms,
        }
    }

    #[test]
    fn verdict_report_reason_is_the_verdict_line() {
        let r = JudgeReport {
            provider_final: Some("codex".into()),
            outcome: ReportOutcome::Verdict,
            failure_mode: None,
            phase_reached: Phase::Phase1,
            total_latency_ms: 4200,
            attempts: vec![rec("codex", "verdict", 4200)],
        };
        assert_eq!(r.render_reason(Some("ALLOW: safe")), "ALLOW: safe");
    }

    #[test]
    fn exhausted_reason_summarizes_terminal_tallies() {
        let r = JudgeReport {
            provider_final: None,
            outcome: ReportOutcome::Exhausted,
            failure_mode: Some("codex:7empty,1timeout".into()),
            phase_reached: Phase::Hedge,
            total_latency_ms: 90000,
            attempts: vec![
                rec("codex", "empty_output", 1500),
                rec("codex", "timeout", 45000),
            ],
        };
        let reason = r.render_reason(None);
        assert!(reason.starts_with("AI judge: no verdict after"), "{reason}");
        assert!(reason.contains("codex"), "{reason}");
    }

    #[test]
    fn failure_mode_no_providers_when_set_empty() {
        assert_eq!(derive_failure_mode(&[], true), Some("no_providers".into()));
    }

    #[test]
    fn failure_mode_tally_excludes_cancelled_outcomes() {
        let attempts = vec![
            rec("codex", "empty_output", 1),
            rec("codex", "cancelled_winner", 1), // excluded
            rec("codex", "exit_error", 1),
            rec("claude", "nonconforming", 1),
        ];
        let fm = derive_failure_mode(&attempts, false).unwrap();
        assert!(fm.contains("codex:1empty,1exit"), "{fm}");
        assert!(fm.contains("claude:1nonconforming"), "{fm}");
        assert!(!fm.contains("cancelled"), "{fm}");
    }
}
