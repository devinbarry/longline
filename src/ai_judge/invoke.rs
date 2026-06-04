use crate::ai_judge::config::AiJudgeConfig;
use crate::ai_judge::orchestrator::{orchestrate, OrchestrateParams, Xorshift};
use crate::ai_judge::outcome::{derive_failure_mode, JudgeReport, Phase, ReportOutcome};
use crate::ai_judge::provider::{resolve_provider_set, Provider, RealRunner};
use crate::ai_judge::response::Verdict;
use crate::ai_judge::settings::{self, SettingsOutcome};

/// Result of a judge run. `verdict ∈ {Allow, Ask}` (I1). `report` is logged.
pub struct JudgeVerdict {
    pub verdict: Verdict,
    pub reason: String,
    pub report: JudgeReport,
}

/// Evaluate inline code using the AI judge (strict prompt).
pub fn evaluate(
    config: &AiJudgeConfig,
    language: &str,
    code: &str,
    cwd: &str,
    context: Option<&str>,
    project_prompt: Option<&str>,
) -> JudgeVerdict {
    let prompt = super::prompt::build_prompt(language, code, cwd, context, project_prompt);
    run(config, prompt)
}

/// Evaluate inline code using the AI judge (lenient prompt).
pub fn evaluate_lenient(
    config: &AiJudgeConfig,
    language: &str,
    code: &str,
    cwd: &str,
    context: Option<&str>,
    project_prompt: Option<&str>,
) -> JudgeVerdict {
    let prompt = super::prompt::build_prompt_lenient(language, code, cwd, context, project_prompt);
    run(config, prompt)
}

fn run(config: &AiJudgeConfig, prompt: String) -> JudgeVerdict {
    let mut set = resolve_provider_set(&config.command, &config.fallback_command);
    for w in &set.warnings {
        eprintln!("{w}");
    }

    ensure_claude_settings(&mut set.providers);

    if set.empty {
        let report = JudgeReport {
            provider_final: None,
            outcome: ReportOutcome::Exhausted,
            failure_mode: derive_failure_mode(&[], true),
            phase_reached: Phase::Phase1,
            total_latency_ms: 0,
            attempts: vec![],
        };
        let reason = report.render_reason(None);
        return JudgeVerdict {
            verdict: Verdict::Ask,
            reason,
            report,
        };
    }

    let params = OrchestrateParams {
        // saturating: an absurd (but syntactically valid) secs value must not
        // overflow/panic here — fail-open (I4) before the orchestrator's own
        // saturating math runs.
        total_budget_ms: config.total_budget_secs.saturating_mul(1000),
        per_attempt_timeout_ms: config.timeout.saturating_mul(1000),
        hedge_after_ms: config.hedge_after_secs.saturating_mul(1000),
        backoff_base_ms: config.backoff_base_ms,
        backoff_max_ms: config.backoff_max_ms,
        relaunch_floor_ms: config.relaunch_floor_ms,
        max_attempts: config.max_attempts,
        max_nonconforming: config.max_nonconforming,
        min_launch_ms: config.relaunch_floor_ms,
    };
    let mut rng = Xorshift::new(process_seed());
    let (clock, mut runner) =
        RealRunner::new(prompt, judge_debug_enabled(), params.per_attempt_timeout_ms);
    let result = orchestrate(&clock, &mut runner, &set.providers, &params, &mut rng);

    match result.verdict {
        Some(v) => JudgeVerdict {
            verdict: v,
            reason: result.report.render_reason(result.verdict_line.as_deref()),
            report: result.report,
        },
        None => JudgeVerdict {
            verdict: Verdict::Ask,
            reason: result.report.render_reason(None),
            report: result.report,
        },
    }
}

/// For the provider named "claude", if its argv contains `--settings <path>`,
/// ensure the settings file is valid (atomic repair). On `Unavailable`, drop
/// `--settings` AND its path token so claude runs with `--setting-sources ""`
/// alone, and note `settings_unavailable` on stderr.
fn ensure_claude_settings(providers: &mut [Provider]) {
    const JOINED: &str = "--settings=";
    for p in providers.iter_mut() {
        if p.name != "claude" {
            continue;
        }
        // Recognize both the split form (`--settings <path>`) and the joined
        // form (`--settings=<path>`), so the cleanupPeriodDays>=3650 guarantee
        // holds for either shape a user might write in `fallback_command`.
        // `remove` lists the argv indices to drop if the settings file can't be
        // placed (so claude falls back to `--setting-sources ""` alone).
        let split = p.argv.iter().position(|a| a == "--settings");
        let resolved: Option<(std::path::PathBuf, Vec<usize>)> = if let Some(i) = split {
            // A dangling `--settings` with no following path is left untouched
            // (it will fail at spawn → ExitError → provider disabled → ask).
            p.argv
                .get(i + 1)
                .map(|path| (std::path::PathBuf::from(path), vec![i, i + 1]))
        } else {
            p.argv.iter().position(|a| a.starts_with(JOINED)).map(|i| {
                (
                    std::path::PathBuf::from(&p.argv[i][JOINED.len()..]),
                    vec![i],
                )
            })
        };

        let Some((path, mut remove)) = resolved else {
            continue;
        };
        if let SettingsOutcome::Unavailable = settings::ensure_settings_file(&path) {
            // Drop highest index first so earlier removals don't shift it.
            remove.sort_unstable_by(|a, b| b.cmp(a));
            for idx in remove {
                p.argv.remove(idx);
            }
            eprintln!(
                "longline: ai-judge settings_unavailable; claude running with --setting-sources \"\" only"
            );
        }
    }
}

fn process_seed() -> u64 {
    let pid = std::process::id() as u64;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    pid ^ nanos
}

fn judge_debug_enabled() -> bool {
    std::env::var("LONGLINE_AI_JUDGE_DEBUG")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fast-budget config without YAML quoting: deserialize `{}`,
    /// finalize, then overwrite the public fields tests need.
    fn test_config(command: &str, fallback: &str) -> AiJudgeConfig {
        let mut c = serde_norway::from_str::<AiJudgeConfig>("{}")
            .unwrap()
            .finalize();
        c.command = command.to_string();
        c.fallback_command = fallback.to_string();
        c.total_budget_secs = 5;
        c.timeout = 2;
        c.hedge_after_secs = 1;
        c.backoff_base_ms = 10;
        c.backoff_max_ms = 40;
        c.relaunch_floor_ms = 5;
        c.max_attempts = 8;
        c.max_nonconforming = 2;
        c
    }

    #[cfg(unix)]
    fn make_executable_script(name: &str, contents: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;

        // Use both process ID and thread ID for unique filenames across parallel tests
        let unique_name = format!(
            "{}-{:?}-{}",
            name,
            std::thread::current().id(),
            std::process::id()
        );
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("ai-judge-invoke");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(unique_name);
        std::fs::write(&path, contents).unwrap();
        // Ensure file is synced to disk before setting permissions
        std::fs::File::open(&path).unwrap().sync_all().unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    /// Signature guard: any change to the 6-arg shape / return type fails to compile.
    #[test]
    #[allow(clippy::type_complexity)]
    fn evaluate_signature_returns_judge_verdict() {
        let _: fn(&AiJudgeConfig, &str, &str, &str, Option<&str>, Option<&str>) -> JudgeVerdict =
            evaluate;
        let _: fn(&AiJudgeConfig, &str, &str, &str, Option<&str>, Option<&str>) -> JudgeVerdict =
            evaluate_lenient;
    }

    #[cfg(unix)]
    #[test]
    fn parses_allow_from_command_output_via_orchestrator() {
        let script =
            make_executable_script("allow.sh", "#!/bin/sh\necho 'ALLOW: safe computation'\n");
        let config = test_config(&script.to_string_lossy(), "");
        let v = evaluate(&config, "python3", "print(1)", "/tmp", None, None);
        assert_eq!(v.verdict, Verdict::Allow);
        assert_eq!(v.reason, "ALLOW: safe computation");
        assert!(matches!(v.report.outcome, ReportOutcome::Verdict));
        let _ = std::fs::remove_file(&script);
    }

    #[test]
    fn empty_command_and_empty_fallback_is_no_providers_ask() {
        let config = test_config("", "");
        let v = evaluate(&config, "python3", "print(1)", "/tmp", None, None);
        assert_eq!(v.verdict, Verdict::Ask);
        assert_eq!(v.report.failure_mode.as_deref(), Some("no_providers"));
        assert!(matches!(v.report.outcome, ReportOutcome::Exhausted));
    }

    #[cfg(unix)]
    #[test]
    fn missing_binary_returns_ask_exhausted_under_budget() {
        // A binary that cannot spawn disables the (sole) provider → exhausted/ask.
        let config = test_config("/definitely-not-a-real-ai-judge-command-12345", "");
        let v = evaluate(&config, "python3", "print(1)", "/tmp", None, None);
        assert_eq!(v.verdict, Verdict::Ask);
        assert!(matches!(v.report.outcome, ReportOutcome::Exhausted));
        // Well under the 5s budget — disabling on spawn error does not spin.
        assert!(
            v.report.total_latency_ms < 5_000,
            "fast exhaust at t={}",
            v.report.total_latency_ms
        );
    }

    #[cfg(unix)]
    #[test]
    fn timeout_script_returns_ask_exhausted_under_budget() {
        // Sleeps past the per-attempt timeout AND the total budget; every attempt
        // times out → exhausted/ask. Budget (5s) bounds the run.
        let script = make_executable_script("sleep.sh", "#!/bin/sh\nsleep 30\necho 'ALLOW: x'\n");
        let config = test_config(&script.to_string_lossy(), "");
        let v = evaluate(&config, "python3", "print(1)", "/tmp", None, None);
        assert_eq!(v.verdict, Verdict::Ask);
        assert!(matches!(v.report.outcome, ReportOutcome::Exhausted));
        // Bounded by the total budget (5s) plus modest slack for kill/reap.
        assert!(
            v.report.total_latency_ms < 15_000,
            "bounded by budget at t={}",
            v.report.total_latency_ms
        );
        let _ = std::fs::remove_file(&script);
    }

    fn unique_test_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join(format!(
                "ensure-claude-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ensure_claude_settings_validates_joined_form() {
        // `--settings=<path>` (joined) must be recognized and the file written/pinned.
        let dir = unique_test_dir("joined");
        let settings = dir.join("judge-claude-settings.json");
        let mut providers = vec![Provider {
            name: "claude".into(),
            argv: vec![
                "claude".into(),
                format!("--settings={}", settings.display()),
                "-p".into(),
            ],
        }];
        ensure_claude_settings(&mut providers);
        assert!(
            settings.exists(),
            "joined --settings= form must be validated and written"
        );
        let content = std::fs::read_to_string(&settings).unwrap();
        assert!(content.contains("\"cleanupPeriodDays\": 3650"));
        // Ready → argv keeps the joined token.
        assert!(providers[0]
            .argv
            .iter()
            .any(|a| a.starts_with("--settings=")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_claude_settings_drops_joined_token_when_unavailable() {
        // An unwritable joined path → drop just that token, keep --setting-sources "".
        let mut providers = vec![Provider {
            name: "claude".into(),
            argv: vec![
                "claude".into(),
                "--setting-sources".into(),
                "".into(),
                "--settings=/proc/longline-cannot-write/x.json".into(),
                "-p".into(),
            ],
        }];
        ensure_claude_settings(&mut providers);
        assert!(
            !providers[0]
                .argv
                .iter()
                .any(|a| a.starts_with("--settings=")),
            "unavailable joined --settings= token must be dropped: {:?}",
            providers[0].argv
        );
        // The unrelated --setting-sources flag (different flag) is untouched.
        assert!(providers[0].argv.iter().any(|a| a == "--setting-sources"));
    }

    #[test]
    fn ensure_claude_settings_drops_both_tokens_when_split_unavailable() {
        let mut providers = vec![Provider {
            name: "claude".into(),
            argv: vec![
                "claude".into(),
                "--settings".into(),
                "/proc/longline-cannot-write/x.json".into(),
                "-p".into(),
            ],
        }];
        ensure_claude_settings(&mut providers);
        assert!(
            !providers[0].argv.iter().any(|a| a == "--settings"),
            "split --settings flag must be dropped: {:?}",
            providers[0].argv
        );
        assert!(
            !providers[0]
                .argv
                .iter()
                .any(|a| a.contains("longline-cannot-write")),
            "split path token must be dropped: {:?}",
            providers[0].argv
        );
    }
}
