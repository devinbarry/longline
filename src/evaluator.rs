use std::path::Path;

use crate::logger;
use longline::ai_judge;
use longline::domain::Decision;
use longline::domain::PolicyResult;
use longline::parser;
use longline::policy;

#[cfg_attr(not(test), allow(dead_code))]
const SENSITIVE_PATH_PATTERNS: &[&str] = &["/.ssh/", "/.aws/", "/.gnupg/"];
#[cfg_attr(not(test), allow(dead_code))]
const SENSITIVE_EXACT_PATHS: &[&str] = &["/etc/shadow"];

#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Invocation {
    Shell {
        command: Option<String>,
        cwd: Option<String>,
        #[allow(dead_code)]
        session_id: Option<String>,
    },
    ReadPath {
        tool_name: String,
        path: Option<String>,
        cwd: Option<String>,
        #[allow(dead_code)]
        session_id: Option<String>,
    },
    SearchPath {
        tool_name: String,
        path: Option<String>,
        cwd: Option<String>,
        #[allow(dead_code)]
        session_id: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct EvaluationOptions {
    pub ask_on_deny: bool,
    #[allow(dead_code)]
    pub ask_ai: bool,
    #[allow(dead_code)]
    pub ask_ai_lenient: bool,
    pub cli_trust_level: Option<policy::TrustLevel>,
    pub cli_safety_level: Option<policy::SafetyLevel>,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct EvaluationOutcome {
    pub decision: Decision,
    pub reason: String,
    pub log_reason: Option<String>,
    pub matched_rules: Vec<String>,
    pub parse_ok: bool,
    pub original_decision: Option<Decision>,
    pub overridden: bool,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum EvaluationError {
    Config(String),
}

impl std::fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(message) => f.write_str(message),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn evaluate_invocation(
    config: policy::RulesConfig,
    home: &Path,
    invocation: Invocation,
    options: EvaluationOptions,
) -> Result<EvaluationOutcome, EvaluationError> {
    let cwd = invocation.cwd().map(Path::new);
    let final_config = longline::config::finalize_config(
        config,
        home,
        cwd,
        options.cli_trust_level,
        options.cli_safety_level,
    )
    .map_err(EvaluationError::Config)?;

    match invocation {
        Invocation::Shell {
            command: None,
            cwd: _,
            session_id: _,
        } => Ok(EvaluationOutcome::simple(
            Decision::Allow,
            "longline: no command".to_string(),
        )),
        Invocation::Shell {
            command: Some(command),
            cwd,
            session_id,
        } => evaluate_shell_command(ShellEvaluationRequest {
            rules: &final_config.rules,
            home,
            cwd: cwd.as_deref().unwrap_or(""),
            command: &command,
            session_id,
            ask_on_deny: options.ask_on_deny,
            ask_ai: options.ask_ai || options.ask_ai_lenient,
            ask_ai_lenient: options.ask_ai_lenient,
            project_ai_prompt: final_config.project_ai_prompt.as_deref(),
        }),
        Invocation::ReadPath {
            tool_name: _,
            path: None,
            cwd: _,
            session_id: _,
        } => Ok(EvaluationOutcome::simple(
            Decision::Allow,
            "longline: Read tool (no path)".to_string(),
        )),
        Invocation::ReadPath {
            tool_name,
            path: Some(path),
            cwd: _,
            session_id: _,
        }
        | Invocation::SearchPath {
            tool_name,
            path: Some(path),
            cwd: _,
            session_id: _,
        } => Ok(evaluate_path(&tool_name, &path)),
        Invocation::SearchPath {
            tool_name,
            path: None,
            cwd: _,
            session_id: _,
        } => Ok(EvaluationOutcome::simple(
            Decision::Allow,
            format!("longline: {tool_name} allowed (no path)"),
        )),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl Invocation {
    fn cwd(&self) -> Option<&str> {
        match self {
            Self::Shell { cwd, .. } | Self::ReadPath { cwd, .. } | Self::SearchPath { cwd, .. } => {
                cwd.as_deref()
            }
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl EvaluationOutcome {
    fn simple(decision: Decision, reason: String) -> Self {
        Self {
            decision,
            reason,
            log_reason: None,
            matched_rules: vec![],
            parse_ok: true,
            original_decision: None,
            overridden: false,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn evaluate_path(tool_name: &str, path: &str) -> EvaluationOutcome {
    for pattern in SENSITIVE_PATH_PATTERNS {
        if path.contains(pattern) {
            return EvaluationOutcome::simple(
                Decision::Ask,
                format!("longline: {tool_name} sensitive path ({pattern}): {path}"),
            );
        }
    }

    for exact in SENSITIVE_EXACT_PATHS {
        if path == *exact {
            return EvaluationOutcome::simple(
                Decision::Ask,
                format!("longline: {tool_name} sensitive path: {path}"),
            );
        }
    }

    EvaluationOutcome::simple(
        Decision::Allow,
        format!("longline: {tool_name} allowed: {path}"),
    )
}

#[cfg_attr(not(test), allow(dead_code))]
struct ShellEvaluationRequest<'a> {
    rules: &'a policy::RulesConfig,
    home: &'a Path,
    cwd: &'a str,
    command: &'a str,
    session_id: Option<String>,
    ask_on_deny: bool,
    ask_ai: bool,
    ask_ai_lenient: bool,
    project_ai_prompt: Option<&'a str>,
}

#[cfg_attr(not(test), allow(dead_code))]
fn evaluate_shell_command(
    request: ShellEvaluationRequest<'_>,
) -> Result<EvaluationOutcome, EvaluationError> {
    let parse_result = parser::parse(request.command);
    evaluate_shell_command_with_parse_result(request, parse_result)
}

#[cfg_attr(not(test), allow(dead_code))]
fn evaluate_shell_command_with_parse_result(
    request: ShellEvaluationRequest<'_>,
    parse_result: Result<parser::Statement, String>,
) -> Result<EvaluationOutcome, EvaluationError> {
    let stmt = match parse_result {
        Ok(stmt) => stmt,
        Err(e) => {
            let log_reason = Some(format!("Parse error: {e}"));
            let entry = logger::make_entry(
                "Bash",
                request.cwd,
                request.command,
                Decision::Ask,
                vec![],
                log_reason.clone(),
                false,
                request.session_id,
            );
            log_decision_for_home(&entry, request.home);

            return Ok(EvaluationOutcome {
                decision: Decision::Ask,
                reason: format!("Failed to parse bash command: {e}"),
                log_reason,
                matched_rules: vec![],
                parse_ok: false,
                original_decision: None,
                overridden: false,
            });
        }
    };

    let result = policy::evaluate(request.rules, &stmt);
    let overridden = request.ask_on_deny && result.decision == Decision::Deny;
    let final_decision = if overridden {
        Decision::Ask
    } else {
        result.decision
    };

    // Mirrors the legacy CLI hook flow until Task 7 removes that path.
    let (final_decision, ai_reason) = if request.ask_ai && final_decision == Decision::Ask {
        let ai_config = ai_judge::load_config();
        let ai_cwd = if request.cwd.is_empty() {
            "."
        } else {
            request.cwd
        };
        let extracted =
            ai_judge::extract_code(request.command, &stmt, ai_cwd, &ai_config).or_else(|| {
                parser::wrappers::extract_inner_commands(&stmt)
                    .iter()
                    .find_map(|inner_stmt| {
                        ai_judge::extract_code(request.command, inner_stmt, ai_cwd, &ai_config)
                    })
            });

        match extracted {
            Some(extracted) => {
                let (ai_decision, reason) = if request.ask_ai_lenient {
                    ai_judge::evaluate_lenient(
                        &ai_config,
                        &extracted.language,
                        &extracted.code,
                        ai_cwd,
                        extracted.context.as_deref(),
                        request.project_ai_prompt,
                    )
                } else {
                    ai_judge::evaluate(
                        &ai_config,
                        &extracted.language,
                        &extracted.code,
                        ai_cwd,
                        extracted.context.as_deref(),
                        request.project_ai_prompt,
                    )
                };
                if request.project_ai_prompt.is_some() {
                    eprintln!(
                        "longline: ai-judge evaluated {} code (project prompt): {ai_decision}",
                        extracted.language
                    );
                } else if request.ask_ai_lenient {
                    eprintln!(
                        "longline: ai-judge evaluated {} code (lenient): {ai_decision}",
                        extracted.language
                    );
                } else {
                    eprintln!(
                        "longline: ai-judge evaluated {} code: {ai_decision}",
                        extracted.language
                    );
                }
                (ai_decision, Some(reason))
            }
            None => (final_decision, None),
        }
    } else {
        (final_decision, None)
    };

    let reason = if let Some(ref ai_reason) = ai_reason {
        format!("longline: {}", ai_reason)
    } else {
        match final_decision {
            Decision::Allow => format!("longline: {}", result.reason),
            Decision::Ask | Decision::Deny if overridden => {
                format!("[overridden] {}", format_reason(&result))
            }
            Decision::Ask | Decision::Deny => format_reason(&result),
        }
    };
    let log_reason = if let Some(ref ai_reason) = ai_reason {
        Some(ai_reason.clone())
    } else if result.reason.is_empty() {
        None
    } else {
        Some(result.reason.clone())
    };
    let matched_rules: Vec<String> = result.rule_id.clone().into_iter().collect();
    let mut entry = logger::make_entry(
        "Bash",
        request.cwd,
        request.command,
        final_decision,
        matched_rules.clone(),
        log_reason.clone(),
        true,
        request.session_id,
    );
    if overridden {
        entry.original_decision = Some(result.decision);
        entry.overridden = true;
    }
    log_decision_for_home(&entry, request.home);

    Ok(EvaluationOutcome {
        decision: final_decision,
        reason,
        log_reason,
        matched_rules,
        parse_ok: true,
        original_decision: overridden.then_some(result.decision),
        overridden,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn format_reason(result: &PolicyResult) -> String {
    match &result.rule_id {
        Some(id) => format!("[{id}] {}", result.reason),
        None => result.reason.clone(),
    }
}

fn log_decision_for_home(entry: &logger::LogEntry, home: &Path) {
    let env_home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    if env_home.as_deref() == Some(home) {
        logger::log_decision(entry);
    } else {
        logger::log_decision_to_home(entry, home);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    use serde_json::Value;

    fn base_config() -> policy::RulesConfig {
        policy::load_embedded_rules().expect("embedded rules should load")
    }

    fn eval(invocation: Invocation) -> EvaluationOutcome {
        let home = tempfile::TempDir::new().unwrap();
        evaluate_invocation(
            base_config(),
            home.path(),
            invocation,
            EvaluationOptions::default(),
        )
        .expect("evaluation should succeed")
    }

    fn shell_invocation(command: &str) -> Invocation {
        Invocation::Shell {
            command: Some(command.to_string()),
            cwd: Some("/tmp".to_string()),
            session_id: Some("session-1".to_string()),
        }
    }

    fn log_path(home: &tempfile::TempDir) -> std::path::PathBuf {
        home.path().join(".claude/hooks-logs/longline.jsonl")
    }

    fn last_log_entry(home: &tempfile::TempDir) -> Value {
        let contents = std::fs::read_to_string(log_path(home)).unwrap();
        let line = contents.lines().last().unwrap();
        serde_json::from_str(line).unwrap()
    }

    struct HomeEnvGuard {
        original_home: Option<OsString>,
    }

    impl HomeEnvGuard {
        fn set(home: &Path) -> Self {
            let original_home = std::env::var_os("HOME");
            std::env::set_var("HOME", home);
            Self { original_home }
        }
    }

    impl Drop for HomeEnvGuard {
        fn drop(&mut self) {
            match &self.original_home {
                Some(home) => std::env::set_var("HOME", home),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    struct FakeAiJudge {
        home: tempfile::TempDir,
        called_path: PathBuf,
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_fake_ai_judge<R>(response: &str, f: impl FnOnce(&FakeAiJudge) -> R) -> R {
        let _lock = env_lock().lock().unwrap();
        let home = tempfile::TempDir::new().unwrap();
        let called_path = home.path().join("fake-judge-called.txt");
        let capture_path = home.path().join("fake-judge-prompt.txt");
        let script_path = home.path().join("fake-judge.sh");
        let script = format!(
            "#!/bin/sh\nprintf 'called\\n' >> \"{}\"\nprintf '%s' \"$@\" > \"{}\"\nprintf '%s\\n' '{}'\n",
            called_path.display(),
            capture_path.display(),
            response
        );
        std::fs::write(&script_path, script).unwrap();
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();

        let config_dir = home.path().join(".config").join("longline");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("ai-judge.yaml"),
            format!("command: {}\ntimeout: 10\n", script_path.display()),
        )
        .unwrap();

        let _home = HomeEnvGuard::set(home.path());
        f(&FakeAiJudge { home, called_path })
    }

    fn evaluate_shell_with_options(
        home: &Path,
        command: &str,
        options: EvaluationOptions,
    ) -> EvaluationOutcome {
        evaluate_invocation(
            base_config(),
            home,
            Invocation::Shell {
                command: Some(command.to_string()),
                cwd: Some(home.display().to_string()),
                session_id: Some("session-ai".to_string()),
            },
            options,
        )
        .expect("evaluation should succeed")
    }

    #[test]
    fn test_evaluate_missing_shell_command_allows_without_log() {
        let home = tempfile::TempDir::new().unwrap();
        let outcome = evaluate_invocation(
            base_config(),
            home.path(),
            Invocation::Shell {
                command: None,
                cwd: Some("/tmp".to_string()),
                session_id: Some("session-1".to_string()),
            },
            EvaluationOptions::default(),
        )
        .unwrap();

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.reason, "longline: no command");
        assert_eq!(outcome.log_reason, None);
        assert_eq!(outcome.matched_rules, Vec::<String>::new());
        assert!(outcome.parse_ok);
        assert_eq!(outcome.original_decision, None);
        assert!(!outcome.overridden);
        assert!(!home
            .path()
            .join(".claude/hooks-logs/longline.jsonl")
            .exists());
    }

    #[test]
    fn test_evaluate_shell_allow_logs_current_fields() {
        let home = tempfile::TempDir::new().unwrap();
        let outcome = evaluate_invocation(
            base_config(),
            home.path(),
            shell_invocation("ls -la"),
            EvaluationOptions::default(),
        )
        .unwrap();

        assert_eq!(outcome.decision, Decision::Allow);
        assert!(outcome.reason.starts_with("longline: "));
        assert_eq!(
            outcome.log_reason,
            outcome
                .reason
                .strip_prefix("longline: ")
                .map(str::to_string)
        );
        assert_eq!(outcome.matched_rules, Vec::<String>::new());
        assert!(outcome.parse_ok);
        assert_eq!(outcome.original_decision, None);
        assert!(!outcome.overridden);

        let entry = last_log_entry(&home);
        assert_eq!(entry["tool"], "Bash");
        assert_eq!(entry["command"], "ls -la");
        assert_eq!(entry["decision"], "allow");
        assert_eq!(entry["parse_ok"], true);
        assert_eq!(entry["session_id"], "session-1");
    }

    #[test]
    fn test_evaluate_shell_parse_error_logs_current_fields() {
        let home = tempfile::TempDir::new().unwrap();
        let command = "parse-error-command";
        let config = base_config();

        let outcome = evaluate_shell_command_with_parse_result(
            ShellEvaluationRequest {
                rules: &config,
                home: home.path(),
                cwd: "/tmp",
                command,
                session_id: Some("session-1".to_string()),
                ask_on_deny: false,
                ask_ai: false,
                ask_ai_lenient: false,
                project_ai_prompt: None,
            },
            Err("synthetic parser failure".to_string()),
        )
        .unwrap();

        assert_eq!(outcome.decision, Decision::Ask);
        assert!(
            outcome.reason.starts_with("Failed to parse bash command: "),
            "{}",
            outcome.reason
        );
        assert!(!outcome.parse_ok);

        let entry = last_log_entry(&home);
        assert_eq!(entry["tool"], "Bash");
        assert_eq!(entry["command"], command);
        assert_eq!(entry["decision"], "ask");
        assert_eq!(entry["parse_ok"], false);
        assert!(
            entry["reason"]
                .as_str()
                .is_some_and(|reason| reason.starts_with("Parse error: ")),
            "{entry:?}"
        );
    }

    #[test]
    fn test_evaluate_shell_deny_returns_rule_reason_and_matched_rule() {
        let outcome = eval(shell_invocation("rm -rf /"));

        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome.reason.starts_with('['), "{}", outcome.reason);
        assert!(outcome.reason.contains(']'), "{}", outcome.reason);
        assert!(!outcome.matched_rules.is_empty());
        assert!(outcome.log_reason.as_deref().is_some_and(|r| !r.is_empty()));
        assert!(outcome.parse_ok);
        assert_eq!(outcome.original_decision, None);
        assert!(!outcome.overridden);
    }

    #[test]
    fn test_evaluate_shell_ask_returns_ask_reason() {
        let outcome = eval(shell_invocation("chmod 777 /tmp/f"));

        assert_eq!(outcome.decision, Decision::Ask);
        assert!(!outcome.reason.is_empty());
        assert!(outcome.log_reason.as_deref().is_some_and(|r| !r.is_empty()));
        assert!(!outcome.matched_rules.is_empty());
        assert!(outcome.parse_ok);
        assert_eq!(outcome.original_decision, None);
        assert!(!outcome.overridden);
    }

    #[test]
    fn test_evaluate_shell_opaque_statement_uses_policy_ask_not_parse_error() {
        let home = tempfile::TempDir::new().unwrap();
        assert!(matches!(
            parser::parse("if then").unwrap(),
            parser::Statement::Opaque(_)
        ));

        let outcome = evaluate_invocation(
            base_config(),
            home.path(),
            shell_invocation("if then"),
            EvaluationOptions::default(),
        )
        .unwrap();

        assert_eq!(outcome.decision, Decision::Ask);
        assert_eq!(outcome.reason, "Unrecognized command structure");
        assert_eq!(
            outcome.log_reason.as_deref(),
            Some("Unrecognized command structure")
        );
        assert_eq!(outcome.matched_rules, Vec::<String>::new());
        assert!(outcome.parse_ok);
        assert_eq!(outcome.original_decision, None);
        assert!(!outcome.overridden);
    }

    #[test]
    fn test_evaluate_shell_ask_on_deny_logs_override_fields() {
        let home = tempfile::TempDir::new().unwrap();
        let outcome = evaluate_invocation(
            base_config(),
            home.path(),
            shell_invocation("rm -rf /"),
            EvaluationOptions {
                ask_on_deny: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(outcome.decision, Decision::Ask);
        assert_eq!(outcome.original_decision, Some(Decision::Deny));
        assert!(outcome.overridden);
        assert!(
            outcome.reason.starts_with("[overridden] "),
            "{}",
            outcome.reason
        );
        assert!(!outcome.matched_rules.is_empty());
        assert!(outcome.log_reason.as_deref().is_some_and(|r| !r.is_empty()));
        assert!(outcome.parse_ok);

        let entry = last_log_entry(&home);
        assert_eq!(entry["decision"], "ask");
        assert_eq!(entry["original_decision"], "deny");
        assert_eq!(entry["overridden"], true);
    }

    #[test]
    fn test_evaluate_shell_ask_ai_lenient_alone_invokes_ai_judge() {
        with_fake_ai_judge("ALLOW: evaluator fake judge allowed", |fake| {
            let outcome = evaluate_shell_with_options(
                fake.home.path(),
                r#"python -c "print(1)""#,
                EvaluationOptions {
                    ask_ai: false,
                    ask_ai_lenient: true,
                    ..Default::default()
                },
            );

            assert_eq!(outcome.decision, Decision::Allow);
            assert_eq!(
                outcome.reason,
                "longline: ALLOW: evaluator fake judge allowed"
            );
            assert!(
                fake.called_path.exists(),
                "lenient-only option should invoke fake AI judge"
            );
        });
    }

    #[test]
    fn test_evaluate_shell_ai_reason_sets_output_and_log_reason() {
        with_fake_ai_judge("ASK: evaluator fake judge needs review", |fake| {
            let outcome = evaluate_shell_with_options(
                fake.home.path(),
                r#"python -c "print(1)""#,
                EvaluationOptions {
                    ask_ai: true,
                    ..Default::default()
                },
            );

            assert_eq!(outcome.decision, Decision::Ask);
            assert_eq!(
                outcome.reason,
                "longline: ASK: evaluator fake judge needs review"
            );
            assert_eq!(
                outcome.log_reason.as_deref(),
                Some("ASK: evaluator fake judge needs review")
            );

            let entry = last_log_entry(&fake.home);
            assert_eq!(entry["decision"], "ask");
            assert_eq!(entry["reason"], "ASK: evaluator fake judge needs review");
        });
    }

    #[test]
    fn test_evaluate_shell_ai_no_extraction_keeps_policy_ask() {
        with_fake_ai_judge("ALLOW: evaluator fake judge should not run", |fake| {
            let outcome = evaluate_shell_with_options(
                fake.home.path(),
                "chmod 777 /tmp/f",
                EvaluationOptions {
                    ask_ai: true,
                    ..Default::default()
                },
            );

            assert_eq!(outcome.decision, Decision::Ask);
            assert_ne!(
                outcome.reason,
                "longline: ALLOW: evaluator fake judge should not run"
            );
            assert_ne!(
                outcome.log_reason.as_deref(),
                Some("ALLOW: evaluator fake judge should not run")
            );
            assert!(
                !fake.called_path.exists(),
                "AI judge command must not run when no code is extracted"
            );
        });
    }

    #[test]
    fn test_evaluate_non_shell_flows_do_not_invoke_ai_judge() {
        with_fake_ai_judge("ALLOW: evaluator fake judge should not run", |fake| {
            let missing = evaluate_invocation(
                base_config(),
                fake.home.path(),
                Invocation::Shell {
                    command: None,
                    cwd: Some(fake.home.path().display().to_string()),
                    session_id: Some("session-ai".to_string()),
                },
                EvaluationOptions {
                    ask_ai: true,
                    ask_ai_lenient: true,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(missing.decision, Decision::Allow);

            let path = evaluate_invocation(
                base_config(),
                fake.home.path(),
                Invocation::ReadPath {
                    tool_name: "Read".to_string(),
                    path: Some("/home/user/.ssh/id_rsa".to_string()),
                    cwd: Some(fake.home.path().display().to_string()),
                    session_id: Some("session-ai".to_string()),
                },
                EvaluationOptions {
                    ask_ai: true,
                    ask_ai_lenient: true,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(path.decision, Decision::Ask);
            assert!(
                !fake.called_path.exists(),
                "AI judge command must not run for missing command or path flows"
            );
        });
    }

    #[test]
    fn test_evaluate_sensitive_read_path_asks_without_log() {
        let home = tempfile::TempDir::new().unwrap();
        let outcome = evaluate_invocation(
            base_config(),
            home.path(),
            Invocation::ReadPath {
                tool_name: "Read".to_string(),
                path: Some("/home/user/.ssh/id_rsa".to_string()),
                cwd: Some("/tmp".to_string()),
                session_id: Some("session-1".to_string()),
            },
            EvaluationOptions::default(),
        )
        .unwrap();

        assert_eq!(outcome.decision, Decision::Ask);
        assert_eq!(
            outcome.reason,
            "longline: Read sensitive path (/.ssh/): /home/user/.ssh/id_rsa"
        );
        assert!(!home
            .path()
            .join(".claude/hooks-logs/longline.jsonl")
            .exists());
    }

    #[test]
    fn test_evaluate_safe_read_path_allows_without_log() {
        let outcome = eval(Invocation::ReadPath {
            tool_name: "Read".to_string(),
            path: Some("src/main.rs".to_string()),
            cwd: Some("/tmp".to_string()),
            session_id: Some("session-1".to_string()),
        });

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.reason, "longline: Read allowed: src/main.rs");
    }

    #[test]
    fn test_evaluate_read_no_path_allows_with_current_reason() {
        let outcome = eval(Invocation::ReadPath {
            tool_name: "Read".to_string(),
            path: None,
            cwd: Some("/tmp".to_string()),
            session_id: Some("session-1".to_string()),
        });

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.reason, "longline: Read tool (no path)");
    }

    #[test]
    fn test_evaluate_grep_no_path_allows_with_current_reason() {
        let outcome = eval(Invocation::SearchPath {
            tool_name: "Grep".to_string(),
            path: None,
            cwd: Some("/tmp".to_string()),
            session_id: Some("session-1".to_string()),
        });

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.reason, "longline: Grep allowed (no path)");
    }
}
