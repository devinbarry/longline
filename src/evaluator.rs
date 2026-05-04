use std::path::{Path, PathBuf};

use crate::logger;
use longline::ai_judge;
use longline::domain::Decision;
use longline::domain::PolicyResult;
use longline::parser;
use longline::parser::{ArgMeta, ListOp, Statement};
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

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn evaluate_invocation(
    final_config: longline::config::FinalConfig,
    audit_log_path: &Path,
    invocation: Invocation,
    options: EvaluationOptions,
    runtime: &'static str,
) -> EvaluationOutcome {
    match invocation {
        Invocation::Shell {
            command: None,
            cwd: _,
            session_id: _,
        } => EvaluationOutcome::simple(Decision::Allow, "longline: no command".to_string()),
        Invocation::Shell {
            command: Some(command),
            cwd,
            session_id,
        } => evaluate_shell_command(ShellEvaluationRequest {
            rules: &final_config.rules,
            audit_log_path,
            cwd: cwd.as_deref().unwrap_or(""),
            command: &command,
            session_id,
            ask_on_deny: options.ask_on_deny,
            ask_ai: options.ask_ai || options.ask_ai_lenient,
            ask_ai_lenient: options.ask_ai_lenient,
            project_ai_prompt: final_config.project_ai_prompt.as_deref(),
            runtime,
        }),
        Invocation::ReadPath {
            tool_name: _,
            path: None,
            cwd: _,
            session_id: _,
        } => {
            EvaluationOutcome::simple(Decision::Allow, "longline: Read tool (no path)".to_string())
        }
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
        } => evaluate_path(&tool_name, &path),
        Invocation::SearchPath {
            tool_name,
            path: None,
            cwd: _,
            session_id: _,
        } => EvaluationOutcome::simple(
            Decision::Allow,
            format!("longline: {tool_name} allowed (no path)"),
        ),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl Invocation {
    /// Returns the cwd if it's a non-empty string. Empty strings are treated
    /// as "no cwd" so a `cwd: ""` payload from a runtime cannot be silently
    /// resolved against the longline process's own cwd by any downstream
    /// consumer (project-config discovery, etc.).
    pub(crate) fn cwd(&self) -> Option<&str> {
        match self {
            Self::Shell { cwd, .. } | Self::ReadPath { cwd, .. } | Self::SearchPath { cwd, .. } => {
                cwd.as_deref().filter(|s| !s.is_empty())
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn tool_name(&self) -> &str {
        match self {
            Self::Shell { .. } => "Bash",
            Self::ReadPath { tool_name, .. } | Self::SearchPath { tool_name, .. } => tool_name,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn command_or_empty(&self) -> &str {
        match self {
            Self::Shell { command, .. } => command.as_deref().unwrap_or(""),
            _ => "",
        }
    }

    #[allow(dead_code)]
    pub(crate) fn session_id(&self) -> Option<&str> {
        match self {
            Self::Shell { session_id, .. }
            | Self::ReadPath { session_id, .. }
            | Self::SearchPath { session_id, .. } => session_id.as_deref(),
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
    audit_log_path: &'a Path,
    cwd: &'a str,
    command: &'a str,
    session_id: Option<String>,
    ask_on_deny: bool,
    ask_ai: bool,
    ask_ai_lenient: bool,
    project_ai_prompt: Option<&'a str>,
    runtime: &'static str,
}

#[cfg_attr(not(test), allow(dead_code))]
fn evaluate_shell_command(request: ShellEvaluationRequest<'_>) -> EvaluationOutcome {
    let parse_result = parser::parse(request.command);
    evaluate_shell_command_with_parse_result(request, parse_result)
}

#[cfg_attr(not(test), allow(dead_code))]
fn evaluate_shell_command_with_parse_result(
    request: ShellEvaluationRequest<'_>,
    parse_result: Result<parser::Statement, String>,
) -> EvaluationOutcome {
    let stmt = match parse_result {
        Ok(stmt) => stmt,
        Err(e) => {
            let log_reason = Some(format!("Parse error: {e}"));
            let entry = logger::make_entry_with_runtime(
                request.runtime,
                "Bash",
                request.cwd,
                request.command,
                Decision::Ask,
                vec![],
                log_reason.clone(),
                false,
                request.session_id,
            );
            logger::log_decision_to(&entry, request.audit_log_path);

            return EvaluationOutcome {
                decision: Decision::Ask,
                reason: format!("Failed to parse bash command: {e}"),
                log_reason,
                matched_rules: vec![],
                parse_ok: false,
                original_decision: None,
                overridden: false,
            };
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
    let (final_decision, ai_reason) =
        if request.ask_ai && final_decision == Decision::Ask && !request.cwd.is_empty() {
            // Empty cwd skips AI extraction entirely. Earlier versions
            // substituted "." here, but that caused read_safe_code_file and
            // effective_cwd_for_extract to canonicalize against the longline
            // process's own cwd — a real leak when a runtime sends `cwd: ""`
            // (Codex). Falling through preserves the original policy ask
            // without consulting any path the runtime didn't authorize.
            let ai_config = ai_judge::load_config();
            let extracted_with_cwd =
                extract_code_with_cwd_following(request.command, &stmt, request.cwd, &ai_config);

            match extracted_with_cwd {
                Some((extracted, effective_cwd)) => {
                    let ai_cwd = effective_cwd.as_str();
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
    let mut entry = logger::make_entry_with_runtime(
        request.runtime,
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
    logger::log_decision_to(&entry, request.audit_log_path);

    EvaluationOutcome {
        decision: final_decision,
        reason,
        log_reason,
        matched_rules,
        parse_ok: true,
        original_decision: overridden.then_some(result.decision),
        overridden,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn format_reason(result: &PolicyResult) -> String {
    match &result.rule_id {
        Some(id) => format!("[{id}] {}", result.reason),
        None => result.reason.clone(),
    }
}

/// Wire-in helper: composes `effective_cwd_for_extract` with
/// `ai_judge::extract_code` (and the wrapper-unwrap fallback) so the
/// `--ask-ai` branch in `evaluate_shell_command` is a single function
/// call. Centralising the plumbing means the integration test exercises
/// the exact production path rather than re-composing it by hand — a
/// hand-mirror would let a `raw_cwd` vs `effective_cwd` typo regress
/// silently.
///
/// Returns `Some((extracted_code, effective_cwd))` so callers can reuse
/// the same effective cwd when handing the extracted code to the AI
/// evaluator. Returns `None` when no script can be extracted.
#[cfg_attr(not(test), allow(dead_code))]
fn extract_code_with_cwd_following(
    raw_command: &str,
    stmt: &Statement,
    raw_cwd: &str,
    config: &ai_judge::AiJudgeConfig,
) -> Option<(ai_judge::ExtractedCode, String)> {
    let effective_cwd = effective_cwd_for_extract(stmt, raw_cwd);
    let extracted =
        ai_judge::extract_code(raw_command, stmt, &effective_cwd, config).or_else(|| {
            parser::wrappers::extract_inner_commands(stmt)
                .iter()
                .find_map(|inner| {
                    ai_judge::extract_code(raw_command, inner, &effective_cwd, config)
                })
        });
    extracted.map(|ec| (ec, effective_cwd))
}

/// For `cd <literal-path> && <next>` shapes, return the canonicalised
/// post-cd directory so the AI judge's script extractor can resolve
/// relative paths in `<next>`. For every other shape returns
/// `cwd.to_string()` unchanged.
///
/// **Documented limitation — first `cd` only.** Only the `cd` at the
/// head of the List is honored. `cd X && cd Y && cmd` updates the cwd
/// to `X`, not `Y`; subsequent `cd`s within the same List are ignored.
/// This diverges from real shell semantics but matches the design's
/// "first && only" scope (see
/// `docs/plans/2026-05-02-ai-judge-module-and-cd-following-design.md`).
/// If real cases for chained-cd composition show up later, extend the
/// helper to walk `list.rest` and accumulate cwd updates.
///
/// Confines the new cwd to `$HOME` or `/tmp`/`$TMPDIR` so a `cd /etc &&
/// cat shadow.py` style construction can't widen the existing
/// `read_safe_code_file` sandbox. Variables, command substitutions,
/// subshells, and `cd` after the first `&&` are all rejected.
///
/// **Documented exclusions — narrower than real shell.** The following
/// shapes also fall back to the original cwd, even though a real shell
/// would honour them. Each is rare enough in agent-generated commands
/// that broadening support has not been justified by real misses; the
/// list is recorded here so future contributors can extend deliberately
/// rather than treat the gaps as bugs:
///   - **Backslash-escaped paths**: `cd My\ Repo && …` — `tree-sitter-
///     bash` keeps backslash-escapes inside a bareword, so the arg
///     reaches `resolve_cd_target` as `ArgMeta::PlainWord` with text
///     `"My\ Repo"` (backslash literal). The arg passes the meta check;
///     the fall-back happens one step later when `std::fs::canonicalize`
///     is asked to resolve a path containing a literal backslash and
///     fails. Implication for future contributors: broadening support
///     for escape-shell-quoted paths means an unescape pass before
///     `canonicalize`, NOT changing the meta-allowlist. Quoted paths
///     without escapes (`cd "My Repo"`, `cd 'My Repo'`) ARE honored —
///     they reach the helper as `SafeString` / `RawString` with the
///     space already literal.
///   - **`cd` with redirects**: `cd repo >/dev/null && …` — rejected by
///     the `!cmd.redirects.is_empty()` guard.
///   - **`$expansions` / `$(substitutions)`**: `cd $REPO && …`,
///     `cd $(pwd) && …` reach the helper as `ArgMeta::UnsafeString` and
///     are rejected by the meta-allowlist. (This is the case that
///     `UnsafeString` was actually built for; backslash-escapes are a
///     separate case as noted above.)
///
/// **Non-adversarial sandbox assumption.** The `is_under_safe_root`
/// check canonicalises the cd target before accepting it, but
/// `read_safe_code_file` re-canonicalises later when it actually opens
/// a file. A concurrent rename or symlink swap between the two checks
/// could in principle let the second canonicalize land somewhere the
/// first would have rejected. The project's threat model is dev speed,
/// not adversarial AI containment, so this race is not patched. Move to
/// descriptor-based validation only if that threat model changes.
#[cfg_attr(not(test), allow(dead_code))]
fn effective_cwd_for_extract(stmt: &Statement, cwd: &str) -> String {
    let Statement::List(list) = stmt else {
        return cwd.to_string();
    };
    let Statement::SimpleCommand(cmd) = list.first.as_ref() else {
        return cwd.to_string();
    };
    if cmd.name.as_deref() != Some("cd") {
        return cwd.to_string();
    }
    if !cmd.redirects.is_empty() {
        return cwd.to_string();
    }
    if cmd.argv.len() != 1 {
        return cwd.to_string();
    }
    let Some((ListOp::And, _)) = list.rest.first() else {
        return cwd.to_string();
    };

    let Some(resolved) = resolve_cd_target(&cmd.argv[0], cwd) else {
        return cwd.to_string();
    };
    if !is_under_safe_root(&resolved) {
        return cwd.to_string();
    }
    resolved.to_string_lossy().to_string()
}

#[cfg_attr(not(test), allow(dead_code))]
fn resolve_cd_target(arg: &parser::Arg, cwd: &str) -> Option<PathBuf> {
    // Only literal forms — PlainWord (cd subdir), RawString ('cd subdir'),
    // SafeString ("cd subdir" with no escapes/expansions). UnsafeString
    // covers $expansions, $(substitutions), concatenations, and
    // brace/arithmetic forms; all rejected so `cd $REPO && cmd` and
    // `cd $(pwd) && cmd` fall back to the original cwd.
    if !matches!(
        arg.meta,
        ArgMeta::PlainWord | ArgMeta::RawString | ArgMeta::SafeString
    ) {
        return None;
    }
    let expanded = expand_tilde(&arg.text)?;
    let candidate = if Path::new(&expanded).is_absolute() {
        PathBuf::from(expanded)
    } else {
        Path::new(cwd).join(expanded)
    };
    std::fs::canonicalize(candidate).ok()
}

/// Local copy of `expand_tilde` from `ai_judge::extract::fs` — that
/// helper is `pub(super)` and exposing it through the lib's public
/// surface for one consumer in the binary crate is more churn than
/// duplicating six lines.
#[cfg_attr(not(test), allow(dead_code))]
fn expand_tilde(path: &str) -> Option<String> {
    if path == "~" {
        return std::env::var("HOME").ok();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").ok()?;
        return Some(Path::new(&home).join(rest).to_string_lossy().to_string());
    }
    Some(path.to_string())
}

#[cfg_attr(not(test), allow(dead_code))]
fn is_under_safe_root(path: &Path) -> bool {
    if let Ok(home) = std::env::var("HOME") {
        if let Ok(home) = std::fs::canonicalize(home) {
            if path.starts_with(&home) {
                return true;
            }
        }
    }
    if path.starts_with("/tmp") {
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

    fn final_config(rules: policy::RulesConfig) -> longline::config::FinalConfig {
        longline::config::FinalConfig {
            rules,
            project_ai_prompt: None,
        }
    }

    fn eval(invocation: Invocation) -> EvaluationOutcome {
        let home = tempfile::TempDir::new().unwrap();
        let log_path = log_path(&home);
        evaluate_invocation(
            final_config(base_config()),
            &log_path,
            invocation,
            EvaluationOptions::default(),
            "claude",
        )
    }

    fn shell_invocation(command: &str) -> Invocation {
        Invocation::Shell {
            command: Some(command.to_string()),
            cwd: Some("/tmp".to_string()),
            session_id: Some("session-1".to_string()),
        }
    }

    fn log_path(home: &tempfile::TempDir) -> std::path::PathBuf {
        log_path_for_home(home.path())
    }

    fn log_path_for_home(home: &Path) -> std::path::PathBuf {
        home.join("longline-test.jsonl")
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
        let log_path = log_path_for_home(home);
        evaluate_invocation(
            final_config(base_config()),
            &log_path,
            Invocation::Shell {
                command: Some(command.to_string()),
                cwd: Some(home.display().to_string()),
                session_id: Some("session-ai".to_string()),
            },
            options,
            "claude",
        )
    }

    #[test]
    fn test_evaluate_missing_shell_command_allows_without_log() {
        let home = tempfile::TempDir::new().unwrap();
        let log_path = log_path(&home);
        let outcome = evaluate_invocation(
            final_config(base_config()),
            &log_path,
            Invocation::Shell {
                command: None,
                cwd: Some("/tmp".to_string()),
                session_id: Some("session-1".to_string()),
            },
            EvaluationOptions::default(),
            "claude",
        );

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.reason, "longline: no command");
        assert_eq!(outcome.log_reason, None);
        assert_eq!(outcome.matched_rules, Vec::<String>::new());
        assert!(outcome.parse_ok);
        assert_eq!(outcome.original_decision, None);
        assert!(!outcome.overridden);
        assert!(!log_path.exists());
    }

    #[test]
    fn test_evaluate_shell_allow_logs_current_fields() {
        let home = tempfile::TempDir::new().unwrap();
        let log_path = log_path(&home);
        let outcome = evaluate_invocation(
            final_config(base_config()),
            &log_path,
            shell_invocation("ls -la"),
            EvaluationOptions::default(),
            "claude",
        );

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
        let log_path = log_path(&home);
        let command = "parse-error-command";
        let config = base_config();

        let outcome = evaluate_shell_command_with_parse_result(
            ShellEvaluationRequest {
                rules: &config,
                audit_log_path: &log_path,
                cwd: "/tmp",
                command,
                session_id: Some("session-1".to_string()),
                ask_on_deny: false,
                ask_ai: false,
                ask_ai_lenient: false,
                project_ai_prompt: None,
                runtime: "claude",
            },
            Err("synthetic parser failure".to_string()),
        );

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
        let log_path = log_path(&home);
        assert!(matches!(
            parser::parse("if then").unwrap(),
            parser::Statement::Opaque(_)
        ));

        let outcome = evaluate_invocation(
            final_config(base_config()),
            &log_path,
            shell_invocation("if then"),
            EvaluationOptions::default(),
            "claude",
        );

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
        let log_path = log_path(&home);
        let outcome = evaluate_invocation(
            final_config(base_config()),
            &log_path,
            shell_invocation("rm -rf /"),
            EvaluationOptions {
                ask_on_deny: true,
                ..Default::default()
            },
            "claude",
        );

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
            let log_path = log_path(&fake.home);
            let missing = evaluate_invocation(
                final_config(base_config()),
                &log_path,
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
                "claude",
            );
            assert_eq!(missing.decision, Decision::Allow);

            let path = evaluate_invocation(
                final_config(base_config()),
                &log_path,
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
                "claude",
            );
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
        let log_path = log_path(&home);
        let outcome = evaluate_invocation(
            final_config(base_config()),
            &log_path,
            Invocation::ReadPath {
                tool_name: "Read".to_string(),
                path: Some("/home/user/.ssh/id_rsa".to_string()),
                cwd: Some("/tmp".to_string()),
                session_id: Some("session-1".to_string()),
            },
            EvaluationOptions::default(),
            "claude",
        );

        assert_eq!(outcome.decision, Decision::Ask);
        assert_eq!(
            outcome.reason,
            "longline: Read sensitive path (/.ssh/): /home/user/.ssh/id_rsa"
        );
        assert!(!log_path.exists());
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

    // ============================================================
    // effective_cwd_for_extract — `cd <literal> && cmd` cwd-following
    // (spec 2026-05-02)
    // ============================================================

    mod cd_following {
        use super::super::effective_cwd_for_extract;
        use longline::parser;
        use std::fs;
        use std::path::PathBuf;

        fn unique_root(name: &str) -> PathBuf {
            // Use the OS temp dir (`/tmp` on Linux, `$TMPDIR` /var/folders/…
            // on macOS) so fixtures land somewhere `is_under_safe_root`
            // accepts on every host. The previous CARGO_MANIFEST_DIR-based
            // location worked on developer machines (the repo is under
            // `$HOME`) but failed on the GitLab runner where checkouts live
            // under `/builds/...`, outside both `$HOME` and `$TMPDIR`.
            let dir = std::env::temp_dir()
                .join("longline-evaluator-cd")
                .join(name);
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            // canonicalize so comparisons match what effective_cwd_for_extract
            // returns (which canonicalises via std::fs::canonicalize).
            fs::canonicalize(dir).unwrap()
        }

        fn parsed(cmd: &str) -> parser::Statement {
            parser::parse(cmd).unwrap()
        }

        // ── Positive: cwd updated ──

        #[test]
        fn absolute_cd_under_tmp_updates_cwd() {
            let target = unique_root("abs-tmp");
            let cmd = format!("cd {} && python script.py", target.display());
            let stmt = parsed(&cmd);
            let result = effective_cwd_for_extract(&stmt, "/tmp");
            assert_eq!(result, target.to_string_lossy());
        }

        #[test]
        fn cd_under_repo_combines_with_module_extraction() {
            // Smoke check — just confirm cwd changes; the actual
            // extraction integration is exercised by Change A's tests.
            let target = unique_root("repo-combined");
            let cmd = format!("cd {} && uv run python -m tests.foo", target.display());
            let stmt = parsed(&cmd);
            let result = effective_cwd_for_extract(&stmt, "/tmp");
            assert_eq!(result, target.to_string_lossy());
        }

        #[test]
        fn tilde_cd_expands_to_home() {
            // We can't pre-create a deterministic dir under $HOME without
            // racing, so use $HOME itself which always exists and
            // canonicalises cleanly.
            let cmd = "cd ~ && python script.py";
            let stmt = parsed(cmd);
            let result = effective_cwd_for_extract(&stmt, "/tmp");
            let home = std::fs::canonicalize(std::env::var("HOME").unwrap())
                .unwrap()
                .to_string_lossy()
                .to_string();
            assert_eq!(result, home);
        }

        #[test]
        fn relative_cd_resolves_against_cwd() {
            let parent = unique_root("rel-parent");
            let sub = parent.join("sub");
            fs::create_dir_all(&sub).unwrap();
            let canonical_sub = fs::canonicalize(&sub).unwrap();
            let cmd = "cd sub && python script.py";
            let stmt = parsed(cmd);
            let result = effective_cwd_for_extract(&stmt, parent.to_str().unwrap());
            assert_eq!(result, canonical_sub.to_string_lossy());
        }

        #[test]
        fn trailing_slash_normalised_via_canonicalize() {
            let parent = unique_root("trailing-slash");
            let sub = parent.join("sub");
            fs::create_dir_all(&sub).unwrap();
            let canonical_sub = fs::canonicalize(&sub).unwrap();
            let cmd = "cd sub/ && python script.py";
            let stmt = parsed(cmd);
            let result = effective_cwd_for_extract(&stmt, parent.to_str().unwrap());
            assert_eq!(result, canonical_sub.to_string_lossy());
        }

        // ── Negative: cwd unchanged ──

        #[test]
        fn variable_cd_target_falls_back() {
            let cmd = "cd $REPO && python script.py";
            let stmt = parsed(cmd);
            let result = effective_cwd_for_extract(&stmt, "/tmp");
            assert_eq!(result, "/tmp");
        }

        #[test]
        fn semicolon_separator_falls_back() {
            // `cd /tmp; cmd` — not &&, so no cwd update.
            let cmd = "cd /tmp; python script.py";
            let stmt = parsed(cmd);
            let result = effective_cwd_for_extract(&stmt, "/var/tmp");
            assert_eq!(result, "/var/tmp");
        }

        #[test]
        fn subshell_cd_does_not_propagate() {
            // `(cd /tmp && cmd)` — outer is a Subshell, not a List
            // starting with cd. Falls back.
            let cmd = "(cd /tmp && python script.py)";
            let stmt = parsed(cmd);
            let result = effective_cwd_for_extract(&stmt, "/var/tmp");
            assert_eq!(result, "/var/tmp");
        }

        #[test]
        fn cd_not_first_in_list_falls_back() {
            // `cmd1 && cd /tmp && cmd2` — first stmt isn't cd, so we
            // don't crawl forward.
            let cmd = "echo go && cd /tmp && python script.py";
            let stmt = parsed(cmd);
            let result = effective_cwd_for_extract(&stmt, "/var/tmp");
            assert_eq!(result, "/var/tmp");
        }

        #[test]
        fn cd_outside_safe_root_falls_back() {
            // `/etc` exists and canonicalises, but is outside $HOME and
            // /tmp confinement → treated as suspicious → fall back.
            let cmd = "cd /etc && python script.py";
            let stmt = parsed(cmd);
            let result = effective_cwd_for_extract(&stmt, "/tmp");
            assert_eq!(result, "/tmp");
        }

        #[test]
        fn nonexistent_cd_target_falls_back() {
            let cmd = "cd /tmp/this-path-does-not-exist-xyzzy && python script.py";
            let stmt = parsed(cmd);
            let result = effective_cwd_for_extract(&stmt, "/tmp");
            assert_eq!(result, "/tmp");
        }

        #[test]
        fn multi_arg_cd_falls_back() {
            // Malformed: `cd /tmp/foo /tmp/bar && cmd` — argv.len() != 1.
            let cmd = "cd /tmp /var && python script.py";
            let stmt = parsed(cmd);
            let result = effective_cwd_for_extract(&stmt, "/var/tmp");
            assert_eq!(result, "/var/tmp");
        }

        // ── Integration: A+B composition through the wire-in pattern ──

        #[test]
        fn integration_cd_then_module_extract_returns_fixture_body() {
            // Stages a real fixture under /tmp, then drives the production
            // wire-in helper `extract_code_with_cwd_following` directly —
            // the same helper `evaluate_shell_command` calls in its
            // `--ask-ai` branch. Calling the helper (rather than
            // re-composing the steps by hand) means a `raw_cwd` vs
            // `effective_cwd` typo regression in the wire-in is caught
            // here.
            //
            // Asserts (a) the returned effective cwd is the canonicalised
            // cd target and (b) the returned `ExtractedCode.code` body is
            // the fixture file — proving Change A (module resolution) and
            // Change B (cwd-following) compose end-to-end. We do NOT call
            // evaluate_shell_command directly because the --ask-ai branch
            // would invoke the real AI evaluator (codex exec), which we
            // cannot and should not run from a unit test.
            use super::super::extract_code_with_cwd_following;
            use longline::ai_judge;

            let dir = PathBuf::from("/tmp").join("longline-cd-int-test");
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("tests")).unwrap();
            fs::write(
                dir.join("tests").join("foo.py"),
                "print('integration body marker')\n",
            )
            .unwrap();
            let canonical_dir = fs::canonicalize(&dir).unwrap();

            let cmd = format!("cd {} && python -m tests.foo", canonical_dir.display());
            let stmt = parsed(&cmd);

            let ai_config = ai_judge::load_config();
            let result = extract_code_with_cwd_following(&cmd, &stmt, "/tmp", &ai_config);

            let (ec, returned_cwd) = result
                .expect("extract_code_with_cwd_following must resolve tests.foo via the wire-in");
            assert_eq!(
                returned_cwd,
                canonical_dir.to_string_lossy(),
                "wire-in must return the canonicalised cd target as the effective cwd"
            );
            assert_eq!(ec.language, "python");
            assert!(
                ec.code.contains("integration body marker"),
                "extracted body must be the fixture, got: {}",
                ec.code
            );

            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn integration_cd_then_bash_c_module_extract_via_wrapper_unwrap() {
            // Variant of the integration test above that forces extraction
            // through the helper's `or_else` wrapper-unwrap fallback path:
            // `bash -c '<inner>'` is not a python invocation itself, so
            // the direct `extract_code(stmt, ...)` call returns None and
            // the fallback walks `extract_inner_commands` to find the
            // synthesized inner `python -m tests.foo` Statement. If a
            // future regression passed `raw_cwd` instead of the post-cd
            // `effective_cwd` to the inner-command extract_code call, the
            // inner extraction would look under `/tmp` rather than the
            // staged fixture dir and this test would fail.
            use super::super::extract_code_with_cwd_following;
            use longline::ai_judge;

            let dir = PathBuf::from("/tmp").join("longline-cd-bashc-int-test");
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("tests")).unwrap();
            fs::write(
                dir.join("tests").join("foo.py"),
                "print('wrapper unwrap body marker')\n",
            )
            .unwrap();
            let canonical_dir = fs::canonicalize(&dir).unwrap();

            let cmd = format!(
                "cd {} && bash -c 'python -m tests.foo'",
                canonical_dir.display()
            );
            let stmt = parsed(&cmd);

            let ai_config = ai_judge::load_config();
            let result = extract_code_with_cwd_following(&cmd, &stmt, "/tmp", &ai_config);

            let (ec, returned_cwd) = result.expect(
                "wire-in's or_else wrapper-unwrap path must resolve tests.foo through bash -c",
            );
            assert_eq!(
                returned_cwd,
                canonical_dir.to_string_lossy(),
                "wire-in must return the canonicalised cd target even when extraction \
                 succeeds via the wrapper-unwrap fallback"
            );
            assert_eq!(ec.language, "python");
            assert!(
                ec.code.contains("wrapper unwrap body marker"),
                "extracted body must be the fixture, got: {}",
                ec.code
            );

            let _ = fs::remove_dir_all(&dir);
        }
    }
}
