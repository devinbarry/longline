use crate::ai_judge::home::expand_tilde_token;
use crate::ai_judge::orchestrator::{AttemptHandle, AttemptId, Clock, Event, Runner};
use crate::ai_judge::outcome::{classify, AttemptOutcome};
use crate::ai_judge::response::parse_output;
use std::fs::File;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// A provider = display name + parsed argv template. The prompt is appended as
/// the final arg at launch time (not stored here).
#[derive(Debug, Clone)]
pub struct Provider {
    pub name: String, // "codex" | "claude"
    pub argv: Vec<String>,
}

impl Provider {
    /// Parse a command string with shell quoting (shlex), then `~`-expand every
    /// token. Returns None when the string is empty/whitespace (absent) or
    /// shlex-unparseable (caller emits a config warning).
    pub fn parse(name: &str, command: &str) -> Option<Provider> {
        if command.trim().is_empty() {
            return None;
        }
        let parts = shlex::split(command)?; // None on unmatched quote
        if parts.is_empty() {
            return None;
        }
        let argv = parts.into_iter().map(|t| expand_tilde_token(&t)).collect();
        Some(Provider {
            name: name.to_string(),
            argv,
        })
    }
}

pub struct ProviderSet {
    pub providers: Vec<Provider>,
    pub warnings: Vec<String>,
    pub empty: bool,
}

/// Resolve the ordered provider set from the two config command strings.
/// codex is primary (index 0), claude the hedge. Empty string → absent (no
/// warning). Non-empty but malformed → absent + one warning. Empty resulting
/// set → `empty = true` (drives `no_providers`).
pub fn resolve_provider_set(command: &str, fallback_command: &str) -> ProviderSet {
    let mut providers = Vec::new();
    let mut warnings = Vec::new();
    for (name, cmd) in [("codex", command), ("claude", fallback_command)] {
        if cmd.trim().is_empty() {
            continue; // documented disable; absent, no warning
        }
        match Provider::parse(name, cmd) {
            Some(p) => providers.push(p),
            None => warnings.push(format!(
                "longline: ai-judge {name} command is malformed (unparseable shell quoting); provider disabled"
            )),
        }
    }
    let empty = providers.is_empty();
    ProviderSet {
        providers,
        warnings,
        empty,
    }
}

// ── Real process Runner / Clock / Handle (Task 9) ───────────────────────────────
//
// Each attempt runs on a worker thread that SOLELY owns its `std::process::Child`.
// The orchestrator never touches the Child or the pid: it cancels by flipping a
// shared `Arc<AtomicBool>`, and it joins workers by dropping their handles.
//
// Output is captured to per-attempt temp files (the child's stdout/stderr fds
// point at real files) — NO pipe-reader threads. This bounds cleanup even when a
// descendant escapes the process group and holds the inherited stdout open: we
// reap the direct child, then read the files back. We never block on an fd held
// open by an escaped grandchild.

/// SIGKILL an entire process group by pgid (== the worker child's pid, since we
/// spawn with `process_group(0)`). Best-effort; ignores errors (the group may be
/// gone). Mirrors `invoke.rs::kill_process_group`.
#[cfg(unix)]
fn kill_process_group(pid: u32) {
    if pid == 0 {
        return;
    }
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}

/// Remove any occurrence of `--ephemeral` from argv when debug is enabled. Keeps
/// codex session rollouts for post-mortem inspection. Mirrors `invoke.rs`.
fn maybe_strip_ephemeral(argv: Vec<String>, debug_enabled: bool) -> Vec<String> {
    if !debug_enabled {
        return argv;
    }
    argv.into_iter().filter(|a| a != "--ephemeral").collect()
}

const STDERR_SNIPPET_MAX: usize = 200;

/// Process-wide monotonic counter to make per-attempt temp-file names unique even
/// at the same wall-clock nanosecond.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Build two unique temp file paths (stdout, stderr) for one attempt, under
/// `std::env::temp_dir()`. std-only (no `tempfile` crate in production).
fn attempt_temp_paths(id: AttemptId) -> (std::path::PathBuf, std::path::PathBuf) {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = Instant::now().elapsed().as_nanos();
    let base = format!(
        "longline-judge-{}-{}-{}-{}",
        std::process::id(),
        id,
        seq,
        nanos
    );
    let dir = std::env::temp_dir();
    (
        dir.join(format!("{base}.out")),
        dir.join(format!("{base}.err")),
    )
}

/// Wall-clock since orchestration start (shares `start` with its `RealRunner`).
pub struct RealClock {
    start: Instant,
}

impl Clock for RealClock {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

/// A live attempt the orchestrator can cancel (flag-only) and join (on drop).
pub struct RealHandle {
    id: AttemptId,
    provider: String,
    cancel_flag: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl AttemptHandle for RealHandle {
    fn id(&self) -> AttemptId {
        self.id
    }
    fn provider_name(&self) -> &str {
        &self.provider
    }
    /// Idempotent; carries NO pid. Flips the shared flag the worker polls.
    fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::SeqCst);
    }
}

impl Drop for RealHandle {
    /// Joining the worker on drop is what makes "orchestrate joins every worker
    /// before returning" hold for free: dropping a handle == joining its worker.
    /// `cancel()` (called by the orchestrator before drop, for losers) signals the
    /// worker promptly so this join is bounded.
    fn drop(&mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// The real process layer. Workers report completion through an mpsc channel;
/// `wait_next` blocks on it with a deadline derived from the shared clock.
pub struct RealRunner {
    prompt: String,
    debug_strip_ephemeral: bool,
    per_attempt_timeout_ms: u64,
    start: Instant,
    tx: mpsc::Sender<(AttemptId, AttemptOutcome)>,
    rx: mpsc::Receiver<(AttemptId, AttemptOutcome)>,
}

impl RealRunner {
    /// Build a paired `(RealClock, RealRunner)` sharing one `start` instant so the
    /// orchestrator's clock and the runner's deadlines agree.
    pub fn new(
        prompt: String,
        debug_strip_ephemeral: bool,
        per_attempt_timeout_ms: u64,
    ) -> (RealClock, RealRunner) {
        let start = Instant::now();
        let (tx, rx) = mpsc::channel();
        (
            RealClock { start },
            RealRunner {
                prompt,
                debug_strip_ephemeral,
                per_attempt_timeout_ms,
                start,
                tx,
                rx,
            },
        )
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

impl Runner for RealRunner {
    type Handle = RealHandle;

    fn launch(&mut self, provider: &Provider, id: AttemptId) -> RealHandle {
        // Build argv = template + prompt, then per-attempt strip of --ephemeral.
        let mut argv = provider.argv.clone();
        argv.push(self.prompt.clone());
        let argv = maybe_strip_ephemeral(argv, self.debug_strip_ephemeral);

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let worker_flag = Arc::clone(&cancel_flag);
        let tx = self.tx.clone();
        let timeout_ms = self.per_attempt_timeout_ms;

        let join = std::thread::spawn(move || {
            run_attempt(id, argv, worker_flag, timeout_ms, tx);
        });

        RealHandle {
            id,
            provider: provider.name.clone(),
            cancel_flag,
            join: Some(join),
        }
    }

    fn wait_next(&mut self, deadline_ms: u64) -> Event {
        let now = self.now_ms();
        let wait = Duration::from_millis(deadline_ms.saturating_sub(now));
        match self.rx.recv_timeout(wait) {
            Ok((id, outcome)) => Event::Arrival(id, outcome),
            // Timeout OR Disconnected → Wake. The orchestrator re-derives state
            // from the clock/deadline on a Wake, so a disconnect (impossible while
            // we hold `tx`) is handled safely as "nothing arrived yet".
            Err(_) => Event::Wake,
        }
    }
}

/// The worker body. SOLE owner of the spawned `Child`. Reaps it, reads back the
/// captured temp files, classifies, and reports — EXCEPT on cancel, where it
/// kills+reaps and sends nothing (the orchestrator synthesizes the cancelled
/// record).
fn run_attempt(
    id: AttemptId,
    argv: Vec<String>,
    cancel_flag: Arc<AtomicBool>,
    timeout_ms: u64,
    tx: mpsc::Sender<(AttemptId, AttemptOutcome)>,
) {
    debug_assert!(!argv.is_empty(), "argv always has at least the program");
    let (out_path, err_path) = attempt_temp_paths(id);

    // Open the two capture files. A failure here is reported as a spawn error.
    let out_file = match File::create(&out_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = tx.send((
                id,
                AttemptOutcome::SpawnError {
                    msg: format!("temp stdout: {e}"),
                },
            ));
            return;
        }
    };
    let err_file = match File::create(&err_path) {
        Ok(f) => f,
        Err(e) => {
            drop(out_file);
            let _ = std::fs::remove_file(&out_path);
            let _ = tx.send((
                id,
                AttemptOutcome::SpawnError {
                    msg: format!("temp stderr: {e}"),
                },
            ));
            return;
        }
    };

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .env("LONGLINE_JUDGE_ACTIVE", "1");

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&out_path);
            let _ = std::fs::remove_file(&err_path);
            let _ = tx.send((id, AttemptOutcome::SpawnError { msg: e.to_string() }));
            return;
        }
    };

    let pid = child.id();
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Child exited and is reaped. Read back captures, unlink, classify.
                let stdout = read_temp_lossy(&out_path);
                let stderr = read_temp_lossy(&err_path);
                let _ = std::fs::remove_file(&out_path);
                let _ = std::fs::remove_file(&err_path);
                let parsed = parse_output(&stdout);
                let mut outcome = classify(parsed, status.code());
                // Enrich an exit error's stderr snippet from the captured stderr.
                if let AttemptOutcome::ExitError { stderr_snippet, .. } = &mut outcome {
                    if stderr_snippet.is_empty() {
                        let snip: String = stderr.trim().chars().take(STDERR_SNIPPET_MAX).collect();
                        *stderr_snippet = snip;
                    }
                }
                let _ = tx.send((id, outcome));
                return;
            }
            Ok(None) => {
                // Still running. Cancel takes priority over timeout.
                if cancel_flag.load(Ordering::SeqCst) {
                    kill_and_reap(pid, &mut child);
                    let _ = std::fs::remove_file(&out_path);
                    let _ = std::fs::remove_file(&err_path);
                    // Send NOTHING: the orchestrator synthesizes the cancelled
                    // record. (A late send would land in a dropped channel.)
                    return;
                }
                let elapsed = start.elapsed().as_millis() as u64;
                if elapsed >= timeout_ms {
                    kill_and_reap(pid, &mut child);
                    let _ = std::fs::remove_file(&out_path);
                    let _ = std::fs::remove_file(&err_path);
                    let _ = tx.send((
                        id,
                        AttemptOutcome::Timeout {
                            elapsed_ms: elapsed,
                        },
                    ));
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                // try_wait failed: best-effort kill+reap, report as a disabling
                // error so we don't spin retrying a broken handle.
                kill_and_reap(pid, &mut child);
                let _ = std::fs::remove_file(&out_path);
                let _ = std::fs::remove_file(&err_path);
                let _ = tx.send((
                    id,
                    AttemptOutcome::SpawnError {
                        msg: format!("wait failed: {e}"),
                    },
                ));
                return;
            }
        }
    }
}

/// Kill the child's whole process group, then reap the direct child. After this
/// returns the direct child is no longer a zombie. (`process_group(0)` makes the
/// child a group leader, so its pid == pgid.)
fn kill_and_reap(pid: u32, child: &mut std::process::Child) {
    #[cfg(unix)]
    kill_process_group(pid);
    // Also kill the direct child directly (covers non-unix and races).
    let _ = child.kill();
    let _ = child.wait();
    #[cfg(not(unix))]
    let _ = pid;
}

/// Read a temp file to a lossy String; missing/unreadable → empty.
fn read_temp_lossy(path: &std::path::Path) -> String {
    let mut buf = Vec::new();
    if let Ok(mut f) = File::open(path) {
        let _ = f.read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shlex_parses_empty_setting_sources_as_genuine_empty_arg() {
        // The load-bearing case split_whitespace cannot represent.
        let p =
            Provider::parse("claude", "claude -p --setting-sources \"\" --model haiku").unwrap();
        let i = p
            .argv
            .iter()
            .position(|a| a == "--setting-sources")
            .unwrap();
        assert_eq!(p.argv[i + 1], "", "empty arg must survive as \"\"");
    }

    #[test]
    fn tilde_in_settings_path_is_expanded() {
        std::env::set_var("HOME", "/home/u");
        let p = Provider::parse("claude", "claude --settings ~/.config/longline/x.json").unwrap();
        assert!(p
            .argv
            .iter()
            .any(|a| a == "/home/u/.config/longline/x.json"));
    }

    #[test]
    fn empty_or_whitespace_command_is_absent() {
        assert!(Provider::parse("claude", "").is_none());
        assert!(Provider::parse("claude", "   ").is_none());
    }

    #[test]
    fn malformed_shlex_is_absent() {
        // unmatched quote -> shlex::split returns None
        assert!(Provider::parse("claude", "claude --settings \"unterminated").is_none());
    }

    #[test]
    fn resolve_set_both_present() {
        let r = resolve_provider_set("codex exec -m x", "claude -p");
        assert_eq!(r.providers.len(), 2);
        assert!(r.warnings.is_empty());
        assert!(!r.empty);
    }

    #[test]
    fn resolve_set_codex_only_when_fallback_empty() {
        let r = resolve_provider_set("codex exec", "");
        assert_eq!(r.providers.len(), 1);
        assert_eq!(r.providers[0].name, "codex");
        assert!(!r.empty);
    }

    #[test]
    fn resolve_set_both_malformed_is_no_providers_with_warnings() {
        let r = resolve_provider_set("codex \"bad", "claude \"bad");
        assert!(r.empty);
        assert_eq!(r.warnings.len(), 2);
    }
}
