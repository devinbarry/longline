//! Integration tests for the real process `Runner`/`Clock`/`Handle` (Task 9).
//!
//! These drive `orchestrate()` against `RealRunner`/`RealClock` with real OS
//! processes spawned from fake-binary shell scripts. The point of the suite is
//! process hygiene: cancellation, reaping, and bounded cleanup even when a
//! descendant escapes the process group.
//!
//! Unix-only: the production worker uses POSIX process groups. The whole file is
//! gated on `cfg(unix)`.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use longline::ai_judge::{
    orchestrate, AttemptHandle, Event, OrchestrateParams, Provider, RealRunner, Runner, Verdict,
    Xorshift,
};

const SEED: u64 = 0xDEAD_BEEF_CAFE_F00D;

/// Write `contents` to a uniquely-named executable script under
/// `target/test-tmp/ai-judge-hygiene/` and return its path. Unique per
/// (name, thread, pid) so parallel tests do not collide. Mirrors the helper in
/// `src/ai_judge/invoke.rs` tests.
fn make_executable_script(name: &str, contents: &str) -> PathBuf {
    let unique_name = format!(
        "{}-{:?}-{}",
        name,
        std::thread::current().id(),
        std::process::id()
    );
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp")
        .join("ai-judge-hygiene");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(unique_name);
    std::fs::write(&path, contents).unwrap();
    // Ensure file is synced to disk before setting permissions / execing.
    std::fs::File::open(&path).unwrap().sync_all().unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// A unique path under the test-tmp dir (NOT created) — for counter / marker
/// files the scripts write to.
fn scratch_path(name: &str) -> PathBuf {
    let unique = format!(
        "{}-{:?}-{}-{}",
        name,
        std::thread::current().id(),
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    );
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp")
        .join("ai-judge-hygiene");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(unique)
}

fn provider(name: &str, path: &Path) -> Provider {
    Provider {
        name: name.to_string(),
        argv: vec![path.to_string_lossy().to_string()],
    }
}

/// Generous params; individual tests override budget / timeout.
fn params(total_budget_ms: u64, per_attempt_timeout_ms: u64) -> OrchestrateParams {
    OrchestrateParams {
        total_budget_ms,
        per_attempt_timeout_ms,
        // Stay in Phase1 (no hedge) for single-provider tests unless overridden.
        hedge_after_ms: 10_000_000,
        backoff_base_ms: 50,
        backoff_max_ms: 200,
        relaunch_floor_ms: 50,
        max_attempts: 16,
        max_nonconforming: 3,
        min_launch_ms: 1,
    }
}

fn run(
    prompt: &str,
    providers: &[Provider],
    p: &OrchestrateParams,
) -> longline::ai_judge::OrchestrateResult {
    let (clock, mut runner) = RealRunner::new(prompt.to_string(), false, p.per_attempt_timeout_ms);
    let mut rng = Xorshift::new(SEED);
    orchestrate(&clock, &mut runner, providers, p, &mut rng)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

/// Empty stdout on attempt 1, `ALLOW: ok` on attempt 2 → the retry path recovers
/// a real verdict, end-to-end with real processes.
#[test]
fn empty_then_allow_retry_recovers() {
    let counter = scratch_path("counter");
    // Count up in a file; first call prints nothing (empty -> retryable), second
    // prints ALLOW.
    let script = make_executable_script(
        "empty-then-allow.sh",
        &format!(
            r#"#!/bin/sh
COUNTER="{counter}"
n=0
if [ -f "$COUNTER" ]; then n=$(cat "$COUNTER"); fi
n=$((n + 1))
printf '%s' "$n" > "$COUNTER"
if [ "$n" -ge 2 ]; then
  echo "ALLOW: ok"
fi
exit 0
"#,
            counter = counter.to_string_lossy()
        ),
    );
    let providers = vec![provider("codex", &script)];
    let p = params(8_000, 4_000);
    let res = run("PROMPT", &providers, &p);
    assert_eq!(
        res.verdict,
        Some(Verdict::Allow),
        "retry recovers a verdict; report={:?}",
        res.report.attempts
    );
    // At least one empty_output recorded before the verdict.
    let empties = res
        .report
        .attempts
        .iter()
        .filter(|a| a.outcome == "empty_output")
        .count();
    assert!(empties >= 1, "an empty attempt preceded the verdict");

    let _ = std::fs::remove_file(&script);
    let _ = std::fs::remove_file(&counter);
}

/// A `sleep 10` script must hit the per-attempt timeout (~1s) and the run must
/// end well under the 10s sleep — proving the worker kills the group and the
/// orchestrator does not block on the child.
#[test]
fn sleep_script_hits_timeout_path() {
    let script = make_executable_script(
        "sleep10.sh",
        r#"#!/bin/sh
sleep 10
echo "ALLOW: too late"
exit 0
"#,
    );
    let providers = vec![provider("codex", &script)];
    // 1s per-attempt timeout, ~2.5s total budget so the run exhausts quickly.
    let p = params(2_500, 1_000);
    let started = Instant::now();
    let res = run("PROMPT", &providers, &p);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(8),
        "must finish well under the 10s sleep; took {elapsed:?}"
    );
    let timeouts = res
        .report
        .attempts
        .iter()
        .filter(|a| a.outcome == "timeout")
        .count();
    assert!(
        timeouts >= 1,
        "a timeout attempt was recorded; attempts={:?}",
        res.report.attempts
    );
    let _ = std::fs::remove_file(&script);
}

/// A provider whose argv points at a non-existent binary → a single spawn_error
/// attempt; the provider is disabled (not retried) and the run exhausts fast.
#[test]
fn missing_binary_is_spawn_error_disable() {
    let missing = PathBuf::from("/nonexistent/longline-judge-does-not-exist-12345");
    let providers = vec![provider("codex", &missing)];
    let p = params(5_000, 1_000);
    let started = Instant::now();
    let res = run("PROMPT", &providers, &p);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "spawn error disables fast (no retry, no budget wait); took {elapsed:?}"
    );
    let spawn_errors = res
        .report
        .attempts
        .iter()
        .filter(|a| a.outcome == "spawn_error")
        .count();
    assert_eq!(
        spawn_errors, 1,
        "exactly one spawn_error, provider disabled; attempts={:?}",
        res.report.attempts
    );
}

/// `exit 1` with empty stdout → exit_error (NOT empty_output / retry). Provider
/// disabled, run exhausts fast.
#[test]
fn nonzero_exit_empty_stdout_is_exit_error() {
    let script = make_executable_script(
        "exit1.sh",
        r#"#!/bin/sh
echo "not logged in" 1>&2
exit 1
"#,
    );
    let providers = vec![provider("codex", &script)];
    let p = params(5_000, 1_000);
    let started = Instant::now();
    let res = run("PROMPT", &providers, &p);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "exit_error disables fast; took {elapsed:?}"
    );
    let exit_errors = res
        .report
        .attempts
        .iter()
        .filter(|a| a.outcome == "exit_error")
        .count();
    assert_eq!(
        exit_errors, 1,
        "one exit_error, not retried as empty; attempts={:?}",
        res.report.attempts
    );
    let empties = res
        .report
        .attempts
        .iter()
        .filter(|a| a.outcome == "empty_output")
        .count();
    assert_eq!(empties, 0, "nonzero exit must NOT classify as empty_output");
    let _ = std::fs::remove_file(&script);
}

/// A descendant escapes the process group (new session via setsid, or a
/// disowned background sleep) and holds the inherited stdout open for 30s, while
/// the PARENT prints ALLOW and exits 0. Because output is captured to temp files
/// (not pipe-reads), the worker reaps the parent and the run returns promptly —
/// it does NOT wedge waiting on the escaped descendant's open fd.
#[test]
fn escaped_descendant_does_not_wedge_hook() {
    // The grandchild starts a new session (setsid) if available, else a disowned
    // background sleep; either way it inherits and holds stdout open longer than
    // the parent lives. The parent prints the verdict and exits immediately.
    let script = make_executable_script(
        "escape.sh",
        r#"#!/bin/sh
# Spawn a descendant that survives the parent and keeps stdout (fd 1) open.
if command -v setsid >/dev/null 2>&1; then
  setsid sh -c 'sleep 30' &
else
  sh -c 'sleep 30' &
  disown 2>/dev/null || true
fi
echo "ALLOW: ok"
exit 0
"#,
    );
    let providers = vec![provider("codex", &script)];
    let p = params(8_000, 5_000);
    let started = Instant::now();
    let res = run("PROMPT", &providers, &p);
    let elapsed = started.elapsed();
    assert_eq!(
        res.verdict,
        Some(Verdict::Allow),
        "parent verdict returns despite escaped descendant; attempts={:?}",
        res.report.attempts
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "temp-file capture bounds cleanup; must not wait on the 30s descendant; took {elapsed:?}"
    );
    let _ = std::fs::remove_file(&script);
}

/// Cancelling an attempt that has already completed and been reaped is a harmless
/// no-op: no panic, the call returns cleanly, and dropping the handle (joining
/// the already-finished worker) is fine.
#[test]
fn stale_cancel_is_noop() {
    let script = make_executable_script(
        "quick-allow.sh",
        r#"#!/bin/sh
echo "ALLOW: ok"
exit 0
"#,
    );
    let prov = provider("codex", &script);
    let (_clock, mut runner) = RealRunner::new("PROMPT".to_string(), false, 5_000);
    let handle = runner.launch(&prov, 0);
    // Drive the runner until the attempt arrives (worker reaped the child).
    let mut arrived = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match runner.wait_next(10_000) {
            Event::Arrival(id, _outcome) => {
                assert_eq!(id, 0);
                arrived = true;
                break;
            }
            Event::Wake => continue,
        }
    }
    assert!(arrived, "the quick attempt arrived");
    // Give the worker a moment to fully finish/reap (it has already sent).
    std::thread::sleep(Duration::from_millis(100));
    // Stale cancel: must not panic / re-signal anything. Idempotent twice.
    handle.cancel();
    handle.cancel();
    // Dropping (joining the finished worker) must be clean.
    drop(handle);
    let _ = std::fs::remove_file(&script);
}

/// Launch an attempt whose child stays alive, cancel it via the orchestrator's
/// deadline (small budget), and assert that after `orchestrate()` returns the
/// child's process group is gone — `kill(-pgid, 0)` returns ESRCH. The script
/// writes its own pgid to a marker file so we can probe it.
#[test]
fn process_group_killed_and_worker_joined_before_return() {
    let pgid_file = scratch_path("pgid");
    // Record our process-group id, then sleep long. The orchestrator's deadline
    // will cancel us; the worker must SIGKILL the whole group and reap.
    let script = make_executable_script(
        "record-pgid-sleep.sh",
        &format!(
            r#"#!/bin/sh
# $$ is this process's pid. Spawned with process_group(0) so pid == pgid.
PGID_FILE="{pgid_file}"
printf '%s' "$$" > "$PGID_FILE"
sleep 30
echo "ALLOW: too late"
"#,
            pgid_file = pgid_file.to_string_lossy()
        ),
    );
    let providers = vec![provider("codex", &script)];
    // Modest total budget: the child never finishes (sleeps 30s); the deadline
    // cancels it. Kept comfortably above spawn latency so the child reliably
    // writes its pgid before being killed, but far below the 30s sleep so the
    // "returned promptly" assertion still proves the worker was joined.
    let p = params(1_200, 5_000);
    let started = Instant::now();
    let res = run("PROMPT", &providers, &p);
    let elapsed = started.elapsed();

    // Worker joined before return → returned close to the budget, not after the
    // 30s sleep, and not detached (no extra wall-clock).
    assert!(
        elapsed < Duration::from_secs(5),
        "returned promptly after the budget (worker joined, group killed); took {elapsed:?}"
    );
    assert_eq!(
        res.report.outcome,
        longline::ai_judge::ReportOutcome::Exhausted
    );

    // Read the pgid the child recorded and confirm the group is gone.
    // (Poll briefly: the worker's kill+reap completes during drop, which the
    // orchestrator awaits, so by the time we're here it should already be gone.)
    let pgid_str = {
        let mut s = String::new();
        let read_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < read_deadline {
            if let Ok(contents) = std::fs::read_to_string(&pgid_file) {
                if !contents.trim().is_empty() {
                    s = contents.trim().to_string();
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        s
    };
    assert!(!pgid_str.is_empty(), "child recorded its pgid");
    let pgid: i32 = pgid_str.parse().expect("pgid is an integer");

    // kill(-pgid, 0): 0 → group still exists; -1/ESRCH → gone. Poll a short
    // window to absorb reap latency, but it should already be gone.
    let mut gone = false;
    let probe_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < probe_deadline {
        let rc = unsafe { libc::kill(-pgid, 0) };
        if rc == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                gone = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        gone,
        "process group {pgid} must be killed+reaped before orchestrate() returns"
    );

    let _ = std::fs::remove_file(&script);
    let _ = std::fs::remove_file(&pgid_file);
}
