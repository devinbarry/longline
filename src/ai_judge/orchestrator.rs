use crate::ai_judge::outcome::{
    derive_failure_mode, outcome_tag, AttemptOutcome, AttemptRecord, JudgeReport, Phase,
    ReportOutcome,
};
use crate::ai_judge::provider::Provider;
use crate::ai_judge::response::Verdict;
use std::collections::HashMap;

// ── Traits ────────────────────────────────────────────────────────────────────

/// Monotonic virtual/real clock in milliseconds since orchestration start.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// Identifies one launched attempt within an orchestration run.
pub type AttemptId = u64;

/// A launched attempt the orchestrator can await (via the shared event source)
/// and cancel. `cancel()` is idempotent and must NOT carry a pid (worker-owned
/// cancellation via a shared atomic flag).
///
/// NOTE: no `Send` bound. The orchestrator is single-threaded — it owns handles
/// on one thread and never moves them across threads. The real runner (Task 9)
/// spawns worker threads that own their own process plumbing and signal
/// completion through the `Runner`'s event channel; `cancel()` flips a shared
/// atomic flag (e.g. `Arc<AtomicBool>`), which is itself `Send`/`Sync` without
/// the handle needing to be `Send`. Dropping `Send` here lets the test fakes use
/// cheap `Rc` interior mutability.
pub trait AttemptHandle {
    fn id(&self) -> AttemptId;
    fn provider_name(&self) -> &str;
    fn cancel(&self);
}

/// What the orchestrator gets back when it waits.
#[allow(dead_code)] // variants used in Task 8
pub enum Event {
    /// An attempt completed: (id, outcome).
    Arrival(AttemptId, AttemptOutcome),
    /// A timer fired (relaunch wake / hedge_at / deadline) with nothing arriving.
    Wake,
}

/// The injected process layer. Launches attempts and is the single event source
/// the orchestrator blocks on. `wait_next(deadline_ms)` returns the next
/// arrival, or `Event::Wake` when `deadline_ms` is reached first. Tie-break at
/// equal time: Arrival before Wake.
pub trait Runner {
    type Handle: AttemptHandle;
    /// Launch `provider` with the prompt; returns a live handle. `id` is the
    /// orchestrator-assigned attempt id; the orchestrator stamps `launched_at`
    /// from the clock for latency accounting.
    fn launch(
        &mut self,
        provider: &crate::ai_judge::provider::Provider,
        id: AttemptId,
    ) -> Self::Handle;
    /// Block until the earliest of: an attempt arrival, or `deadline_ms`.
    fn wait_next(&mut self, deadline_ms: u64) -> Event;
}

// ── Xorshift RNG ──────────────────────────────────────────────────────────────

/// Tiny seeded xorshift — no `rand` dependency. Production seeds per-process
/// (pid XOR a coarse clock read, once at startup); tests inject a fixed seed.
pub struct Xorshift(u64);

impl Xorshift {
    pub fn new(seed: u64) -> Self {
        Xorshift(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Jitter in [0, span_ms).
    #[allow(dead_code)] // used in Task 8
    pub fn jitter(&mut self, span_ms: u64) -> u64 {
        if span_ms == 0 {
            0
        } else {
            self.next_u64() % span_ms
        }
    }
}

// ── Orchestrate result/params ──────────────────────────────────────────────────

pub struct OrchestrateResult {
    /// Some(verdict) on success; None when exhausted (caller maps to Ask).
    pub verdict: Option<Verdict>,
    pub verdict_line: Option<String>,
    pub report: JudgeReport,
}

/// Inputs the loop needs that come from config (already finalized).
pub struct OrchestrateParams {
    pub total_budget_ms: u64,
    #[allow(dead_code)] // per-attempt timeout is enforced by the Runner, not the loop
    pub per_attempt_timeout_ms: u64,
    pub hedge_after_ms: u64,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
    pub relaunch_floor_ms: u64,
    pub max_attempts: u32,
    pub max_nonconforming: u32,
    pub min_launch_ms: u64,
}

// Backoff schedule (Cluster B):
//   d_k = min(backoff_base_ms * 2^k, backoff_max_ms)   (2^k saturates for large k)
//   gap = max( d_k + rng.jitter(JITTER_SPAN), relaunch_floor_ms )
// JITTER_SPAN is `backoff_base_ms`: deterministic, and small relative to d_k for
// every k>=1 (equal to it only at k=0). Cluster B asserts each successive gap is
// in `[d_k, d_k + JITTER_SPAN)` (capped at `backoff_max_ms`) and `>= relaunch_floor_ms`.

/// JITTER_SPAN as a function of params — the chosen span is `backoff_base_ms`.
fn jitter_span(params: &OrchestrateParams) -> u64 {
    params.backoff_base_ms
}

/// `d_k = min(backoff_base_ms * 2^k, backoff_max_ms)`, saturating for large k.
fn backoff_base_delay(backoff_base_ms: u64, backoff_max_ms: u64, k: u32) -> u64 {
    let scale = 1u64.checked_shl(k).unwrap_or(u64::MAX);
    let d = backoff_base_ms.saturating_mul(scale);
    d.min(backoff_max_ms)
}

/// Full relaunch gap including jitter and the floor.
fn backoff_delay(params: &OrchestrateParams, k: u32, rng: &mut Xorshift) -> u64 {
    let d = backoff_base_delay(params.backoff_base_ms, params.backoff_max_ms, k);
    let jittered = d.saturating_add(rng.jitter(jitter_span(params)));
    jittered.max(params.relaunch_floor_ms)
}

/// Per-provider mutable scheduling state.
struct ProvState {
    disabled: bool,
    nonconforming_count: u32,
    failed_retryable_count: u32,
    in_flight: Option<AttemptId>,
    /// Earliest virtual ms it may (re)launch. 0 = ready now.
    next_launch_at: u64,
    /// Hedge becomes eligible at hedge_after_ms OR when the primary disables.
    promoted_early: bool,
}

impl ProvState {
    fn new() -> Self {
        ProvState {
            disabled: false,
            nonconforming_count: 0,
            failed_retryable_count: 0,
            in_flight: None,
            next_launch_at: 0,
            promoted_early: false,
        }
    }
}

/// An attempt currently in flight, keyed by AttemptId.
struct InFlight<H: AttemptHandle> {
    provider_index: usize,
    launched_at: u64,
    handle: H,
}

/// Is `provider_index` eligible to launch at virtual time `now`?
/// Index 0 (primary) is always eligible. Index 1 (hedge) becomes eligible at the
/// time boundary OR via early promotion. Indices >=2 are not modeled (the design
/// is two-provider) and follow the hedge rule.
fn provider_eligible(index: usize, now: u64, hedge_after_ms: u64, state: &ProvState) -> bool {
    if index == 0 {
        true
    } else {
        now >= hedge_after_ms || state.promoted_early
    }
}

pub fn orchestrate<C: Clock, R: Runner>(
    clock: &C,
    runner: &mut R,
    providers: &[Provider],
    params: &OrchestrateParams,
    rng: &mut Xorshift,
) -> OrchestrateResult {
    let deadline = params.total_budget_ms;
    let empty_provider_set = providers.is_empty();

    let mut prov: Vec<ProvState> = providers.iter().map(|_| ProvState::new()).collect();
    let mut in_flight: HashMap<AttemptId, InFlight<R::Handle>> = HashMap::new();
    let mut records: Vec<AttemptRecord> = Vec::new();
    let mut next_id: AttemptId = 0;
    let mut launched_count: u32 = 0;
    let mut phase_reached = Phase::Phase1;

    loop {
        let mut now = clock.now_ms();
        if now >= params.hedge_after_ms {
            phase_reached = Phase::Hedge;
        }

        // ── Launch pass ──────────────────────────────────────────────────────
        for index in 0..prov.len() {
            let eligible = {
                let st = &prov[index];
                !st.disabled
                    && st.in_flight.is_none()
                    && st.next_launch_at <= now
                    && provider_eligible(index, now, params.hedge_after_ms, st)
            };
            if !eligible {
                continue;
            }
            // Launch caps: global attempt count and a budget floor.
            if launched_count >= params.max_attempts {
                continue;
            }
            if deadline.saturating_sub(now) < params.min_launch_ms {
                continue;
            }
            let id = next_id;
            next_id += 1;
            let handle = runner.launch(&providers[index], id);
            prov[index].in_flight = Some(id);
            in_flight.insert(
                id,
                InFlight {
                    provider_index: index,
                    launched_at: now,
                    handle,
                },
            );
            launched_count += 1;
        }

        // ── Termination check ────────────────────────────────────────────────
        // End at the FIRST of: deadline reached, or nothing-in-flight AND no
        // provider can still launch (disabled, or can never afford a launch
        // before the deadline). Verdict termination is handled on arrival below.
        let deadline_reached = now >= deadline;
        let any_in_flight = !in_flight.is_empty();
        let any_launchable = (0..prov.len()).any(|i| {
            let st = &prov[i];
            // Could this provider EVER launch again before the deadline?
            // Eligibility may become true later (hedge boundary / promotion), so
            // we check the relaxed "could become eligible" rather than `now`.
            let could_be_eligible = i == 0
                || params.hedge_after_ms < deadline
                || st.promoted_early
                || now >= params.hedge_after_ms;
            !st.disabled
                && st.in_flight.is_none()
                && could_be_eligible
                && launched_count < params.max_attempts
                && deadline.saturating_sub(st.next_launch_at.max(now)) >= params.min_launch_ms
        });

        if deadline_reached || (!any_in_flight && !any_launchable) {
            // Synthesize cancelled_deadline records for everything still in flight.
            cancel_in_flight(&mut in_flight, &mut records, now, "cancelled_deadline");
            let total_latency_ms = clock.now_ms();
            let failure_mode = derive_failure_mode(&records, empty_provider_set);
            let report = JudgeReport {
                provider_final: None,
                outcome: ReportOutcome::Exhausted,
                failure_mode,
                phase_reached,
                total_latency_ms,
                attempts: records,
            };
            return OrchestrateResult {
                verdict: None,
                verdict_line: None,
                report,
            };
        }

        // ── Compute wait deadline ────────────────────────────────────────────
        let mut wake = deadline;
        for (index, st) in prov.iter().enumerate() {
            if st.in_flight.is_some() || st.disabled {
                continue;
            }
            // A provider that is waiting to relaunch contributes its next_launch_at
            // wake (only if strictly in the future; past/now is handled by the
            // launch pass next iteration, but we still need the loop to turn).
            if provider_eligible(index, now, params.hedge_after_ms, st) && st.next_launch_at > now {
                wake = wake.min(st.next_launch_at);
            }
        }
        // Mandatory hedge_at wake: if we have not yet reached the hedge boundary,
        // wake at it so the hedge launches on time even while the primary is in
        // flight.
        if now < params.hedge_after_ms {
            wake = wake.min(params.hedge_after_ms);
        }

        // ── Wait for the next event ──────────────────────────────────────────
        let event = runner.wait_next(wake);
        now = clock.now_ms();
        if now >= params.hedge_after_ms {
            phase_reached = Phase::Hedge;
        }

        match event {
            Event::Wake => {
                // Time advanced; relaunches / hedge / deadline are picked up next
                // iteration.
            }
            Event::Arrival(id, outcome) => {
                let info = in_flight
                    .remove(&id)
                    .expect("arrival for an unknown in-flight id");
                let index = info.provider_index;
                let latency_ms = now.saturating_sub(info.launched_at);
                prov[index].in_flight = None;

                if let AttemptOutcome::Verdict(v, line) = outcome {
                    // WINNER. Record it, cancel every other in-flight attempt.
                    records.push(AttemptRecord {
                        provider: providers[index].name.clone(),
                        outcome: "verdict".into(),
                        latency_ms,
                    });
                    cancel_in_flight(&mut in_flight, &mut records, now, "cancelled_winner");
                    // Clear any remaining in_flight markers (their attempts were cancelled).
                    for st in prov.iter_mut() {
                        st.in_flight = None;
                    }
                    let total_latency_ms = clock.now_ms();
                    let report = JudgeReport {
                        provider_final: Some(providers[index].name.clone()),
                        outcome: ReportOutcome::Verdict,
                        failure_mode: None,
                        phase_reached,
                        total_latency_ms,
                        attempts: records,
                    };
                    return OrchestrateResult {
                        verdict: Some(v),
                        verdict_line: Some(line),
                        report,
                    };
                }

                // Non-verdict terminal record.
                records.push(AttemptRecord {
                    provider: providers[index].name.clone(),
                    outcome: outcome_tag(&outcome).into(),
                    latency_ms,
                });

                // Update provider state.
                if outcome.disables_provider() {
                    prov[index].disabled = true;
                } else if matches!(outcome, AttemptOutcome::NonConforming { .. }) {
                    prov[index].nonconforming_count += 1;
                    if prov[index].nonconforming_count >= params.max_nonconforming {
                        prov[index].disabled = true;
                    }
                }

                if !prov[index].disabled && outcome.is_retryable() {
                    let k = prov[index].failed_retryable_count;
                    let gap = if phase_reached == Phase::Hedge {
                        // Hedge phase: floor only, no exponential backoff.
                        params.relaunch_floor_ms
                    } else {
                        backoff_delay(params, k, rng)
                    };
                    let gap = gap.max(params.relaunch_floor_ms);
                    prov[index].next_launch_at = now.saturating_add(gap);
                    prov[index].failed_retryable_count += 1;
                }

                // Primary just disabled → promote the hedge immediately.
                if index == 0 && prov[index].disabled && prov.len() > 1 {
                    let hedge = &mut prov[1];
                    if !hedge.promoted_early {
                        hedge.promoted_early = true;
                        hedge.next_launch_at = hedge.next_launch_at.min(now);
                    }
                }
            }
        }
    }
}

/// Synthesize cancellation records for every still-in-flight attempt and cancel
/// the handles. Drains `in_flight`.
fn cancel_in_flight<H: AttemptHandle>(
    in_flight: &mut HashMap<AttemptId, InFlight<H>>,
    records: &mut Vec<AttemptRecord>,
    now: u64,
    tag: &str,
) {
    // Deterministic order: ascending id.
    let mut ids: Vec<AttemptId> = in_flight.keys().copied().collect();
    ids.sort_unstable();
    for id in ids {
        let info = in_flight.remove(&id).expect("id from keys must exist");
        let latency_ms = now.saturating_sub(info.launched_at);
        records.push(AttemptRecord {
            provider: info.handle.provider_name().to_string(),
            outcome: tag.to_string(),
            latency_ms,
        });
        info.handle.cancel();
    }
}

// ── Fakes (test-only) ─────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod fakes {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// Virtual clock with shared interior-mutable time. Task 8's FakeRunner holds
    /// a clone of the same `Rc<Cell<u64>>` and advances it inside `wait_next`.
    pub struct FakeClock {
        t: Rc<Cell<u64>>,
    }

    impl FakeClock {
        pub fn new() -> Self {
            FakeClock {
                t: Rc::new(Cell::new(0)),
            }
        }

        /// Clone of the shared time cell, for FakeRunner to advance (Task 8).
        #[allow(dead_code)] // consumed in Task 8 by FakeRunner
        pub(crate) fn shared(&self) -> Rc<Cell<u64>> {
            Rc::clone(&self.t)
        }

        /// Set virtual time forward (test helper / FakeRunner use). Monotonic in
        /// practice; this setter does not enforce monotonicity (Task 8 advances
        /// only forward).
        pub fn advance_to(&self, ms: u64) {
            self.t.set(ms);
        }
    }

    impl Clock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.t.get()
        }
    }

    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};

    /// A launched attempt in the fake. `cancel()` pushes `id` into the shared
    /// `cancel_log` (duplicate pushes are allowed and harmless — tests assert
    /// membership, not multiplicity).
    pub struct FakeHandle {
        id: AttemptId,
        provider: String,
        cancel_log: Rc<RefCell<Vec<AttemptId>>>,
    }

    impl AttemptHandle for FakeHandle {
        fn id(&self) -> AttemptId {
            self.id
        }
        fn provider_name(&self) -> &str {
            &self.provider
        }
        fn cancel(&self) {
            self.cancel_log.borrow_mut().push(self.id);
        }
    }

    /// A scheduled virtual arrival.
    struct Pending {
        id: AttemptId,
        at_ms: u64,
        outcome: AttemptOutcome,
    }

    /// Deterministic single-threaded process layer over virtual time.
    pub struct FakeRunner {
        t: Rc<Cell<u64>>,
        script: HashMap<String, VecDeque<(AttemptOutcome, u64)>>,
        pending: Vec<Pending>,
        launch_log: Vec<(AttemptId, String, u64)>,
        cancel_log: Rc<RefCell<Vec<AttemptId>>>,
    }

    impl FakeRunner {
        pub fn with_script(
            clock: &FakeClock,
            script: HashMap<String, VecDeque<(AttemptOutcome, u64)>>,
        ) -> Self {
            FakeRunner {
                t: clock.shared(),
                script,
                pending: Vec::new(),
                launch_log: Vec::new(),
                cancel_log: Rc::new(RefCell::new(Vec::new())),
            }
        }

        /// (id, provider, launched_at_ms) per launch, in launch order.
        pub fn launch_log(&self) -> Vec<(AttemptId, String, u64)> {
            self.launch_log.clone()
        }

        /// AttemptIds that received a cancel (membership is what tests assert).
        pub fn cancel_log(&self) -> Vec<AttemptId> {
            self.cancel_log.borrow().clone()
        }
    }

    impl Runner for FakeRunner {
        type Handle = FakeHandle;

        fn launch(&mut self, provider: &Provider, id: AttemptId) -> FakeHandle {
            let now = self.t.get();
            let queue = self.script.get_mut(&provider.name).unwrap_or_else(|| {
                panic!("FakeRunner: no script for provider {:?}", provider.name)
            });
            let (outcome, dur) = queue.pop_front().unwrap_or_else(|| {
                panic!(
                    "FakeRunner: script for provider {:?} exhausted (launch id {id})",
                    provider.name
                )
            });
            let at = now.saturating_add(dur);
            self.pending.push(Pending {
                id,
                at_ms: at,
                outcome,
            });
            self.launch_log.push((id, provider.name.clone(), now));
            FakeHandle {
                id,
                provider: provider.name.clone(),
                cancel_log: Rc::clone(&self.cancel_log),
            }
        }

        fn wait_next(&mut self, deadline_ms: u64) -> Event {
            let cancelled = self.cancel_log.borrow();
            // Earliest deliverable (non-cancelled) arrival, tie-break ascending id.
            let mut best: Option<usize> = None;
            for (i, p) in self.pending.iter().enumerate() {
                if cancelled.contains(&p.id) {
                    continue; // a cancelled arrival is never delivered
                }
                match best {
                    None => best = Some(i),
                    Some(b) => {
                        let cur = &self.pending[b];
                        if p.at_ms < cur.at_ms || (p.at_ms == cur.at_ms && p.id < cur.id) {
                            best = Some(i);
                        }
                    }
                }
            }
            drop(cancelled);

            match best {
                Some(i) if self.pending[i].at_ms <= deadline_ms => {
                    // Arrival-before-Wake holds at equal time (<=).
                    let p = self.pending.remove(i);
                    let target = p.at_ms.max(self.t.get()); // never go backward
                    self.t.set(target);
                    Event::Arrival(p.id, p.outcome)
                }
                _ => {
                    let target = deadline_ms.max(self.t.get()); // never go backward
                    self.t.set(target);
                    Event::Wake
                }
            }
        }
    }
}

// Re-export FakeClock at the orchestrator-module level so `seam_tests`'s
// `use super::*;` can reach it directly as `FakeClock`.
#[cfg(test)]
pub(crate) use fakes::FakeClock;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod seam_tests {
    use super::*;

    #[test]
    fn xorshift_is_deterministic_for_fixed_seed() {
        let mut a = Xorshift::new(12345);
        let mut b = Xorshift::new(12345);
        let xs: Vec<u64> = (0..5).map(|_| a.next_u64()).collect();
        let ys: Vec<u64> = (0..5).map(|_| b.next_u64()).collect();
        assert_eq!(xs, ys);
        assert_ne!(xs[0], xs[1]); // not a constant stream
    }

    #[test]
    fn fake_clock_advances_to_next_scheduled_arrival() {
        let clock = FakeClock::new();
        assert_eq!(clock.now_ms(), 0);
        clock.advance_to(1500);
        assert_eq!(clock.now_ms(), 1500);
    }
}

// ── State-machine tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod machine_tests {
    use super::fakes::{FakeClock, FakeRunner};
    use super::*;
    use crate::ai_judge::outcome::AttemptOutcome::*;
    use crate::ai_judge::provider::Provider;
    use crate::ai_judge::response::Verdict;
    use std::collections::{HashMap, VecDeque};

    const SEED: u64 = 0xDEAD_BEEF_CAFE_F00D;

    fn provider(name: &str) -> Provider {
        Provider {
            name: name.to_string(),
            argv: vec![name.to_string()],
        }
    }

    /// Base params; tests override specific fields.
    fn base_params() -> OrchestrateParams {
        OrchestrateParams {
            total_budget_ms: 90_000,
            per_attempt_timeout_ms: 45_000,
            hedge_after_ms: 30_000,
            backoff_base_ms: 1_000,
            backoff_max_ms: 8_000,
            relaunch_floor_ms: 500,
            max_attempts: 8,
            max_nonconforming: 3,
            min_launch_ms: 1_000,
        }
    }

    type Script = Vec<(&'static str, Vec<(AttemptOutcome, u64)>)>;

    /// Build a FakeRunner over a script and run orchestrate to completion.
    /// Returns (result, launch_log, cancel_log).
    fn run(
        providers: &[Provider],
        script: Script,
        params: &OrchestrateParams,
    ) -> (
        OrchestrateResult,
        Vec<(AttemptId, String, u64)>,
        Vec<AttemptId>,
    ) {
        let clock = FakeClock::new();
        let mut map: HashMap<String, VecDeque<(AttemptOutcome, u64)>> = HashMap::new();
        for (name, events) in script {
            map.insert(name.to_string(), events.into_iter().collect());
        }
        let mut runner = FakeRunner::with_script(&clock, map);
        let mut rng = Xorshift::new(SEED);
        let result = orchestrate(&clock, &mut runner, providers, params, &mut rng);
        let launch_log = runner.launch_log();
        let cancel_log = runner.cancel_log();
        (result, launch_log, cancel_log)
    }

    // Count attempts matching (provider, tag).
    fn count(report: &JudgeReport, prov: &str, tag: &str) -> usize {
        report
            .attempts
            .iter()
            .filter(|a| a.provider == prov && a.outcome == tag)
            .count()
    }

    fn count_provider(report: &JudgeReport, prov: &str) -> usize {
        report
            .attempts
            .iter()
            .filter(|a| a.provider == prov)
            .count()
    }

    fn launches_for<'a>(
        launch_log: &'a [(AttemptId, String, u64)],
        prov: &str,
    ) -> Vec<&'a (AttemptId, String, u64)> {
        launch_log.iter().filter(|(_, p, _)| p == prov).collect()
    }

    // ── Cluster A — happy paths & immediate verdict ─────────────────────────────

    #[test]
    fn empty_then_empty_then_verdict_recovers_in_phase1_without_claude() {
        let providers = vec![provider("codex"), provider("claude")];
        // Three codex attempts: empty (1500), empty (1400), verdict (4000).
        // Backoff base 1000, two failures => gaps ~1000 + ~2000 (plus jitter),
        // total well under hedge_after_ms.
        let mut params = base_params();
        params.hedge_after_ms = 60_000;
        let script: Script = vec![
            (
                "codex",
                vec![
                    (EmptyOutput, 1500),
                    (EmptyOutput, 1400),
                    (Verdict(Verdict::Allow, "ALLOW: ok".into()), 4000),
                ],
            ),
            ("claude", vec![]),
        ];
        let (res, _ll, _cl) = run(&providers, script, &params);
        assert_eq!(res.verdict, Some(Verdict::Allow));
        assert_eq!(res.report.outcome, ReportOutcome::Verdict);
        assert_eq!(res.report.phase_reached, Phase::Phase1);
        assert_eq!(
            count_provider(&res.report, "claude"),
            0,
            "claude must never launch"
        );
    }

    #[test]
    fn legit_ask_on_attempt_one_returns_immediately() {
        let providers = vec![provider("codex"), provider("claude")];
        let script: Script = vec![
            (
                "codex",
                vec![(Verdict(Verdict::Ask, "ASK: network".into()), 4000)],
            ),
            ("claude", vec![]),
        ];
        let (res, _ll, _cl) = run(&providers, script, &base_params());
        assert_eq!(res.verdict, Some(Verdict::Ask));
        assert_eq!(res.report.outcome, ReportOutcome::Verdict);
        assert_eq!(res.report.attempts.len(), 1, "no retry on a legit ASK");
        assert_eq!(res.report.attempts[0].outcome, "verdict");
    }

    // ── Cluster B — backoff schedule ────────────────────────────────────────────

    #[test]
    fn backoff_delays_follow_exponential_within_jitter() {
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.hedge_after_ms = 10_000_000; // stay in Phase1
        params.backoff_base_ms = 1_000;
        params.backoff_max_ms = 8_000;
        params.relaunch_floor_ms = 100;
        params.max_attempts = 6;
        params.min_launch_ms = 1; // never block launches on budget floor
        params.total_budget_ms = 10_000_000;
        // Six instant EmptyOutputs so the only gaps are the scheduled backoffs.
        let codex: Vec<(AttemptOutcome, u64)> = (0..6).map(|_| (EmptyOutput, 0)).collect();
        let script: Script = vec![("codex", codex), ("claude", vec![])];
        let (res, ll, _cl) = run(&providers, script, &params);
        assert_eq!(res.report.outcome, ReportOutcome::Exhausted);
        let codex_ll = launches_for(&ll, "codex");
        assert_eq!(codex_ll.len(), 6, "max_attempts launches");
        // Replay the RNG to get the exact jitter sequence.
        let mut rng = Xorshift::new(SEED);
        let span = params.backoff_base_ms; // JITTER_SPAN
        for k in 0..(codex_ll.len() - 1) {
            let gap = codex_ll[k + 1].2 - codex_ll[k].2;
            let d_k = backoff_base_delay(params.backoff_base_ms, params.backoff_max_ms, k as u32);
            let j = rng.jitter(span);
            let expected = (d_k + j).max(params.relaunch_floor_ms);
            assert_eq!(gap, expected, "gap[{k}] exact replay");
            assert!(gap >= d_k, "gap[{k}]={gap} >= d_k={d_k}");
            assert!(gap < d_k + span, "gap[{k}]={gap} < d_k+span={}", d_k + span);
            assert!(
                gap >= params.relaunch_floor_ms,
                "gap[{k}]={gap} >= floor={}",
                params.relaunch_floor_ms
            );
        }
    }

    // ── Cluster C — hedge & phase 2 ─────────────────────────────────────────────

    #[test]
    fn all_empty_through_hedge_enters_hedge_claude_wins() {
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.hedge_after_ms = 5_000;
        params.relaunch_floor_ms = 500;
        // Many instant codex empties keep it failing through the hedge boundary.
        let codex: Vec<(AttemptOutcome, u64)> = (0..40).map(|_| (EmptyOutput, 0)).collect();
        let script: Script = vec![
            ("codex", codex),
            (
                "claude",
                vec![(Verdict(Verdict::Allow, "ALLOW: ok".into()), 3000)],
            ),
        ];
        let (res, _ll, _cl) = run(&providers, script, &params);
        assert_eq!(res.report.phase_reached, Phase::Hedge);
        assert_eq!(res.report.provider_final.as_deref(), Some("claude"));
        assert_eq!(res.verdict, Some(Verdict::Allow));
    }

    #[test]
    fn hedge_at_wake_is_independent_of_in_flight_primary() {
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.hedge_after_ms = 5_000;
        params.per_attempt_timeout_ms = 45_000;
        params.total_budget_ms = 90_000;
        // codex verdict arrives LATE (after the hedge boundary); claude verdict is fast.
        let script: Script = vec![
            (
                "codex",
                vec![(Verdict(Verdict::Allow, "ALLOW: codex".into()), 20_000)],
            ),
            (
                "claude",
                vec![(Verdict(Verdict::Allow, "ALLOW: claude".into()), 1_000)],
            ),
        ];
        let (res, ll, _cl) = run(&providers, script, &params);
        // claude must have been launched at ~hedge_after_ms even though codex was
        // still in flight.
        let claude_ll = launches_for(&ll, "claude");
        assert_eq!(claude_ll.len(), 1, "claude launched once");
        assert_eq!(
            claude_ll[0].2, params.hedge_after_ms,
            "claude launched at the hedge boundary"
        );
        // claude (faster) wins.
        assert_eq!(res.report.provider_final.as_deref(), Some("claude"));
        assert_eq!(res.verdict, Some(Verdict::Allow));
    }

    #[test]
    fn primary_timeout_hedge_wins_before_primary_timeout() {
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.hedge_after_ms = 5_000;
        params.per_attempt_timeout_ms = 45_000;
        let script: Script = vec![
            ("codex", vec![(Timeout { elapsed_ms: 45_000 }, 45_000)]),
            (
                "claude",
                vec![(Verdict(Verdict::Allow, "ALLOW: claude".into()), 3_000)],
            ),
        ];
        let (res, ll, _cl) = run(&providers, script, &params);
        assert_eq!(res.report.provider_final.as_deref(), Some("claude"));
        assert_eq!(res.verdict, Some(Verdict::Allow));
        // claude won around hedge_after_ms + 3000 = 8000, before codex's 45000 timeout.
        assert!(
            res.report.total_latency_ms < 45_000,
            "won before codex timeout"
        );
        // codex Timeout never produced a terminal verdict record.
        assert_eq!(count(&res.report, "codex", "verdict"), 0);
        let _ = launches_for(&ll, "codex");
    }

    #[test]
    fn phase2_legit_ask_wins_and_cancels_hedge() {
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.hedge_after_ms = 5_000;
        params.max_attempts = 1_000; // don't cap before codex reaches its ASK
                                     // codex keeps failing until just after the hedge boundary, then in phase 2
                                     // returns an ASK while claude is in flight.
                                     // First, instant empties to cross the boundary; then a codex ASK that
                                     // resolves before claude's slow verdict.
        let mut codex: Vec<(AttemptOutcome, u64)> = (0..40).map(|_| (EmptyOutput, 0)).collect();
        // Replace the attempt that lands after the boundary with an ASK at +1000.
        // Simpler: make codex empties instant until boundary, then ASK quick.
        // We append an ASK after enough empties; orchestrator relaunches codex in
        // hedge phase with the floor gap.
        codex.push((Verdict(Verdict::Ask, "ASK: codex".into()), 1_000));
        let script: Script = vec![
            ("codex", codex),
            (
                "claude",
                vec![(Verdict(Verdict::Allow, "ALLOW: claude slow".into()), 50_000)],
            ),
        ];
        let (res, ll, cl) = run(&providers, script, &params);
        assert_eq!(res.verdict, Some(Verdict::Ask), "codex ASK wins");
        assert_eq!(res.report.provider_final.as_deref(), Some("codex"));
        // claude was launched (in flight) and then cancelled by the winner.
        let claude_ll = launches_for(&ll, "claude");
        assert_eq!(claude_ll.len(), 1, "claude was launched");
        let claude_id = claude_ll[0].0;
        assert!(cl.contains(&claude_id), "claude's handle was cancelled");
        // claude appears as cancelled_winner, never as an awaited Allow.
        assert_eq!(count(&res.report, "claude", "cancelled_winner"), 1);
    }

    // ── Cluster D — provider disabling & immediate promotion ────────────────────

    #[test]
    fn primary_spawn_error_promotes_hedge_immediately() {
        let providers = vec![provider("codex"), provider("claude")];
        let params = base_params(); // hedge_after_ms = 30_000
        let script: Script = vec![
            (
                "codex",
                vec![(
                    SpawnError {
                        msg: "no such file".into(),
                    },
                    50,
                )],
            ),
            (
                "claude",
                vec![(Verdict(Verdict::Allow, "ALLOW: ok".into()), 3_000)],
            ),
        ];
        let (res, ll, _cl) = run(&providers, script, &params);
        assert_eq!(res.verdict, Some(Verdict::Allow));
        assert_eq!(res.report.provider_final.as_deref(), Some("claude"));
        let claude_ll = launches_for(&ll, "claude");
        assert_eq!(claude_ll.len(), 1);
        // claude launched immediately after the codex spawn error (~50ms), NOT at
        // hedge_after_ms (30_000).
        assert!(
            claude_ll[0].2 < params.hedge_after_ms,
            "claude promoted immediately at t={}",
            claude_ll[0].2
        );
    }

    #[test]
    fn immediate_fallback_promotion_when_primary_absent() {
        let providers = vec![provider("claude")];
        let script: Script = vec![(
            "claude",
            vec![(Verdict(Verdict::Allow, "ALLOW: ok".into()), 3_000)],
        )];
        let (res, ll, _cl) = run(&providers, script, &base_params());
        assert_eq!(res.verdict, Some(Verdict::Allow));
        let claude_ll = launches_for(&ll, "claude");
        assert_eq!(claude_ll.len(), 1);
        assert_eq!(claude_ll[0].2, 0, "sole provider launches at t=0");
    }

    #[test]
    fn max_nonconforming_disables_provider_on_count_reach() {
        // codex-only so disabling exhausts immediately (no hedge to promote).
        let providers = vec![provider("codex")];
        let mut params = base_params();
        params.max_nonconforming = 2;
        params.total_budget_ms = 10_000_000;
        let script: Script = vec![(
            "codex",
            vec![
                (
                    NonConforming {
                        snippet: "x".into(),
                    },
                    100,
                ),
                (
                    NonConforming {
                        snippet: "y".into(),
                    },
                    100,
                ),
                (
                    NonConforming {
                        snippet: "z".into(),
                    },
                    100,
                ),
            ],
        )];
        let (res, ll, _cl) = run(&providers, script, &params);
        // Disabled when count REACHES 2 — only 2 codex launches, no 3rd.
        let codex_ll = launches_for(&ll, "codex");
        assert_eq!(codex_ll.len(), 2, "disabled on count reach, no 3rd attempt");
        assert_eq!(res.report.outcome, ReportOutcome::Exhausted);
        // Fast exhaust (well under the budget) since claude is absent.
        assert!(
            res.report.total_latency_ms < params.total_budget_ms / 2,
            "fast exhaust at t={}",
            res.report.total_latency_ms
        );
    }

    #[test]
    fn exit_error_disables_not_retried() {
        let providers = vec![provider("codex"), provider("claude")];
        let params = base_params();
        let script: Script = vec![
            (
                "codex",
                vec![(
                    ExitError {
                        status: 1,
                        stderr_snippet: "not logged in".into(),
                    },
                    100,
                )],
            ),
            (
                "claude",
                vec![(Verdict(Verdict::Allow, "ALLOW: ok".into()), 3_000)],
            ),
        ];
        let (res, ll, _cl) = run(&providers, script, &params);
        let codex_ll = launches_for(&ll, "codex");
        assert_eq!(codex_ll.len(), 1, "no second codex attempt (disabled)");
        // claude carries to a verdict.
        assert_eq!(res.report.provider_final.as_deref(), Some("claude"));
        assert_eq!(res.verdict, Some(Verdict::Allow));
    }

    #[test]
    fn verdict_with_nonzero_exit_still_wins() {
        // The fake delivers a Verdict outcome directly (classification happened
        // upstream, verdict-first); it must win.
        let providers = vec![provider("codex"), provider("claude")];
        let script: Script = vec![
            (
                "codex",
                vec![(Verdict(Verdict::Allow, "ALLOW: ok".into()), 4_000)],
            ),
            ("claude", vec![]),
        ];
        let (res, _ll, _cl) = run(&providers, script, &base_params());
        assert_eq!(res.verdict, Some(Verdict::Allow));
        assert_eq!(res.report.provider_final.as_deref(), Some("codex"));
    }

    // ── Cluster E — termination & exhaustion ────────────────────────────────────

    #[test]
    fn both_providers_fail_to_deadline_cancels_all_exhausted() {
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.hedge_after_ms = 5_000;
        params.total_budget_ms = 60_000;
        params.relaunch_floor_ms = 500;
        params.max_attempts = 1_000; // do not cap on attempts; cap on budget
        params.min_launch_ms = 1_000;
        // Both providers loop transient empties. Give plenty so scripts never run dry.
        let codex: Vec<(AttemptOutcome, u64)> = (0..500).map(|_| (EmptyOutput, 100)).collect();
        let claude: Vec<(AttemptOutcome, u64)> = (0..500).map(|_| (EmptyOutput, 100)).collect();
        let script: Script = vec![("codex", codex), ("claude", claude)];
        let (res, _ll, _cl) = run(&providers, script, &params);
        assert_eq!(res.report.outcome, ReportOutcome::Exhausted);
        let fm = res.report.failure_mode.as_deref().unwrap_or("");
        assert!(!fm.is_empty(), "non-empty tally: {fm:?}");
        assert!(fm.contains("empty"), "tally mentions empties: {fm:?}");
    }

    #[test]
    fn primary_only_exhausts_when_hedge_absent() {
        let providers = vec![provider("codex")];
        let mut params = base_params();
        params.total_budget_ms = 30_000;
        params.max_attempts = 1_000;
        params.relaunch_floor_ms = 500;
        let codex: Vec<(AttemptOutcome, u64)> = (0..500).map(|_| (EmptyOutput, 100)).collect();
        let script: Script = vec![("codex", codex)];
        let (res, _ll, _cl) = run(&providers, script, &params);
        assert_eq!(res.verdict, None);
        assert_eq!(res.report.outcome, ReportOutcome::Exhausted);
    }

    #[test]
    fn no_providers_returns_exhausted_immediately() {
        let providers: Vec<Provider> = vec![];
        let (res, ll, _cl) = run(&providers, vec![], &base_params());
        assert_eq!(res.verdict, None);
        assert_eq!(res.report.outcome, ReportOutcome::Exhausted);
        assert_eq!(res.report.failure_mode.as_deref(), Some("no_providers"));
        assert!(res.report.attempts.is_empty());
        assert_eq!(res.report.total_latency_ms, 0);
        assert!(ll.is_empty());
    }

    // ── Cluster F — caps, floor, arrival order, cancelled records ───────────────

    #[test]
    fn max_attempts_is_a_launch_cap_final_in_flight_still_awaited() {
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.max_attempts = 3;
        params.hedge_after_ms = 10_000_000; // stay phase1, codex only
        params.total_budget_ms = 10_000_000;
        params.relaunch_floor_ms = 500;
        let script: Script = vec![
            (
                "codex",
                vec![
                    (EmptyOutput, 100),
                    (EmptyOutput, 100),
                    (Verdict(Verdict::Allow, "ALLOW: late".into()), 4_000),
                ],
            ),
            ("claude", vec![]),
        ];
        let (res, ll, _cl) = run(&providers, script, &params);
        let codex_ll = launches_for(&ll, "codex");
        assert_eq!(codex_ll.len(), 3, "exactly 3 launches, no 4th");
        // The 3rd (final) launched attempt is awaited and its Verdict wins.
        assert_eq!(res.verdict, Some(Verdict::Allow));
        assert_eq!(res.report.provider_final.as_deref(), Some("codex"));
    }

    #[test]
    fn relaunch_floor_prevents_tight_loop() {
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.hedge_after_ms = 10_000_000; // phase1 only
        params.total_budget_ms = 10_000_000;
        params.backoff_base_ms = 100;
        params.backoff_max_ms = 100;
        params.relaunch_floor_ms = 700; // floor dominates the tiny backoff
        params.max_attempts = 5;
        let codex: Vec<(AttemptOutcome, u64)> = (0..5).map(|_| (EmptyOutput, 0)).collect();
        let script: Script = vec![("codex", codex), ("claude", vec![])];
        let (_res, ll, _cl) = run(&providers, script, &params);
        let codex_ll = launches_for(&ll, "codex");
        assert!(codex_ll.len() >= 2);
        for w in codex_ll.windows(2) {
            let gap = w[1].2 - w[0].2;
            assert!(
                gap >= params.relaunch_floor_ms,
                "consecutive launches gap {gap} >= floor {}",
                params.relaunch_floor_ms
            );
        }
    }

    #[test]
    fn no_launch_when_remaining_budget_below_min_launch() {
        let providers = vec![provider("codex")];
        let mut params = base_params();
        params.hedge_after_ms = 10_000_000;
        params.total_budget_ms = 5_000;
        params.min_launch_ms = 2_000;
        params.relaunch_floor_ms = 500;
        params.max_attempts = 1_000;
        // codex: a few empties consuming budget. After ~one attempt the remaining
        // budget should drop below min_launch and end the run rather than spin.
        let codex: Vec<(AttemptOutcome, u64)> = (0..50).map(|_| (EmptyOutput, 2_000)).collect();
        let script: Script = vec![("codex", codex)];
        let (res, ll, _cl) = run(&providers, script, &params);
        assert_eq!(res.report.outcome, ReportOutcome::Exhausted);
        let codex_ll = launches_for(&ll, "codex");
        // First launch at t=0 (budget 5000, min 2000 ok). It returns at 2000;
        // relaunch ~2500; remaining 5000-2500=2500 >= 2000 so a 2nd may launch,
        // returning at 4500; then remaining < 2000 → no more. Bounded, no spin.
        assert!(codex_ll.len() <= 2, "bounded launches: {}", codex_ll.len());
    }

    #[test]
    fn arrival_order_first_valid_wins_late_loser_discarded() {
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.hedge_after_ms = 5_000;
        params.per_attempt_timeout_ms = 90_000;
        // Phase 2 with BOTH in flight: codex's single long attempt spans the hedge
        // boundary and resolves to a Verdict at the SAME absolute time as claude.
        // codex launches at 0, verdict at 8000. claude launches at the hedge
        // boundary 5000, verdict at 5000 + 3000 = 8000. Same time → lower id wins.
        let script: Script = vec![
            (
                "codex",
                vec![(Verdict(Verdict::Allow, "ALLOW: codex".into()), 8_000)],
            ),
            (
                "claude",
                vec![(Verdict(Verdict::Allow, "ALLOW: claude".into()), 3_000)],
            ),
        ];
        let (res, ll, cl) = run(&providers, script, &params);
        // Exactly one verdict returned, no panic / double return.
        assert_eq!(res.verdict, Some(Verdict::Allow));
        let verdict_recs = res
            .report
            .attempts
            .iter()
            .filter(|a| a.outcome == "verdict")
            .count();
        assert_eq!(verdict_recs, 1, "exactly one terminal verdict");
        // Find codex's last launch id and claude's launch id; the higher id at the
        // same time is the loser and must be cancelled.
        let claude_ll = launches_for(&ll, "claude");
        assert_eq!(claude_ll.len(), 1);
        let claude_id = claude_ll[0].0;
        let codex_ll = launches_for(&ll, "codex");
        let codex_last_id = codex_ll.last().unwrap().0;
        // Lower id wins; the other is the cancelled loser.
        let winner = res.report.provider_final.as_deref().unwrap();
        let loser_id = if claude_id < codex_last_id {
            // claude wins → codex loser
            assert_eq!(winner, "claude");
            codex_last_id
        } else {
            assert_eq!(winner, "codex");
            claude_id
        };
        assert!(cl.contains(&loser_id), "loser id {loser_id} cancelled");
    }

    #[test]
    fn cancelled_outcomes_logged_and_excluded_from_tallies() {
        // One cancelled_winner (loser cancelled by a winner). Plus the failure_mode
        // must not contain "cancelled".
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.hedge_after_ms = 5_000;
        params.max_attempts = 1_000;
        // codex crosses the boundary, then ASKs (winner) while claude is in flight
        // (cancelled_winner). Also codex accrued some empties → real failure tally.
        let mut codex: Vec<(AttemptOutcome, u64)> = (0..40).map(|_| (EmptyOutput, 0)).collect();
        codex.push((Verdict(Verdict::Ask, "ASK: codex".into()), 1_000));
        let script: Script = vec![
            ("codex", codex),
            (
                "claude",
                vec![(Verdict(Verdict::Allow, "ALLOW: slow".into()), 50_000)],
            ),
        ];
        let (res, _ll, _cl) = run(&providers, script, &params);
        // cancelled_winner tag present.
        assert_eq!(count(&res.report, "claude", "cancelled_winner"), 1);
        // failure_mode (for a verdict result it's None) — but the cancelled tag
        // never contributes. Recompute the tally over all attempts to prove the
        // exclusion regardless of result kind.
        let fm = derive_failure_mode(&res.report.attempts, false).unwrap_or_default();
        assert!(
            !fm.contains("cancelled"),
            "tally excludes cancelled: {fm:?}"
        );
        assert!(fm.contains("empty"), "real empties still tallied: {fm:?}");
    }

    #[test]
    fn cancelled_deadline_logged_and_excluded() {
        // Construct an in-flight-at-deadline scenario producing cancelled_deadline.
        let providers = vec![provider("codex"), provider("claude")];
        let mut params = base_params();
        params.hedge_after_ms = 1_000;
        params.total_budget_ms = 10_000;
        params.min_launch_ms = 1_000;
        // Both launched and still in flight (long durations) when the deadline hits.
        let script: Script = vec![
            (
                "codex",
                vec![(Verdict(Verdict::Allow, "ALLOW: never".into()), 100_000)],
            ),
            (
                "claude",
                vec![(Verdict(Verdict::Allow, "ALLOW: never".into()), 100_000)],
            ),
        ];
        let (res, _ll, _cl) = run(&providers, script, &params);
        assert_eq!(res.report.outcome, ReportOutcome::Exhausted);
        let cancelled_deadline = res
            .report
            .attempts
            .iter()
            .filter(|a| a.outcome == "cancelled_deadline")
            .count();
        assert!(cancelled_deadline >= 1, "at least one cancelled_deadline");
        let fm = res.report.failure_mode.as_deref().unwrap_or("");
        assert!(
            !fm.contains("cancelled"),
            "tally excludes cancelled: {fm:?}"
        );
    }
}
