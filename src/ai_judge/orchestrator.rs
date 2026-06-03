use crate::ai_judge::outcome::AttemptOutcome;

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
pub trait AttemptHandle: Send {
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

    // FakeRunner is fleshed out in Task 8 driven by the state-machine tests:
    // it holds a script of (provider_name -> VecDeque<(AttemptOutcome, duration_ms)>)
    // keyed by launch order; each launch pops the next scripted result and
    // schedules a virtual arrival at now+duration; wait_next advances virtual time
    // to min(next_arrival, deadline) honoring Arrival-before-Wake; cancellations
    // are recorded so tests can assert "loser received cancel".
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
