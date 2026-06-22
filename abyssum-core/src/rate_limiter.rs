//! Per-domain request pacing — the single pacing authority for every scanner.
//!
//! Stealth and infrastructure-respect are half of Abyssum's value (see
//! `openspec/project.md`): probing must never out-pace what the operator allowed,
//! and must back *off* — never speed up — when a target shows strain. To make that
//! structurally enforceable, all outbound timing routes through one
//! [`RateLimiter`]. Scanners never sleep on their own; they call [`acquire`] before
//! each request and [`record_signal`] after each response. A scanner that slept on
//! its own could undercut the floor; routing through this type means it cannot.
//!
//! The limiter is cheaply cloneable (it is [`Arc`]-backed) and is intended to be
//! held by the scan context built in `add-scan-orchestration` (a02) and shared
//! across all scanners, so each scanner *acquires* pacing without owning any
//! timing of its own.
//!
//! # Behavior
//!
//! - **First request per domain is free.** Reconnaissance starts immediately; only
//!   subsequent requests to that domain are paced.
//! - **Randomized base delay.** Each paced request waits a fresh uniform sample in
//!   `[min_delay, max_delay]` — never a fixed or linearly-increasing value, both of
//!   which are detectable fingerprints.
//! - **Adaptive backoff.** A `429`/`403` (rate-limit / forbidden) or a `5xx`
//!   (server distress) grows an additive, per-domain extra delay up to a cap; clean
//!   responses decay it back toward zero.
//! - **The configured minimum is an absolute floor.** Adaptive logic may only ever
//!   *increase* the delay; nothing can drop it below `min_delay`.
//! - **Distress stop condition.** When a domain's recent server-error rate stays
//!   above a threshold over a window, [`acquire`] returns [`Pace::Halt`] so the
//!   caller stops probing a target that is already struggling.
//!
//! [`acquire`]: RateLimiter::acquire
//! [`record_signal`]: RateLimiter::record_signal

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::config::ScanningConfig;

/// Extra backoff added on the *first* hostile/distress signal to a quiet domain.
///
/// Backoff grows multiplicatively, so it needs a non-zero seed to grow from. This
/// anchors the v1 security guide's progressive curve (~30s, 60s, 120s, 240s, cap).
const INITIAL_BACKOFF: Duration = Duration::from_secs(30);

/// Multiplicative growth applied to existing backoff on each further signal.
const BACKOFF_GROWTH: f64 = 2.0;

/// Hard ceiling on the extra backoff (mirrors the v1 guide's 300s ceiling).
const BACKOFF_CAP: Duration = Duration::from_secs(300);

/// Multiplicative shrink applied to backoff on each clean (non-signal) response.
const BACKOFF_DECAY: f64 = 0.5;

/// Below this, decaying backoff snaps cleanly to zero so a domain fully recovers to
/// the floor after sustained quiet (multiplicative decay never reaches zero alone).
const BACKOFF_SNAP_TO_ZERO: Duration = Duration::from_secs(1);

/// How many recent responses per domain feed the server-distress detector.
const DISTRESS_WINDOW: usize = 10;

/// Server-error (5xx) fraction over a full window at or above which a domain is
/// considered in distress and further probing halts.
const DISTRESS_ERROR_RATE: f64 = 0.5;

/// The result of [`RateLimiter::acquire`]: whether the caller may send the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pace {
    /// Cleared to proceed: any pacing delay has already elapsed.
    Proceed,
    /// The domain is in sustained distress (server-error surge); the caller must
    /// stop issuing further requests to it. Scanning should report target distress.
    Halt,
}

/// Pacing state for a single domain. Backoff is additive on top of the random base
/// delay, and the recent-response window drives the distress stop condition.
#[derive(Debug)]
struct DomainState {
    /// Whether the next request is this domain's first (which gets the free pass).
    first_request: bool,
    /// Extra additive backoff layered on top of the random base delay. `>= 0`,
    /// capped at [`BACKOFF_CAP`].
    backoff: Duration,
    /// Sliding window of the most recent responses: `true` = server error (5xx).
    recent: VecDeque<bool>,
}

impl Default for DomainState {
    fn default() -> Self {
        Self {
            first_request: true,
            backoff: Duration::ZERO,
            recent: VecDeque::with_capacity(DISTRESS_WINDOW),
        }
    }
}

impl DomainState {
    /// Push one response outcome into the sliding window, evicting the oldest once
    /// the window is full.
    fn record_outcome(&mut self, server_error: bool) {
        if self.recent.len() == DISTRESS_WINDOW {
            self.recent.pop_front();
        }
        self.recent.push_back(server_error);
    }

    /// Whether this domain's recent server-error rate is high enough, over a *full*
    /// window, to count as sustained distress. A partial window never halts — we
    /// require enough evidence first.
    fn in_distress(&self) -> bool {
        if self.recent.len() < DISTRESS_WINDOW {
            return false;
        }
        let errors = self.recent.iter().filter(|&&e| e).count();
        errors as f64 / self.recent.len() as f64 >= DISTRESS_ERROR_RATE
    }
}

/// The shared, cheaply-cloneable pacing authority. Clone it freely; all clones
/// share the same per-domain state through an [`Arc`].
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    /// Absolute floor on any pacing delay.
    min_delay: Duration,
    /// Upper bound of the randomized base-delay window.
    max_delay: Duration,
    /// Per-domain state. The mutex is never held across a sleep, so each domain's
    /// pacing is independent and concurrent scanners interleave freely.
    domains: Mutex<HashMap<String, DomainState>>,
}

impl RateLimiter {
    /// Build a limiter from the scanning config's `min_delay` / `max_delay`
    /// (seconds; floats), converting them to internal durations. Negative values
    /// are clamped to zero, and a `max` below `min` collapses to `min` (the floor
    /// always wins).
    pub fn from_config(cfg: &ScanningConfig) -> Self {
        Self::new(
            Duration::from_secs_f64(cfg.min_delay.max(0.0)),
            Duration::from_secs_f64(cfg.max_delay.max(0.0)),
        )
    }

    /// Build a limiter from explicit min/max delays. If `max < min`, the window
    /// collapses to `min`.
    pub fn new(min: Duration, max: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                min_delay: min,
                max_delay: max.max(min),
                domains: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Wait the appropriate pacing duration before a request to `domain`, then
    /// return whether the caller may proceed.
    ///
    /// - The **first** request to a freshly-seen domain returns [`Pace::Proceed`]
    ///   immediately with no artificial delay.
    /// - Subsequent requests sleep for a fresh uniform sample in
    ///   `[min_delay, max_delay]` plus the domain's current backoff, floored at
    ///   `min_delay`, then return [`Pace::Proceed`].
    /// - If the domain is in sustained distress, returns [`Pace::Halt`] *without*
    ///   sleeping and without sending.
    pub async fn acquire(&self, domain: &str) -> Pace {
        // Compute the delay under the lock, then release it *before* sleeping: the
        // mutex must never be held across an `.await` sleep, or one slow domain
        // would serialize every other domain.
        let delay = {
            let mut domains = self.inner.domains.lock().await;
            let state = domains.entry(domain.to_string()).or_default();

            if state.in_distress() {
                warn!(
                    domain = %domain,
                    "halting probes: sustained server-error rate indicates target distress"
                );
                return Pace::Halt;
            }

            if state.first_request {
                state.first_request = false;
                debug!(domain = %domain, "first request to domain; no artificial delay");
                return Pace::Proceed;
            }

            let base = self.sample_base();
            let extra = state.backoff;
            // The floor is absolute and asserted right at the sleep site, so it
            // holds no matter how the delay formula evolves.
            let delay = (base + extra).max(self.inner.min_delay);
            debug!(
                domain = %domain,
                base_ms = base.as_millis() as u64,
                backoff_ms = extra.as_millis() as u64,
                delay_ms = delay.as_millis() as u64,
                "pacing request"
            );
            delay
        };

        sleep(delay).await;
        Pace::Proceed
    }

    /// Record the outcome of a completed request to `domain` by its HTTP status.
    ///
    /// - `429` / `403` (rate-limited / forbidden) or any `5xx` (server distress)
    ///   grows the domain's extra backoff multiplicatively, clamped to the cap.
    /// - Any other status is a clean completion and decays the backoff toward zero.
    /// - `5xx` responses additionally feed the per-domain distress window that can
    ///   trip [`Pace::Halt`] in [`acquire`](Self::acquire).
    pub async fn record_signal(&self, domain: &str, status: u16) {
        let server_error = (500..600).contains(&status);
        let hostile = status == 429 || status == 403 || server_error;

        let mut domains = self.inner.domains.lock().await;
        let state = domains.entry(domain.to_string()).or_default();

        // Only 5xx counts toward the *distress* window; 429/403 grow backoff but are
        // a policy response, not a sign the server itself is failing.
        state.record_outcome(server_error);

        let before = state.backoff;
        if hostile {
            state.backoff = grow_backoff(before);
            warn!(
                domain = %domain,
                status,
                before_ms = before.as_millis() as u64,
                after_ms = state.backoff.as_millis() as u64,
                "increasing backoff after rate-limit / distress signal"
            );
        } else {
            state.backoff = decay_backoff(before);
            if before != state.backoff {
                debug!(
                    domain = %domain,
                    status,
                    before_ms = before.as_millis() as u64,
                    after_ms = state.backoff.as_millis() as u64,
                    "decaying backoff after clean response"
                );
            }
        }
    }

    /// Draw a fresh uniform base delay in `[min_delay, max_delay]`. Returns
    /// `min_delay` when the window has zero width (e.g. `min == max`).
    fn sample_base(&self) -> Duration {
        let min = self.inner.min_delay.as_secs_f64();
        let max = self.inner.max_delay.as_secs_f64();
        if max <= min {
            return self.inner.min_delay;
        }
        // Inclusive range so the draw matches the documented `[min, max]` band
        // exactly (the half-open `min..max` could never return `max`).
        let secs = rand::thread_rng().gen_range(min..=max);
        Duration::from_secs_f64(secs)
    }
}

/// Grow backoff one step: seed at [`INITIAL_BACKOFF`] from zero, otherwise multiply
/// by [`BACKOFF_GROWTH`], clamped to [`BACKOFF_CAP`].
fn grow_backoff(current: Duration) -> Duration {
    let grown = if current.is_zero() {
        INITIAL_BACKOFF
    } else {
        current.mul_f64(BACKOFF_GROWTH)
    };
    grown.min(BACKOFF_CAP)
}

/// Decay backoff one step toward zero, snapping fully to zero once it drops below
/// [`BACKOFF_SNAP_TO_ZERO`].
fn decay_backoff(current: Duration) -> Duration {
    if current.is_zero() {
        return Duration::ZERO;
    }
    let decayed = current.mul_f64(BACKOFF_DECAY);
    if decayed < BACKOFF_SNAP_TO_ZERO {
        Duration::ZERO
    } else {
        decayed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    fn limiter(min_secs: f64, max_secs: f64) -> RateLimiter {
        RateLimiter::new(
            Duration::from_secs_f64(min_secs),
            Duration::from_secs_f64(max_secs),
        )
    }

    /// Run `acquire` and report both the verdict and how long it actually slept.
    /// Under the paused clock (`start_paused = true`) the elapsed value equals the
    /// computed delay exactly, so durations can be asserted deterministically with
    /// no real waiting and no HTTP (task 4.6).
    async fn timed_acquire(rl: &RateLimiter, domain: &str) -> (Pace, Duration) {
        let start = Instant::now();
        let pace = rl.acquire(domain).await;
        (pace, start.elapsed())
    }

    // --- Pure backoff-curve helpers (deterministic, no clock) -------------------

    #[test]
    fn backoff_grows_from_zero_then_caps() {
        let mut b = Duration::ZERO;
        b = grow_backoff(b);
        assert_eq!(b, INITIAL_BACKOFF);
        // Successive growth is strictly increasing until it saturates at the cap.
        let mut prev = b;
        for _ in 0..10 {
            b = grow_backoff(b);
            assert!(b >= prev, "growth must be monotonic: {b:?} < {prev:?}");
            assert!(b <= BACKOFF_CAP, "growth must never exceed the cap");
            prev = b;
        }
        assert_eq!(b, BACKOFF_CAP, "repeated growth must reach the cap");
    }

    #[test]
    fn backoff_decays_to_exactly_zero() {
        let mut b = BACKOFF_CAP;
        let mut prev = b;
        for _ in 0..50 {
            b = decay_backoff(b);
            assert!(b <= prev, "decay must be monotonic: {b:?} > {prev:?}");
            prev = b;
        }
        assert_eq!(
            b,
            Duration::ZERO,
            "sustained quiet must recover fully to zero"
        );
    }

    // --- Task 4.1: first request free, later paced ------------------------------

    #[tokio::test(start_paused = true)]
    async fn first_request_is_free_then_subsequent_is_paced() {
        let rl = limiter(1.0, 3.0);
        let (p1, d1) = timed_acquire(&rl, "alpha.test").await;
        assert_eq!(p1, Pace::Proceed);
        assert_eq!(d1, Duration::ZERO, "first request must incur no delay");

        let (p2, d2) = timed_acquire(&rl, "alpha.test").await;
        assert_eq!(p2, Pace::Proceed);
        assert!(
            d2 >= Duration::from_secs_f64(1.0),
            "second request must be paced at >= min, got {d2:?}"
        );
    }

    // --- Task 4.2: base delays fall in [min, max] and are not all identical ------

    #[tokio::test(start_paused = true)]
    async fn base_delays_vary_within_the_band() {
        let rl = limiter(1.0, 3.0);
        let _ = rl.acquire("alpha.test").await; // consume the free first request

        let mut samples = Vec::new();
        for _ in 0..40 {
            let (_, d) = timed_acquire(&rl, "alpha.test").await;
            assert!(d >= Duration::from_secs_f64(1.0), "below min: {d:?}");
            assert!(d <= Duration::from_secs_f64(3.0), "above max: {d:?}");
            samples.push(d);
        }
        let first = samples[0];
        assert!(
            samples.iter().any(|&d| d != first),
            "delays must not all be identical (randomized pacing)"
        );
    }

    // --- Task 4.3: delay is always >= floor, even at cap and after decay ---------

    #[tokio::test(start_paused = true)]
    async fn delay_never_drops_below_floor() {
        let floor = Duration::from_secs_f64(2.0);
        let rl = limiter(2.0, 5.0);
        let _ = rl.acquire("alpha.test").await;

        // Normal paced request.
        let (_, d) = timed_acquire(&rl, "alpha.test").await;
        assert!(d >= floor, "normal: {d:?} < {floor:?}");

        // Backoff driven to its cap.
        for _ in 0..12 {
            rl.record_signal("alpha.test", 429).await;
        }
        let (_, d) = timed_acquire(&rl, "alpha.test").await;
        assert!(d >= floor, "at cap: {d:?} < {floor:?}");

        // Backoff fully decayed back down.
        for _ in 0..50 {
            rl.record_signal("alpha.test", 200).await;
        }
        let (_, d) = timed_acquire(&rl, "alpha.test").await;
        assert!(d >= floor, "after decay: {d:?} < {floor:?}");
    }

    // --- Task 4.4: 429/403 grow effective delay to a cap, then quiet shrinks it --

    #[tokio::test(start_paused = true)]
    async fn signals_grow_delay_to_cap_then_quiet_shrinks_it() {
        // min == max removes base randomness, so effective delay == base + backoff
        // and growth/decay are directly observable.
        let base = Duration::from_secs_f64(1.0);
        let rl = limiter(1.0, 1.0);
        let _ = rl.acquire("alpha.test").await; // free first request

        let (_, d0) = timed_acquire(&rl, "alpha.test").await;
        assert_eq!(d0, base, "no backoff yet -> exactly the base");

        // Alternate 403 and 429 to exercise both hostile statuses; delay must grow
        // monotonically up to the cap.
        let mut prev = d0;
        for i in 0..8 {
            let status = if i % 2 == 0 { 429 } else { 403 };
            rl.record_signal("alpha.test", status).await;
            let (_, d) = timed_acquire(&rl, "alpha.test").await;
            assert!(
                d >= prev,
                "step {i}: delay must not shrink: {d:?} < {prev:?}"
            );
            prev = d;
        }
        assert_eq!(
            prev,
            base + BACKOFF_CAP,
            "repeated signals must saturate at base + cap"
        );

        // Sustained clean completions must shrink it back to the floor. `prev`
        // still holds the saturated `base + cap` from the growth loop above.
        for _ in 0..50 {
            rl.record_signal("alpha.test", 200).await;
            let (_, d) = timed_acquire(&rl, "alpha.test").await;
            assert!(d <= prev, "decay must not grow: {d:?} > {prev:?}");
            prev = d;
        }
        assert_eq!(prev, base, "sustained quiet must return to the floor");
    }

    // --- Task 4.5: backoff is isolated per domain -------------------------------

    #[tokio::test(start_paused = true)]
    async fn signals_on_one_domain_do_not_affect_another() {
        let base = Duration::from_secs_f64(1.0);
        let rl = limiter(1.0, 1.0);
        let _ = rl.acquire("alpha.test").await;
        let _ = rl.acquire("beta.test").await;

        for _ in 0..5 {
            rl.record_signal("alpha.test", 429).await;
        }

        let (_, d_alpha) = timed_acquire(&rl, "alpha.test").await;
        let (_, d_beta) = timed_acquire(&rl, "beta.test").await;
        assert!(
            d_alpha > base,
            "signalled domain must be backed off: {d_alpha:?}"
        );
        assert_eq!(d_beta, base, "quiet domain must be unaffected: {d_beta:?}");
    }

    // --- Task 4.7: 5xx server errors increase the delay -------------------------

    #[tokio::test(start_paused = true)]
    async fn server_errors_increase_delay() {
        let rl = limiter(1.0, 1.0);
        let _ = rl.acquire("alpha.test").await;

        let (_, before) = timed_acquire(&rl, "alpha.test").await;
        rl.record_signal("alpha.test", 503).await;
        let (_, after) = timed_acquire(&rl, "alpha.test").await;
        assert!(
            after > before,
            "a 5xx must raise the next delay: {after:?} !> {before:?}"
        );
    }

    // --- Task 4.8: sustained 5xx rate halts probing, isolated per domain ---------

    #[tokio::test(start_paused = true)]
    async fn sustained_server_errors_halt_and_are_isolated() {
        let rl = limiter(1.0, 2.0);
        let _ = rl.acquire("alpha.test").await;
        let _ = rl.acquire("beta.test").await;

        // Fill alpha's window with server errors -> sustained distress.
        for _ in 0..DISTRESS_WINDOW {
            rl.record_signal("alpha.test", 500).await;
        }
        assert_eq!(
            rl.acquire("alpha.test").await,
            Pace::Halt,
            "sustained 5xx rate must halt further probing"
        );

        // Beta saw no errors and must keep going — distress is per-domain.
        assert_eq!(
            rl.acquire("beta.test").await,
            Pace::Proceed,
            "an unaffected domain must not be halted"
        );
    }

    // --- A short 5xx burst raises backoff but does not (yet) halt ---------------

    #[tokio::test(start_paused = true)]
    async fn brief_server_error_burst_does_not_halt() {
        let rl = limiter(1.0, 2.0);
        let _ = rl.acquire("alpha.test").await;

        // Fewer than a full window of errors: back off, but keep probing.
        for _ in 0..(DISTRESS_WINDOW / 2) {
            rl.record_signal("alpha.test", 500).await;
        }
        assert_eq!(
            rl.acquire("alpha.test").await,
            Pace::Proceed,
            "a partial-window error burst must not halt"
        );
    }
}
