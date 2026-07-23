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
//! - **Support-infrastructure lane.** A request marked as a support-infrastructure
//!   lookup — a query to a third-party service the operator uses to *map* the
//!   target (a public DNS resolver, a certificate-transparency / RDAP aggregator) —
//!   is paced through [`acquire_support`] by a separate, faster policy. It is not
//!   held to the target floor and the target-distress halt never stops it, but it
//!   still backs off (via [`record_signal_support`]) when the support service itself
//!   signals rate limiting.
//!
//! [`acquire`]: RateLimiter::acquire
//! [`acquire_support`]: RateLimiter::acquire_support
//! [`record_signal`]: RateLimiter::record_signal
//! [`record_signal_support`]: RateLimiter::record_signal_support

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

/// One lane's randomized pacing window: a request's base delay is drawn uniformly
/// from `[min_delay, max_delay]`, and `min_delay` is that lane's floor.
#[derive(Debug, Clone, Copy)]
struct Policy {
    min_delay: Duration,
    max_delay: Duration,
}

impl Policy {
    /// Build a policy, collapsing an inverted window (`max < min`) to `[min, min]`
    /// so the floor always wins.
    fn new(min: Duration, max: Duration) -> Self {
        Self {
            min_delay: min,
            max_delay: max.max(min),
        }
    }

    /// Draw a fresh uniform base delay in `[min_delay, max_delay]`. Returns
    /// `min_delay` when the window has zero width (e.g. `min == max`).
    fn sample(&self) -> Duration {
        let min = self.min_delay.as_secs_f64();
        let max = self.max_delay.as_secs_f64();
        if max <= min {
            return self.min_delay;
        }
        // Inclusive range so the draw matches the documented `[min, max]` band
        // exactly (the half-open `min..max` could never return `max`).
        let secs = rand::thread_rng().gen_range(min..=max);
        Duration::from_secs_f64(secs)
    }
}

struct Inner {
    /// Pacing for target traffic: the conservative floor, backoff, and distress halt.
    target: Policy,
    /// Pacing for support-infrastructure lookups (public resolvers, CT/RDAP
    /// aggregators): a separate, faster window that is NOT held to the target floor
    /// and whose lane the target-distress halt never stops.
    support: Policy,
    /// Per-domain target-traffic state. The mutex is never held across a sleep, so
    /// each domain's pacing is independent and concurrent scanners interleave freely.
    target_domains: Mutex<HashMap<String, DomainState>>,
    /// Per-host support-lookup state, kept separate so a support service's backoff
    /// never touches target pacing and vice versa.
    support_domains: Mutex<HashMap<String, DomainState>>,
}

impl RateLimiter {
    /// Build a limiter from the scanning config's `min_delay` / `max_delay`
    /// (seconds; floats), converting them to internal durations. Negative values
    /// are clamped to zero, and a `max` below `min` collapses to `min` (the floor
    /// always wins).
    pub fn from_config(cfg: &ScanningConfig) -> Self {
        Self::with_policies(
            Duration::from_secs_f64(cfg.min_delay.max(0.0)),
            Duration::from_secs_f64(cfg.max_delay.max(0.0)),
            Duration::from_secs_f64(cfg.support_min_delay.max(0.0)),
            Duration::from_secs_f64(cfg.support_max_delay.max(0.0)),
        )
    }

    /// Build a limiter from explicit target min/max delays. If `max < min`, the
    /// window collapses to `min`. The support lane defaults to the same window as
    /// the target lane; callers that exercise the support lane set it explicitly
    /// with [`with_policies`](Self::with_policies).
    pub fn new(min: Duration, max: Duration) -> Self {
        Self::with_policies(min, max, min, max)
    }

    /// Build a limiter with explicit target and support pacing windows. Either
    /// window collapses to `[min, min]` when its `max < min`, so each lane's floor
    /// always wins.
    pub fn with_policies(
        target_min: Duration,
        target_max: Duration,
        support_min: Duration,
        support_max: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                target: Policy::new(target_min, target_max),
                support: Policy::new(support_min, support_max),
                target_domains: Mutex::new(HashMap::new()),
                support_domains: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Wait the target-traffic pacing duration before a request to `domain`, then
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
        self.acquire_on(domain, &self.inner.target, &self.inner.target_domains, true)
            .await
    }

    /// Like [`acquire`](Self::acquire) but for a **support-infrastructure lookup**
    /// (a public DNS resolver, a certificate-transparency / RDAP aggregator): paced
    /// by the separate, faster support policy, never held to the target floor, and
    /// never halted by the target-distress stop condition. It still honors any
    /// backoff grown from the support service's own rate-limit signals (see
    /// [`record_signal_support`](Self::record_signal_support)).
    pub async fn acquire_support(&self, domain: &str) -> Pace {
        self.acquire_on(
            domain,
            &self.inner.support,
            &self.inner.support_domains,
            false,
        )
        .await
    }

    /// Shared pacing core for one lane: compute the delay under the lock (never held
    /// across the sleep, or one slow domain would serialize every other), then sleep
    /// and clear the caller to proceed. `halt_on_distress` gates the distress stop
    /// condition to the target lane only — support lookups are never halted by the
    /// target's distress.
    async fn acquire_on(
        &self,
        domain: &str,
        policy: &Policy,
        domains: &Mutex<HashMap<String, DomainState>>,
        halt_on_distress: bool,
    ) -> Pace {
        let delay = {
            let mut domains = domains.lock().await;
            let state = domains.entry(domain.to_string()).or_default();

            if halt_on_distress && state.in_distress() {
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

            let base = policy.sample();
            let extra = state.backoff;
            // The floor is absolute and asserted right at the sleep site, so it
            // holds no matter how the delay formula evolves. Each lane is floored at
            // its *own* minimum — the support lane at its faster floor, never the
            // target one.
            let delay = (base + extra).max(policy.min_delay);
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
        self.record_on(domain, status, &self.inner.target_domains)
            .await
    }

    /// Record the outcome of a completed **support-infrastructure** lookup to
    /// `domain` by its HTTP status. A rate-limit / distress status from the support
    /// service (`429`/`403`/`5xx`) grows that service's backoff so the support lane
    /// still yields when the service pushes back; a clean response decays it. The
    /// distress window is recorded but never halts the support lane — only
    /// [`acquire`](Self::acquire) (target traffic) consults it.
    pub async fn record_signal_support(&self, domain: &str, status: u16) {
        self.record_on(domain, status, &self.inner.support_domains)
            .await
    }

    /// Shared backoff / distress bookkeeping for one lane's per-domain map.
    async fn record_on(
        &self,
        domain: &str,
        status: u16,
        domains: &Mutex<HashMap<String, DomainState>>,
    ) {
        let server_error = (500..600).contains(&status);
        let hostile = status == 429 || status == 403 || server_error;

        let mut domains = domains.lock().await;
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

    // --- g04: the support lane -------------------------------------------------

    /// A limiter with distinct target and support windows, for the support-lane
    /// tests. All four values are seconds.
    fn lanes(t_min: f64, t_max: f64, s_min: f64, s_max: f64) -> RateLimiter {
        RateLimiter::with_policies(
            Duration::from_secs_f64(t_min),
            Duration::from_secs_f64(t_max),
            Duration::from_secs_f64(s_min),
            Duration::from_secs_f64(s_max),
        )
    }

    /// `acquire_support` timed like [`timed_acquire`], under the paused clock.
    async fn timed_acquire_support(rl: &RateLimiter, domain: &str) -> (Pace, Duration) {
        let start = Instant::now();
        let pace = rl.acquire_support(domain).await;
        (pace, start.elapsed())
    }

    // Support lookups are paced by the faster support window, not the target floor.
    #[tokio::test(start_paused = true)]
    async fn support_lookups_are_not_paced_at_the_target_floor() {
        // Target floor 2s; support window a fast, bounded 0.1s.
        let rl = lanes(2.0, 2.0, 0.1, 0.1);

        // Target lane: first free, then held at the 2s floor.
        let _ = rl.acquire("target.test").await;
        let (_, target_delay) = timed_acquire(&rl, "target.test").await;
        assert!(
            target_delay >= Duration::from_secs_f64(2.0),
            "target probe must sit at the floor, got {target_delay:?}"
        );

        // Support lane: first free, then paced by the fast support window — well
        // below the target floor, yet still honoring its own (fast) floor.
        let _ = rl.acquire_support("resolver.test").await;
        let (pace, support_delay) = timed_acquire_support(&rl, "resolver.test").await;
        assert_eq!(pace, Pace::Proceed);
        assert!(
            support_delay < Duration::from_secs_f64(2.0),
            "support lookup must not be held to the target floor, got {support_delay:?}"
        );
        assert!(
            support_delay >= Duration::from_secs_f64(0.1),
            "support lookup still honors its own fast floor, got {support_delay:?}"
        );
    }

    // The target-distress halt never stops a support lookup, even to the same host.
    #[tokio::test(start_paused = true)]
    async fn target_distress_does_not_halt_support_lookups() {
        let rl = lanes(1.0, 1.0, 0.1, 0.1);

        // Drive a domain into sustained target distress on the target lane.
        for _ in 0..DISTRESS_WINDOW {
            rl.record_signal("dns.test", 500).await;
        }
        assert_eq!(
            rl.acquire("dns.test").await,
            Pace::Halt,
            "sustained 5xx must halt target probing"
        );

        // The very same host, queried as a support lookup, is never halted by the
        // target's distress — the two lanes keep independent state.
        assert_eq!(
            rl.acquire_support("dns.test").await,
            Pace::Proceed,
            "target distress must not halt a support lookup"
        );
        assert_eq!(
            rl.acquire_support("dns.test").await,
            Pace::Proceed,
            "and stays un-halted on subsequent support lookups"
        );
    }

    // A support service that returns a rate-limit signal still triggers backoff on
    // the support lane, and the target lane is untouched by it.
    #[tokio::test(start_paused = true)]
    async fn support_rate_limit_signal_backs_off_the_support_lane() {
        // Fixed support window so the base delay is constant and backoff is visible.
        let rl = lanes(1.0, 1.0, 0.1, 0.1);
        let _ = rl.acquire_support("resolver.test").await; // free first request

        let (_, before) = timed_acquire_support(&rl, "resolver.test").await;
        // The support service pushes back with a 429.
        rl.record_signal_support("resolver.test", 429).await;
        let (_, after) = timed_acquire_support(&rl, "resolver.test").await;
        assert!(
            after > before,
            "a support-service rate-limit signal must grow the support backoff: {after:?} !> {before:?}"
        );

        // The target lane saw none of this — its state is independent, so this host's
        // first *target* request is still free.
        let (_, target_first) = timed_acquire(&rl, "resolver.test").await;
        assert_eq!(
            target_first,
            Duration::ZERO,
            "the support signal must not touch the target lane"
        );
    }

    // A big resolver phase finishes far faster than the same many target probes —
    // the whole point of g04 (a ~2000-lookup brute-force must not serialize at the
    // target floor).
    #[tokio::test(start_paused = true)]
    async fn support_phase_completes_far_faster_than_target_probes() {
        const N: usize = 50;
        // Target floor 1s vs a 0.05s support window.
        let rl = lanes(1.0, 1.0, 0.05, 0.05);

        let target_start = Instant::now();
        for _ in 0..N {
            let _ = rl.acquire("target.test").await;
        }
        let target_total = target_start.elapsed();

        let support_start = Instant::now();
        for _ in 0..N {
            let _ = rl.acquire_support("resolver.test").await;
        }
        let support_total = support_start.elapsed();

        // Both got one free first request; the rest are paced by their lane.
        assert!(
            support_total * 4 < target_total,
            "support phase ({support_total:?}) should be far faster than {N} target probes ({target_total:?})"
        );
    }
}
