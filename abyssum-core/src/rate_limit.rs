//! Per-domain request pacing and adaptive backoff — Abyssum's single pacing
//! authority.
//!
//! Stealth and infrastructure-respect are half of Abyssum's value (see
//! `openspec/project.md`): testing must stay quiet and must never DoS the
//! target. To make that *structurally* true rather than a per-scanner courtesy,
//! all outbound pacing routes through one [`RateLimiter`]. Scanners never sleep
//! on their own — they cannot reach below the floor, because the only place a
//! delay is computed is here.
//!
//! The limiter is cheaply cloneable (an [`Arc`] around shared per-domain state)
//! and `Send + Sync`, so the scan context (built later in `add-scan-orchestration`)
//! holds one and hands clones to every scanner. Each clone shares the same
//! per-domain timing map.
//!
//! ## The contract
//!
//! Before each request a scanner calls [`acquire`](RateLimiter::acquire); after
//! each response it calls [`record_signal`](RateLimiter::record_signal):
//!
//! - **First request to a domain** returns immediately — reconnaissance starts
//!   without artificial delay.
//! - **Subsequent requests** wait a fresh uniform-random duration in
//!   `[min_delay, max_delay]` (no fixed cadence for signature detection to key
//!   on), plus any active backoff, **never below `min_delay`**.
//! - **Hostile or distress signals** (HTTP 429/403, or 5xx server errors) grow
//!   that domain's extra backoff multiplicatively up to a cap; clean completions
//!   decay it back toward zero.
//! - **Sustained server distress** (server-error rate over a threshold across a
//!   full window) is a stop condition: [`acquire`](RateLimiter::acquire) returns
//!   [`Pace::Halt`] so the engine stops probing that host rather than pushing
//!   through.
//!
//! The configured minimum is an **absolute floor**. Adaptive logic may only ever
//! *slow down*; no decay, jitter, or other path may produce a delay below it.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::config::ScanningConfig;

/// Extra backoff seeded on a domain's first hostile/distress signal (on top of
/// the random base delay). Anchored to the v1 progressive-backoff curve, whose
/// first step is ~30 s.
const INITIAL_BACKOFF: Duration = Duration::from_secs(30);

/// Multiplicative growth applied to the extra backoff on each repeated signal
/// (30 s → 60 → 120 → 240 → capped). Exponential-ish growth, per the v1 curve.
const BACKOFF_GROWTH: f64 = 2.0;

/// Hard ceiling on the extra backoff (~5 min, mirroring v1's 300 s ceiling).
/// Adaptive growth can never exceed this.
const BACKOFF_CAP: Duration = Duration::from_secs(300);

/// Multiplicative shrink applied to the extra backoff on each clean completion.
const BACKOFF_DECAY: f64 = 0.5;

/// Once decayed below this, the extra backoff snaps to zero so sustained quiet
/// fully recovers the floor (a multiplicative shrink alone never reaches zero).
const BACKOFF_SNAP: Duration = Duration::from_secs(1);

/// How many recent responses per domain feed the distress (stop-condition)
/// window. The window must be full before distress can halt probing, so a
/// single early error never trips it.
const DISTRESS_WINDOW: usize = 20;

/// Server-error fraction over a full [`DISTRESS_WINDOW`] above which further
/// probing of a domain is halted.
const DISTRESS_THRESHOLD: f64 = 0.5;

/// Outcome of [`RateLimiter::acquire`]: whether the caller may proceed (the
/// appropriate delay has already been awaited) or must halt because the target
/// is in sustained distress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pace {
    /// Proceed — pacing has been applied; issue the request.
    Proceed,
    /// Halt — the domain shows sustained distress; do not issue further requests
    /// to it. Surfaced so the engine can report scanning was halted rather than
    /// continuing to probe at full pace.
    Halt,
}

/// Shared, cheaply cloneable per-domain pacing authority.
///
/// Cloning is `Arc`-cheap and all clones share one per-domain state map, so the
/// limiter can be embedded in the scan context and handed to every scanner while
/// keeping each host's timing global and consistent.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Absolute floor on any applied delay (also the bottom of the random band).
    min_delay: Duration,
    /// Top of the random base-delay band (clamped to be `>= min_delay`).
    max_delay: Duration,
    /// Per-domain pacing state behind an async lock, so concurrent scanners
    /// interleave correctly and each host's timing stays independent.
    domains: Mutex<HashMap<String, DomainState>>,
}

/// Per-domain pacing state.
#[derive(Debug, Default)]
struct DomainState {
    /// `false` until the first request to this domain has been issued (the
    /// "free first request" flag).
    seen: bool,
    /// Current extra backoff added on top of the random base delay. Grows on
    /// signals (capped), decays toward zero on clean completions.
    backoff: Duration,
    /// Recent response outcomes for distress detection: `true` == server error
    /// (5xx). Bounded to [`DISTRESS_WINDOW`].
    recent: VecDeque<bool>,
}

impl RateLimiter {
    /// Build a limiter from the scanning configuration, converting the
    /// `min_delay` / `max_delay` seconds into internal durations.
    ///
    /// Non-finite or negative values are treated as zero; `max_delay` is clamped
    /// up to `min_delay` so the random band is always well-formed.
    pub fn from_config(scanning: &ScanningConfig) -> Self {
        Self::new(
            dur_from_secs(scanning.min_delay),
            dur_from_secs(scanning.max_delay),
        )
    }

    /// Build a limiter directly from durations. `max_delay` is clamped up to
    /// `min_delay` if it is smaller, keeping the random band valid.
    pub fn new(min_delay: Duration, max_delay: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                min_delay,
                max_delay: max_delay.max(min_delay),
                domains: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Pace a request to `domain`, sleeping the appropriate duration before
    /// returning.
    ///
    /// - The **first** request to a freshly-seen domain returns immediately
    ///   ([`Pace::Proceed`], no artificial delay).
    /// - **Subsequent** requests wait `max(min_delay, base + backoff)` where
    ///   `base` is a fresh uniform draw in `[min_delay, max_delay]`.
    /// - If the domain is in **sustained distress**, returns [`Pace::Halt`]
    ///   without sleeping, so the caller stops probing it.
    pub async fn acquire(&self, domain: &str) -> Pace {
        // Compute the delay (and mutate state) under the lock, then drop the lock
        // *before* sleeping so other domains/scanners are never blocked by one
        // host's pacing. `None` means "halt".
        let plan = {
            let mut domains = self.inner.domains.lock().await;
            let state = domains.entry(domain.to_string()).or_default();

            if is_distressed(state) {
                warn!(
                    domain = %domain,
                    "halting further requests to domain: sustained target distress"
                );
                None
            } else if !state.seen {
                state.seen = true;
                debug!(domain = %domain, "first request to domain — no artificial delay");
                Some(Duration::ZERO)
            } else {
                let base = self.random_base();
                // The floor is asserted here, at the sleep site, so no computed
                // delay can ever drop below the configured minimum regardless of
                // how the formula evolves.
                let delay = floor_delay(self.inner.min_delay, base, state.backoff);
                debug!(
                    domain = %domain,
                    delay_ms = delay.as_millis() as u64,
                    base_ms = base.as_millis() as u64,
                    backoff_ms = state.backoff.as_millis() as u64,
                    "pacing request"
                );
                Some(delay)
            }
        };

        match plan {
            None => Pace::Halt,
            Some(delay) => {
                if !delay.is_zero() {
                    sleep(delay).await;
                }
                Pace::Proceed
            }
        }
    }

    /// Update a domain's adaptive backoff from a response status.
    ///
    /// - **429 / 403** (rate-limit / forbidden) and **5xx** (server distress)
    ///   grow the extra backoff multiplicatively, clamped to the cap, and emit a
    ///   warn-level log.
    /// - Any other status is a clean completion: the extra backoff decays toward
    ///   zero (debug-level log).
    ///
    /// 5xx responses additionally feed the per-domain distress window that can
    /// later halt probing via [`acquire`](Self::acquire).
    pub async fn record_signal(&self, domain: &str, status: u16) {
        let mut domains = self.inner.domains.lock().await;
        let state = domains.entry(domain.to_string()).or_default();

        let server_error = (500..=599).contains(&status);
        let rate_limited = status == 429 || status == 403;

        // The distress stop-condition keys on server errors only: 429/403 mean
        // "slow down" (handled by backoff), while a surge of 5xx means the host
        // is breaking and we should stop.
        push_outcome(&mut state.recent, server_error);

        if rate_limited || server_error {
            state.backoff = grow(state.backoff);
            warn!(
                domain = %domain,
                status,
                backoff_ms = state.backoff.as_millis() as u64,
                "hostile/distress signal — increasing backoff"
            );
        } else {
            state.backoff = decay(state.backoff);
            debug!(
                domain = %domain,
                status,
                backoff_ms = state.backoff.as_millis() as u64,
                "clean completion — decaying backoff"
            );
        }
    }

    /// Draw a fresh uniform base delay in `[min_delay, max_delay]`. A fresh
    /// sample every call is deliberate — fixed or patterned timing is a
    /// fingerprinting vector.
    fn random_base(&self) -> Duration {
        let min = self.inner.min_delay.as_secs_f64();
        let max = self.inner.max_delay.as_secs_f64();
        let secs = if max > min {
            // Inclusive of `max` to match the design's stated uniform `[min, max]`
            // band (a half-open `[min, max)` draw can never sample the ceiling).
            rand::thread_rng().gen_range(min..=max)
        } else {
            // Degenerate band (min == max): the base is exactly the floor.
            min
        };
        Duration::from_secs_f64(secs)
    }
}

/// Convert a configured seconds value into a duration, treating non-finite or
/// non-positive input as zero (so a misconfigured delay can never panic).
fn dur_from_secs(secs: f64) -> Duration {
    if secs.is_finite() && secs > 0.0 {
        Duration::from_secs_f64(secs)
    } else {
        Duration::ZERO
    }
}

/// Apply the absolute floor: the effective delay is `base + backoff`, but never
/// below `min`. `base` is already `>= min`; this guard makes the invariant
/// structural even as the formula changes.
fn floor_delay(min: Duration, base: Duration, backoff: Duration) -> Duration {
    (base + backoff).max(min)
}

/// Grow extra backoff: seed it on the first signal, otherwise multiply, clamped
/// to the cap. Monotonic non-decreasing up to [`BACKOFF_CAP`].
fn grow(current: Duration) -> Duration {
    let next = if current.is_zero() {
        INITIAL_BACKOFF
    } else {
        current.mul_f64(BACKOFF_GROWTH)
    };
    next.min(BACKOFF_CAP)
}

/// Decay extra backoff toward zero, snapping to zero once it falls below
/// [`BACKOFF_SNAP`] so sustained quiet fully recovers the floor.
fn decay(current: Duration) -> Duration {
    let next = current.mul_f64(BACKOFF_DECAY);
    if next < BACKOFF_SNAP {
        Duration::ZERO
    } else {
        next
    }
}

/// Record a response outcome in the bounded distress window (`true` == 5xx).
fn push_outcome(recent: &mut VecDeque<bool>, is_error: bool) {
    if recent.len() == DISTRESS_WINDOW {
        recent.pop_front();
    }
    recent.push_back(is_error);
}

/// Whether a domain's recent responses show sustained distress: the window must
/// be full and the server-error fraction must exceed the threshold.
fn is_distressed(state: &DomainState) -> bool {
    if state.recent.len() < DISTRESS_WINDOW {
        return false;
    }
    let errors = state.recent.iter().filter(|&&e| e).count();
    (errors as f64) / (state.recent.len() as f64) > DISTRESS_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    /// Shorthand: a duration from fractional seconds.
    fn secs(s: f64) -> Duration {
        Duration::from_secs_f64(s)
    }

    // --- Pure helpers: the floor and the backoff state machine ---------------

    #[test]
    fn floor_is_absolute_even_below_min() {
        let min = secs(2.0);
        // A (hypothetical) base below the floor still clamps up to it.
        assert_eq!(floor_delay(min, secs(0.5), Duration::ZERO), min);
        // Base at the floor, no backoff → exactly the floor.
        assert_eq!(floor_delay(min, min, Duration::ZERO), min);
        // Backoff only ever adds on top; result is never below the floor.
        assert!(floor_delay(min, min, secs(10.0)) >= min);
        assert_eq!(floor_delay(min, min, secs(10.0)), secs(12.0));
    }

    #[test]
    fn backoff_grows_multiplicatively_and_caps() {
        let mut b = Duration::ZERO;
        b = grow(b);
        assert_eq!(b, INITIAL_BACKOFF); // seeded on first signal
        let mut prev = b;
        // Repeated signals grow monotonically and never exceed the cap.
        for _ in 0..12 {
            b = grow(b);
            assert!(b >= prev, "backoff must not shrink on a signal");
            assert!(b <= BACKOFF_CAP, "backoff must not exceed the cap");
            prev = b;
        }
        assert_eq!(b, BACKOFF_CAP, "repeated signals must reach the cap");
    }

    #[test]
    fn backoff_decays_to_zero() {
        let mut b = BACKOFF_CAP;
        let mut prev = b;
        for _ in 0..50 {
            b = decay(b);
            assert!(b <= prev, "decay must not grow backoff");
            prev = b;
            if b.is_zero() {
                break;
            }
        }
        assert_eq!(b, Duration::ZERO, "sustained quiet must fully recover");
    }

    // --- Construction --------------------------------------------------------

    #[test]
    fn from_config_converts_seconds_to_durations() {
        let sc = ScanningConfig {
            min_delay: 0.5,
            max_delay: 1.5,
            max_concurrency: 4,
        };
        let rl = RateLimiter::from_config(&sc);
        assert_eq!(rl.inner.min_delay, secs(0.5));
        assert_eq!(rl.inner.max_delay, secs(1.5));
    }

    #[test]
    fn from_config_clamps_degenerate_band() {
        // max < min is repaired to a valid (degenerate) band.
        let sc = ScanningConfig {
            min_delay: 3.0,
            max_delay: 1.0,
            max_concurrency: 4,
        };
        let rl = RateLimiter::from_config(&sc);
        assert_eq!(rl.inner.min_delay, secs(3.0));
        assert_eq!(rl.inner.max_delay, secs(3.0));
    }

    // --- Timing (driven by the paused virtual clock — no HTTP) ---------------

    /// Task 4.1: first acquire for a fresh domain is effectively zero; a later
    /// one is paced.
    #[tokio::test(start_paused = true)]
    async fn first_request_is_immediate_then_paced() {
        let rl = RateLimiter::new(secs(1.0), secs(3.0));

        let t0 = Instant::now();
        assert_eq!(rl.acquire("a.com").await, Pace::Proceed);
        assert_eq!(t0.elapsed(), Duration::ZERO, "first request must be free");

        let t1 = Instant::now();
        rl.acquire("a.com").await;
        assert!(
            t1.elapsed() >= secs(1.0),
            "second request must be paced at >= min"
        );
    }

    /// Task 4.2: sampled base delays fall within `[min, max]` and are not all
    /// identical.
    #[tokio::test(start_paused = true)]
    async fn base_delays_within_band_and_varied() {
        let rl = RateLimiter::new(secs(1.0), secs(3.0));
        rl.acquire("a.com").await; // burn the free first request

        let mut seen = std::collections::HashSet::new();
        for _ in 0..40 {
            let t = Instant::now();
            rl.acquire("a.com").await;
            let d = t.elapsed();
            assert!(d >= secs(1.0), "delay {d:?} below min");
            assert!(d <= secs(3.0), "delay {d:?} above max (no backoff active)");
            seen.insert(d.as_nanos());
        }
        assert!(seen.len() > 1, "delays must not all be identical");
    }

    /// Task 4.3: every delay is `>= min_delay`, including at the backoff cap and
    /// after decay.
    #[tokio::test(start_paused = true)]
    async fn delay_never_below_min_across_backoff_lifecycle() {
        let rl = RateLimiter::new(secs(1.0), secs(2.0));
        rl.acquire("a.com").await; // seen

        // Drive backoff up to its cap.
        for _ in 0..10 {
            rl.record_signal("a.com", 429).await;
        }
        for _ in 0..5 {
            let t = Instant::now();
            rl.acquire("a.com").await;
            assert!(t.elapsed() >= secs(1.0), "floor breached at cap");
        }

        // Decay all the way back down.
        for _ in 0..40 {
            rl.record_signal("a.com", 200).await;
        }
        for _ in 0..5 {
            let t = Instant::now();
            rl.acquire("a.com").await;
            assert!(t.elapsed() >= secs(1.0), "floor breached after decay");
        }
    }

    /// Task 4.4: repeated 429/403 signals grow the effective delay monotonically
    /// up to the cap; sustained non-signal completions shrink it back toward the
    /// floor. Uses a degenerate band (min == max) so the base is constant and the
    /// backoff component is observable directly.
    #[tokio::test(start_paused = true)]
    async fn signals_grow_delay_to_cap_then_recover() {
        let base = secs(1.0);
        let rl = RateLimiter::new(base, base); // no jitter
        rl.acquire("a.com").await; // seen

        // Grow: each 429 lifts the next paced delay, monotonically, to a plateau.
        let mut prev = Duration::ZERO;
        let mut samples = Vec::new();
        for _ in 0..8 {
            rl.record_signal("a.com", 429).await;
            let t = Instant::now();
            rl.acquire("a.com").await;
            let d = t.elapsed();
            assert!(d >= prev, "delay must grow monotonically: {d:?} < {prev:?}");
            prev = d;
            samples.push(d);
        }
        let n = samples.len();
        assert_eq!(
            samples[n - 1],
            samples[n - 2],
            "delay must plateau at the cap"
        );
        assert_eq!(
            samples[n - 1],
            base + BACKOFF_CAP,
            "plateau must equal base + cap"
        );

        // Recover: sustained clean completions shrink the delay back to the floor.
        let mut prev = samples[n - 1];
        for _ in 0..15 {
            rl.record_signal("a.com", 200).await;
            let t = Instant::now();
            rl.acquire("a.com").await;
            let d = t.elapsed();
            assert!(
                d <= prev,
                "delay must shrink monotonically: {d:?} > {prev:?}"
            );
            prev = d;
        }
        assert_eq!(prev, base, "delay must recover to the floor band");
    }

    /// Task 4.5: signals on one domain do not change another domain's delay.
    #[tokio::test(start_paused = true)]
    async fn signals_are_isolated_per_domain() {
        let base = secs(1.0);
        let rl = RateLimiter::new(base, base);
        rl.acquire("a.com").await; // seen + free
        rl.acquire("b.com").await; // seen + free

        // Pile backoff onto a.com only.
        for _ in 0..5 {
            rl.record_signal("a.com", 429).await;
        }

        let ta = Instant::now();
        rl.acquire("a.com").await;
        let da = ta.elapsed();

        let tb = Instant::now();
        rl.acquire("b.com").await;
        let db = tb.elapsed();

        assert!(da > base, "domain a should carry its backoff: {da:?}");
        assert_eq!(
            db, base,
            "domain b must be unaffected by a's signals: {db:?}"
        );
    }

    /// Per-domain independence also means each newly-seen domain gets its own
    /// free first request even after another has been paced heavily.
    #[tokio::test(start_paused = true)]
    async fn each_new_domain_gets_a_free_first_request() {
        let rl = RateLimiter::new(secs(1.0), secs(2.0));
        rl.acquire("a.com").await;
        for _ in 0..3 {
            rl.acquire("a.com").await; // pace a.com a few times
        }

        let t = Instant::now();
        rl.acquire("b.com").await;
        assert_eq!(
            t.elapsed(),
            Duration::ZERO,
            "new domain's first request is free"
        );
    }

    /// A 403 grows backoff just like a 429.
    #[tokio::test(start_paused = true)]
    async fn forbidden_status_adds_backoff() {
        let base = secs(1.0);
        let rl = RateLimiter::new(base, base);
        rl.acquire("a.com").await;
        rl.record_signal("a.com", 403).await;

        let t = Instant::now();
        rl.acquire("a.com").await;
        assert!(t.elapsed() > base, "403 must add backoff");
    }

    /// Spec "Server errors increase backoff": a 5xx lengthens the next delay.
    #[tokio::test(start_paused = true)]
    async fn server_errors_increase_delay() {
        let base = secs(1.0);
        let rl = RateLimiter::new(base, base);
        rl.acquire("a.com").await;
        rl.record_signal("a.com", 500).await;

        let t = Instant::now();
        rl.acquire("a.com").await;
        assert!(t.elapsed() > base, "5xx must increase the delay");
    }

    /// Spec "Sustained distress halts further probing": a full window of server
    /// errors stops probing that domain, while a healthy domain still proceeds.
    #[tokio::test(start_paused = true)]
    async fn sustained_distress_halts_only_the_sick_domain() {
        let base = secs(1.0);
        let rl = RateLimiter::new(base, base);
        assert_eq!(rl.acquire("sick.com").await, Pace::Proceed);

        for _ in 0..DISTRESS_WINDOW {
            rl.record_signal("sick.com", 503).await;
        }
        assert_eq!(
            rl.acquire("sick.com").await,
            Pace::Halt,
            "sustained 5xx must halt the domain"
        );

        // A different, healthy domain is unaffected.
        assert_eq!(rl.acquire("ok.com").await, Pace::Proceed);
    }

    /// A scattering of 5xx below the threshold does not halt probing.
    #[tokio::test(start_paused = true)]
    async fn occasional_errors_do_not_halt() {
        let base = secs(1.0);
        let rl = RateLimiter::new(base, base);
        rl.acquire("a.com").await;
        // Fill the window mostly with successes.
        for i in 0..DISTRESS_WINDOW {
            let status = if i % 5 == 0 { 500 } else { 200 };
            rl.record_signal("a.com", status).await;
        }
        assert_eq!(
            rl.acquire("a.com").await,
            Pace::Proceed,
            "a low error rate must not halt probing"
        );
    }

    /// Clones share per-domain state — proving the limiter is the single shared
    /// authority the scan context will hand to every scanner.
    #[tokio::test(start_paused = true)]
    async fn clones_share_per_domain_state() {
        let rl = RateLimiter::new(secs(1.0), secs(1.0));
        let rl2 = rl.clone();

        rl.acquire("a.com").await; // mark a.com seen via one handle

        // The clone sees a.com as already-seen, so its request is paced, not free.
        let t = Instant::now();
        rl2.acquire("a.com").await;
        assert!(
            t.elapsed() >= secs(1.0),
            "clones must share state: second handle should pace, not free-pass"
        );
    }
}
