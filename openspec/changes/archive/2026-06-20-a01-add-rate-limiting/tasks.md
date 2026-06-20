# Tasks

## 1. Rate limiter skeleton
- [x] 1.1 Add a `RateLimiter` type in `abyssum-core` that is cheaply cloneable and holds per-domain state behind an async lock
- [x] 1.2 Construct it from the `scanning.min_delay` / `scanning.max_delay` config values, converting seconds to internal durations
- [x] 1.3 Define a per-domain state record holding the first-request flag and the current extra-backoff amount
- [x] 1.4 Expose the limiter on the scan context so scanners acquire pacing without owning timing themselves

## 2. Per-domain pacing
- [x] 2.1 Implement `acquire(domain)`: on the first request to a domain, return immediately with no artificial delay and mark the domain as seen
- [x] 2.2 On subsequent requests, draw a fresh uniform random delay in `[min_delay, max_delay]` and sleep before returning
- [x] 2.3 Key all state by domain so each host's timing is independent of every other host
- [x] 2.4 Apply the configured minimum as a hard floor at the sleep site so no computed delay can ever drop below it

## 3. Adaptive backoff
- [x] 3.1 Implement `record_signal(domain, status)`: on a 429 or 403, grow that domain's extra backoff by a multiplicative step, clamped to the cap
- [x] 3.2 On a non-signal completion, decay that domain's extra backoff toward zero
- [x] 3.3 In `acquire`, add the domain's current extra backoff on top of the random base delay (still floored by the minimum)
- [x] 3.4 Emit warn-level logs when backoff grows due to a signal, and debug-level logs for normal pacing
- [x] 3.5 Treat 5xx server errors as distress: grow that domain's backoff like a hostile signal
- [x] 3.6 Track a per-domain recent-response window and halt further requests (`acquire` returns `Pace::Halt`) when the server-error rate stays above threshold, reporting target distress

## 4. Tests (local only — no real targets)
- [x] 4.1 Test that the first `acquire` for a fresh domain returns effectively zero delay and a later `acquire` does not
- [x] 4.2 Test that sampled base delays fall within `[min, max]` and are not all identical
- [x] 4.3 Test that every `acquire` delay is `>= min_delay`, including when backoff is at its cap and after decay
- [x] 4.4 Test that repeated 429/403 signals grow a domain's effective delay monotonically up to the cap, then sustained non-signal completions shrink it back toward the floor
- [x] 4.5 Test that signals on one domain do not change another domain's delay
- [x] 4.6 Drive timing through a virtual/paused clock so the suite is deterministic and issues no HTTP
- [x] 4.7 Test that 5xx server errors increase a domain's effective delay
- [x] 4.8 Test that a sustained 5xx error rate over a window halts further probing and is isolated per domain
