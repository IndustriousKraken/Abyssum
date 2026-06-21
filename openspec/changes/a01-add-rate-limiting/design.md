# Design: Rate Limiting

## Technical Approach

A single `RateLimiter` type lives in `abyssum-core` and is shared (cheaply cloneable, e.g.
`Arc`-wrapped) across all scanners via the `ScanContext`. Scanners never sleep on their own;
they call one method before each request:

```
acquire(domain) -> waits the appropriate duration, then returns
record_signal(domain, status) -> updates per-domain backoff from a response status
```

Per-domain state lives behind an async lock (`tokio::sync::Mutex` over a
`HashMap<String, DomainState>`), so concurrent scanners interleave correctly and each host's
timing is independent. `DomainState` holds: whether the first request has happened, and the
current extra-backoff amount.

```
acquire(domain):
    state = map.entry(domain)
    if state.first_request:
        state.first_request = false
        return            # no artificial delay — fast path
    base  = uniform(min_delay, max_delay)       # random jitter
    extra = state.backoff                        # additive, >= 0
    sleep(max(min_delay, base + extra))          # floor is absolute
```

The `max(min_delay, …)` is belt-and-suspenders: `base` is already `>= min_delay`, but
asserting the floor at the sleep site makes the invariant impossible to violate as the
formula evolves.

### Why measure from request start, not response

Delay is applied *before* dispatching the request and is independent of how long the prior
request's response took. This keeps the timing pattern from leaking server latency into our
cadence (a fingerprinting vector) — the v1 guide calls this out explicitly.

## Library / Crate Choices

- **Async/locking:** `tokio` (`tokio::sync::Mutex`, `tokio::time::sleep`, `Instant`).
- **Randomness:** `rand` for the uniform `[min, max]` draw per request. The draw must be a
  fresh sample each time — never a fixed or pattern-based value (the guide flags fixed and
  linearly-increasing delays as detectable).
- **Logging:** `tracing` for debug pacing lines and warn-level backoff/signal events.
- **Config source:** `scanning.min_delay` / `scanning.max_delay` from
  `bootstrap-rust-workspace` (seconds; floats). Internally these convert to millisecond
  durations.

## Adaptive Backoff State Machine

Additive, per-domain, bounded:

| Event | Effect on the domain's extra backoff |
|-------|--------------------------------------|
| 429 / 403 observed | grow it (multiplicative step), clamped to a cap |
| non-signal request completes | decay it toward zero (multiplicative shrink) |

The exact step/decay/cap numbers are implementation detail, but anchored to the v1 security
guidelines' progressive-backoff curve (rationale below). A reasonable concrete realization,
not behaviorally binding beyond "grows on repeats, caps, then recovers":

- step on each signal so a few repeats reach tens of seconds of *extra* delay,
- a cap on the order of ~5 minutes of extra delay (mirrors the guide's 300 s ceiling),
- decay applied as clean requests succeed, returning to zero extra after sustained quiet.

### Rationale: anchoring to the v1 backoff curve

`docs/security-guidelines.md` documents a progressive curve — roughly 30 s, 60 s, 120 s,
240 s, capped at 300 s on successive errors — meant to stop hammering a server that is
already signalling distress. We preserve that *shape* (exponential-ish growth on repeated
signals, hard ceiling, recovery as signals stop) but express it as **additive extra delay on
top of the user's random base**, because the canon's invariant is that adaptive logic only
ever slows down. We deliberately drop v1's RPS/burst/cooldown bookkeeping and `retry-after`
auto-reconfiguration as out-of-scope complexity; the observable contract is just: signals
add backoff up to a cap, quiet removes it, the floor is never breached.

## Key Decisions

### Decision: One shared limiter, scanners never sleep themselves
Routing all pacing through one type makes the floor structurally enforceable and keeps every
scanner honest. A scanner that slept on its own could undercut the floor; it cannot reach the
sleep.

### Decision: First request per domain is free
Matches v1 behavior and the canon. State is keyed by domain, so each newly-seen host gets one
immediate request, then enters paced mode.

### Decision: Backoff is additive, not a replacement
The random base between min/max is always present; backoff is added on top. This satisfies
"may only ever slow down" while preserving the anti-fingerprinting randomness.

## Testing

- Unit test: repeated `acquire` for one domain always yields a delay `>= min_delay`, even
  with backoff at its cap and even after decay; the first `acquire` for a fresh domain is
  effectively zero.
- Unit test: sampled base delays fall within `[min, max]` and are not all identical (random).
- Unit test: feeding repeated 429/403 signals grows the domain's effective delay
  monotonically up to the cap; feeding subsequent non-signal completions shrinks it back
  toward the floor.
- Unit test: two domains' states are independent — signals on domain A do not change
  domain B's delay.
- Use a controllable/virtual clock (e.g. `tokio::time` pause/advance) so tests are
  deterministic and fast. **No network, no real targets** — pacing is tested by inspecting
  computed durations, not by issuing HTTP.
