## Why

Stealth and good citizenship are half of Abyssum's value proposition (see
`openspec/project.md`): testing must stay within authorized scope without tripping rate
limits, WAFs, or account lockouts. The shared scan engine therefore needs a single pacing
authority that every scanner and surface routes its requests through, so "fast" can never
mean "faster than the operator allowed."

This change adds the `rate-limiting` capability: per-domain randomized request pacing with a
hard floor, plus adaptive backoff that reacts to rate-limit/forbidden signals by slowing
*down* — never speeding up. It depends only on the bootstrapped configuration/error/logging
spine (`bootstrap-rust-workspace`); the scanners (#5–#10) and orchestration (#2) consume it.

## What Changes

### 1. Per-domain randomized pacing

Before each request to a domain, the rate limiter waits a random duration drawn uniformly
between the configured minimum and maximum delay. Pacing state is tracked independently per
host so one domain's activity never affects another's timing.

### 2. First-request fast path

The first request to a given domain incurs no artificial delay, so reconnaissance starts
immediately; subsequent requests to that domain are paced.

### 3. Adaptive backoff on hostile signals

When a response indicates rate limiting or forbidden access (HTTP 429/403), the limiter adds
extra backoff for that domain on top of the random base delay. Repeated signals grow the
extra backoff up to a cap; as signals stop, it decays back toward zero.

### 4. The configured minimum delay is a hard floor

Adaptive logic may only ever increase the delay. No condition — backoff decay, jitter, or
otherwise — may ever produce a delay below the operator's configured minimum.

## Impact

- Adds the `rate-limiting` capability to `openspec/specs/`.
- Consumes the `scanning.min_delay` / `scanning.max_delay` config keys owned by
  `bootstrap-rust-workspace`.
- Unblocks every scanner (#5–#10): they call this limiter so probing respects the floor.
- No new user-facing surface; behavior is observable through scanner pacing and logs.
