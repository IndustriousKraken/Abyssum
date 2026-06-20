# tests-malformed-delay-config-in-rate-limiter

## Coverage gap

`RateLimiter::from_config` converts the configured `min_delay` / `max_delay`
seconds (`f64`) into `Duration`s through `dur_from_secs`
(`abyssum-core/src/rate_limit.rs:266`), which guards against out-of-range input:

```rust
fn dur_from_secs(secs: f64) -> Duration {
    if secs.is_finite() && secs > 0.0 {
        Duration::from_secs_f64(secs)
    } else {
        Duration::ZERO
    }
}
```

The guard exists because `Duration::from_secs_f64` **panics** on a negative or
NaN argument; the comment states the intent is "so a misconfigured delay can
never panic." These inputs are user-reachable: `ABYSSUM_SCANNING_MIN_DELAY=-1`,
`=nan`, or `=inf` all parse as valid `f64` in `Config::apply_env`
(`abyssum-core/src/config.rs:211-216`) and flow straight into `from_config`.

The guard is untested. The construction tests cover only well-formed input:
`from_config_converts_seconds_to_durations` (rate_limit.rs:378) and
`from_config_clamps_degenerate_band` (rate_limit.rs:391, `max < min`). No test
passes a negative, zero, NaN, or infinite delay, so the panic-prevention branch
(`else => Duration::ZERO`) and its interaction with the `max_delay.max(min_delay)`
band clamp (rate_limit.rs:144) are never exercised. A regression that dropped the
`is_finite() && secs > 0.0` guard would turn a misconfigured delay into a startup
panic with no failing test.

## Source location

- `abyssum-core/src/rate_limit.rs` — `dur_from_secs` (266-272), `from_config`
  (131-136), `new` band clamp (140-148).
- Tests land in the existing `#[cfg(test)] mod tests` in
  `abyssum-core/src/rate_limit.rs` (helper `secs` and direct access to
  `rl.inner.min_delay` / `rl.inner.max_delay` are already used there).

## Acceptance criteria (against the existing specification)

This asserts already-implemented behavior; it introduces **no** new or changed
contract. `from_config` already coerces out-of-range delays to zero without
panicking and keeps the band well-formed — these tests pin that.

Grounded in `openspec/specs/rate-limiting/spec.md`:

- **Requirement: Randomized Per-Request Pacing** — pacing draws a delay within a
  `[min, max]` band; building the limiter SHALL always yield a well-formed band
  (`max >= min`), even from out-of-range configured values.
- **Requirement: Configured Minimum Is A Hard Floor** — the limiter must be
  constructible and usable so the floor can be applied; construction SHALL NOT
  panic on a misconfigured delay.

Acceptance: `RateLimiter::from_config` (and `dur_from_secs`) map negative, zero,
NaN, and infinite configured delays to `Duration::ZERO` without panicking, and
the resulting band still satisfies `max_delay >= min_delay`.
