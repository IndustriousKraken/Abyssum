# Tasks: malformed-delay config tests for the rate limiter

All tests land in the existing `#[cfg(test)] mod tests` in
`abyssum-core/src/rate_limit.rs`. Use `ScanningConfig { .. ScanningConfig::default() }`
to set just the delay fields, `RateLimiter::from_config(&sc)`, and assert on
`rl.inner.min_delay` / `rl.inner.max_delay` (as the existing construction tests
do). `dur_from_secs` is module-private and callable directly via `super::*`.

- [ ] 1.1 `dur_from_secs_maps_out_of_range_to_zero` — direct unit test of the
  helper: assert `dur_from_secs(-1.0)`, `dur_from_secs(0.0)`,
  `dur_from_secs(f64::NAN)`, `dur_from_secs(f64::INFINITY)`, and
  `dur_from_secs(f64::NEG_INFINITY)` each equal `Duration::ZERO`, and that a
  normal value (`dur_from_secs(2.5)`) equals `secs(2.5)`.
- [ ] 1.2 `from_config_coerces_negative_delays_to_zero_without_panic` — build a
  `ScanningConfig` with `min_delay = -1.0`, `max_delay = -2.0`; assert
  `from_config` returns (does not panic) and both `rl.inner.min_delay` and
  `rl.inner.max_delay` equal `Duration::ZERO`.
- [ ] 1.3 `from_config_coerces_nonfinite_delays_to_zero_without_panic` — build a
  `ScanningConfig` with `min_delay = f64::NAN`, `max_delay = f64::INFINITY`;
  assert `from_config` does not panic and both inner durations equal
  `Duration::ZERO`.
- [ ] 1.4 `from_config_keeps_band_well_formed_with_negative_min` — build a
  `ScanningConfig` with `min_delay = -1.0`, `max_delay = 5.0`; assert
  `rl.inner.min_delay == Duration::ZERO`, `rl.inner.max_delay == secs(5.0)`, and
  `rl.inner.max_delay >= rl.inner.min_delay` (the band-clamp invariant holds even
  when one bound was coerced).
