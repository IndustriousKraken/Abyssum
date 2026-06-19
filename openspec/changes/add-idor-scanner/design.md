# Design: IDOR Scanner

## Technical Approach

Implement `IdorScanner` in `abyssum-scanners`, implementing the `BaseScanner` trait from
`abyssum-core` (defined in `add-scan-orchestration`). The scanner receives a `ScanContext`
providing the HTTP client, the rate limiter, a progress callback, and a cancellation
signal — it owns none of those concerns itself.

The scan has three phases, all driven through the scan engine:

```
1. seed: probe a few likely "self" endpoints (e.g. /api/users, /api/me) and harvest
   real identifiers from the bodies -> baseline references per id-shape.
   If none are harvested, fall back to a default numeric baseline ("1").

2. path enumeration: for each (endpoint pattern, baseline reference):
     baseline = GET pattern.replace(id, baseline_ref)   # captures baseline body+status
     for each alt_ref in neighbours(baseline_ref, shape):
         check cancellation
         await rate_limiter.acquire(domain)             # enforces the pacing floor
         resp = GET pattern.replace(id, alt_ref)        # WITHOUT the Authorization header
         if confirmed_idor(baseline, resp): emit Finding
         progress(tested, total, current)

3. parameter enumeration: for each (param endpoint, param name):
     baseline = GET endpoint?param=1
     resp     = GET endpoint?param=2
     if confirmed_idor(baseline, resp): emit Finding
```

Requests in the enumeration phases are issued with the `Authorization` header stripped, so
a success proves the object is reachable without the caller's credentials — the essence of
an IDOR. Concurrency (if any) flows through the rate limiter, so it never means "faster
than the configured floor per domain".

## Identifier shapes and neighbour generation

| Shape | Baseline source | Alternatives probed |
|-------|-----------------|---------------------|
| numeric | harvested digit / default `1` | the few integers immediately around the baseline |
| uuid | harvested UUID | a small fixed set of well-known/sentinel UUIDs |
| username | harvested name | a small fixed set of common account names |
| email | harvested address | a small fixed set of common addresses |

The exact wordlists and neighbour window are implementation data, not behavior; the
observable contract is "probe references *other than* the baseline of the same shape".

## Confirmation rules (informs the spec's behavior, kept testable)

`confirmed_idor(baseline, resp)` is true iff **all** hold:
- `resp` status is success (2xx);
- the reference tried is not the baseline reference;
- `resp` body is not an error/not-found page (negative-indicator scan);
- `resp` body differs materially from the baseline body (so an identical echo of the same
  object, or a generic shell page served for every id, is not reported).

Body difference uses a length-then-structural comparison (JSON-aware when both parse as
JSON, byte comparison otherwise). The exact comparator is implementation detail; the
contract is "a response identical to the baseline is not an IDOR".

## Severity and sensitive-field detection

Scan the confirmed body for sensitive field names / value patterns:
- **Critical:** credentials/secrets/financial (`password`, `token`, `api_key`, `secret`,
  `credit_card`, `bank`).
- **High:** PII (`email`, `phone`, `ssn`, `address`).
- **Medium:** user-shaped data without PII.
- **Low:** otherwise.

The finding's overall severity is the highest among its confirmed references.

## Library / Data Choices

- **HTTP:** `reqwest` client supplied by `ScanContext`.
- **Pattern / parameter heuristics:** small inline detection lists (object-reference
  parameter names, id-shape patterns) kept in code as heuristics — these are detection logic,
  not the curated, DB-seeded wordlists used by the discovery scanners. No user-uploaded
  wordlists in v1 (see `project.md` non-goals).
- **JSON / body inspection:** `serde_json` for parse-aware comparison and field harvesting,
  with regex fallbacks for non-JSON bodies.

## Testing

- Unit tests for neighbour generation per id-shape, the error/not-found classifier, the
  baseline-difference comparator, and severity scoring over representative bodies.
- Integration test against a **local mock HTTP server** (e.g. `wiremock`/`axum` test
  server) serving object endpoints where some ids return distinct unauthorized data
  (vulnerable) and some return only the caller's own object or a generic shell (safe);
  assert the scanner reports exactly the vulnerable references with the right evidence.
- Tests that cancellation stops promptly with a partial result and that requests are paced
  through the rate limiter.
- **No real targets.** All tests are local and deterministic.
