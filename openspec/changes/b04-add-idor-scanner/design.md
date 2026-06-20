# Design: IDOR Scanner

## Technical Approach

Implement `IdorScanner` in `abyssum-scanners`, implementing the `BaseScanner` trait from
`abyssum-core` (defined in `add-scan-orchestration`). The scanner is given a `ScanContext`
with a progress callback, a cancellation signal, and a single paced `send()` — **no raw HTTP
client** — so it owns none of those concerns and cannot bypass pacing.

The scan has three phases, all driven through `ctx.send`:

```
1. seed: ctx.send a few likely "self" endpoints (e.g. /api/users, /api/me) and harvest
   real identifiers from the bodies -> baseline references per id-shape.
   If none are harvested, fall back to a default numeric baseline ("1").

2. path enumeration: for each (id_template, baseline reference):
     baseline = ctx.send(GET, id_template.replace(id, baseline_ref))   # baseline body+status
     for each alt_ref in neighbours(baseline_ref, shape):
         ctx.check_cancellation()
         resp = ctx.send(GET, id_template.replace(id, alt_ref), credentials-omitted)
         if confirmed_idor(baseline, resp): emit Finding
         ctx.report_progress(tested, total, current)

3. parameter enumeration: for each (param endpoint, param name):
     baseline = ctx.send(GET, endpoint?param=1)
     resp     = ctx.send(GET, endpoint?param=2, credentials-omitted)
     if confirmed_idor(baseline, resp): emit Finding
```

Enumeration probes are `RequestSpec`s that **omit the context credential**, so a success
proves the object is reachable without the caller's credentials — the essence of an IDOR.
`ctx.send` still paces each one per-domain, so it never means "faster than the configured
floor per domain".

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

Body difference uses a length-then-structural comparison. **Default comparator (overridable):**
two bodies "differ materially" when their whitespace-normalized lengths differ by more than a
small tolerance (default **5%**) OR, when both parse as JSON, their sets of scalar leaf values
differ; a body equal to the baseline, or equal to the not-found/error response, counts as
"no difference". The contract is "a response identical to the baseline is not an IDOR".

## Severity and sensitive-field detection

Scan the confirmed body for sensitive field names / value patterns:
- **Critical:** credentials/secrets/financial (`password`, `token`, `api_key`, `secret`,
  `credit_card`, `bank`).
- **High:** PII (`email`, `phone`, `ssn`, `address`).
- **Medium:** user-shaped data without PII.
- **Low:** otherwise.

Each confirmed IDOR is its own `Finding` with its own `severity` from the canonical set; when
one finding aggregates several confirmed references, its severity is the highest among them.
There is **no scan-level severity field** — any "overall" figure a surface shows is a
presentation rollup (the max severity across the session's findings), not a stored value.

### Canonical finding mapping

This scanner emits `Finding`s whose `severity` is drawn from the canonical `Severity` set
(`info | low | medium | high | critical`) and whose `status` is from `{vulnerable, safe,
info}` (per `add-scan-orchestration`). The id-shape, the reference tried, and the
exposed-data class live in the finding title/description and evidence, not in new status or
severity values. The object-reference point comes from the `Target`'s `id_template` (a path
carrying an object-reference placeholder, e.g. `/api/users/{id}`); the scanner seeds no
wordlist and uses small inline reference/neighbour lists instead.

- Confirmed IDOR exposing credentials/secrets/financial data → `status: vulnerable`,
  `severity: critical`.
- Confirmed IDOR exposing PII → `status: vulnerable`, `severity: high`.
- Confirmed IDOR exposing user-shaped data without PII → `status: vulnerable`,
  `severity: medium`; otherwise `severity: low`.
- A non-baseline reference that returns an identical/error response (no cross-object
  access) → not an IDOR; `status: safe`, `severity: info` if recorded.

### Progress reporting with a dynamic candidate set

The orchestration progress contract reports a tested count out of a total, but IDOR cannot
know its total up front: neighbour candidates are generated dynamically *after* the harvest
phase establishes baseline references. The scanner resolves this in two phases:

1. **Harvest** — while seeding/harvesting baseline references, progress is reported with the
   **total unknown/indeterminate** (the candidate set does not yet exist).
2. **Enumerate** — once the neighbour candidate set is enumerated from the harvested
   baselines, the scanner sets a **concrete total** and reports `tested / total` against it,
   raising the total as further candidates are discovered.

The total therefore becomes genuinely known rather than staying a placeholder: it is
indeterminate only during harvest and reflects the real candidate count thereafter, kept
consistent with the tested/total contract.

## Library / Data Choices

- **HTTP:** issued through `ScanContext::send` (paced, UA-stamped); no raw client is exposed.
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
