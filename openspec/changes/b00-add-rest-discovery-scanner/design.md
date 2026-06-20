# Design: REST Discovery Scanner

## Technical Approach

Implement `RestDiscoveryScanner` in `abyssum-scanners`, implementing the `BaseScanner`
trait from `abyssum-core` (defined in `add-scan-orchestration`). The scanner receives a
`ScanContext` providing the HTTP client, the rate limiter, a progress callback, and a
cancellation signal — it owns none of those concerns itself.

```
for each candidate path in wordlist:
    check cancellation
    await rate_limiter.acquire(domain)     # enforces the user's pacing floor
    response = http.get(base_url + path)
    classify(response) -> Finding | none
    progress(tested, total, current_path)
```

Concurrency is bounded and flows through the rate limiter, so "concurrent" never means
"faster than the configured floor per domain".

## Library / Data Choices

- **Wordlist:** obtained from the seeded reference-data store (see `add-seed-data`),
  looked up by the named lists for this scanner. REST discovery loads two named lists —
  `rest_endpoints` and `rest_api_bases` — each by name, shipped in
  `assets/seed/wordlists/` (`endpoints.txt`, `api_bases.txt`) and seeded into the database
  on first run. No user-uploaded wordlists in v1 (see `project.md` non-goals).
- **HTTP:** `reqwest` client supplied by `ScanContext`.

## Classification Rules (informs the spec's behavior, kept testable)

| Signal | Classification |
|--------|----------------|
| 2xx, or 401/403 on a path that returns API-shaped content | endpoint present (accessible or protected) |
| 404 / generic not-found | absent |
| 5xx | present-but-erroring (reported, low confidence) |

Classification must tolerate soft-404s (200 with a not-found body) — see scenario in the
spec. The exact heuristic is implementation detail; the *observable* contract is "a soft-404
is not reported as a finding".

### Canonical finding mapping

This scanner emits `Finding`s whose `severity` is drawn from the canonical `Severity` set
(`info | low | medium | high | critical`) and whose `status` is from `{vulnerable, safe,
info}` (per `add-scan-orchestration`). Scanner-specific classification labels
("accessible", "protected") live in the finding title/description, not in new status or
severity values.

- Discovered endpoint that is accessible but benign → `status: info`, `severity: info`.
- Discovered endpoint that exposes a sensitive/accessible surface → `status: vulnerable`,
  with `severity` scaled to the exposure (`low`/`medium` for a notable surface).
- Endpoint that exists but returns auth-required (protected) → `status: safe`,
  `severity: info`.

## Testing

- Unit tests for the classifier over representative responses (200 API, 200 soft-404, 401,
  403, 404, 500).
- Integration test against a **local mock HTTP server** (e.g. `wiremock`/`axum` test server)
  exposing a few known endpoints; assert the scanner finds exactly those and respects
  cancellation.
- **No real targets.** All tests are local and deterministic.
