# Design: REST Discovery Scanner

## Technical Approach

Implement `RestDiscoveryScanner` in `abyssum-scanners`, implementing the `BaseScanner`
trait from `abyssum-core` (defined in `add-scan-orchestration`). The scanner is given a
`ScanContext` with a progress callback, a cancellation signal, and a single paced `send()` —
**no raw HTTP client** — so it owns none of those concerns and cannot bypass pacing.

```
for each candidate path in wordlist:
    ctx.check_cancellation()
    response = ctx.send(GET, target.full_url_for(path))   # paces + stamps a rotating UA; the only way out
    classify(response) -> Finding | none
    ctx.report_progress(tested, total, current_path)
```

Every request goes through `ctx.send`, which paces per-domain through the shared limiter, so
"concurrent" never means "faster than the configured floor per domain".

## Library / Data Choices

- **Wordlist:** obtained from the seeded reference-data store (see `add-seed-data`),
  looked up by the named lists for this scanner. REST discovery loads two named lists —
  `rest_endpoints` and `rest_api_bases` — each by name, shipped in
  `assets/seed/wordlists/` (`endpoints.txt`, `api_bases.txt`) and seeded into the database
  on first run. No user-uploaded wordlists in v1 (see `project.md` non-goals).
- **HTTP:** issued through `ScanContext::send` (paced, UA-stamped); no raw client is exposed
  to the scanner.

## Classification Rules (informs the spec's behavior, kept testable)

| Signal | Classification |
|--------|----------------|
| 2xx, or 401/403 on a path that returns API-shaped content | endpoint present (accessible or protected) |
| 404 / generic not-found | absent |
| 5xx | present-but-erroring (reported, low confidence) |

Classification must tolerate soft-404s (200 with a not-found body). **Default heuristic
(overridable):** before probing the wordlist, send one request to a random unlikely path
(e.g. `/<random-uuid>`) and record that response's status and a body fingerprint (length
bucket + a hash of the whitespace-normalized body). A candidate is classified *absent* when
its response matches that fingerprint — same status and either an equal normalized-body hash
or a body length within a small tolerance. "API-shaped content" = a JSON/XML `Content-Type`
or a body that parses as JSON. The *observable* contract remains "a soft-404 is not reported
as a finding"; the fingerprint is the concrete default that makes it deterministic.

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
