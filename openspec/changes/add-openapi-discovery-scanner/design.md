# Design: OpenAPI Discovery Scanner

## Technical Approach

Implement `OpenApiDiscoveryScanner` in `abyssum-scanners`, implementing the `BaseScanner`
trait from `abyssum-core` (defined in `add-scan-orchestration`). The scanner receives a
`ScanContext` providing the HTTP client, the rate limiter, a progress callback, and a
cancellation signal — it owns none of those concerns itself.

```
for each candidate spec path:
    check cancellation
    await rate_limiter.acquire(domain)     # enforces the user's pacing floor
    response = http.get(base_url + path)
    if response is a valid OpenAPI/Swagger document:
        endpoints = extract documented paths
        record spec + endpoints
    progress(tested, total, current_path)
emit one finding summarizing every discovered spec and its endpoints
```

Probing is the same shape as `rest-discovery`; the difference is the per-response decision
("is this an API spec?") and the evidence (the documented endpoint set), not the engine
plumbing.

## Library / Data Choices

- **Spec-location wordlist:** obtained from the seeded reference-data store (see
  `add-seed-data`), looked up by scanner id. The curated list ships in
  `assets/seed/wordlists/openapi_paths.txt` and is seeded into the database on first run; it
  covers the well-known locations (`/openapi.json`, `/swagger.json`, `/openapi.yaml`,
  `/swagger.yaml`, `/api-docs`, `/api/docs`, …). No user-uploaded wordlists in v1 (see
  `project.md` non-goals).
- **HTTP:** `reqwest` client supplied by `ScanContext`.
- **Parsing:** `serde_json` for JSON specs and `serde_yaml` for YAML specs, both decoded
  into a generic JSON value so validation/extraction is format-agnostic. Format is chosen
  from the response `content-type` and the path extension, with the other format tried as a
  fallback.

## Validation Rules (informs the spec's behavior, kept testable)

A response counts as a valid API spec only if its parsed body is an object that bears an
OpenAPI/Swagger marker:

| Signal in parsed body | Verdict |
|-----------------------|---------|
| top-level `openapi` string field | valid (OpenAPI 3.x) |
| top-level `swagger` string field | valid (Swagger 2.0) |
| top-level `paths` object | valid (documented surface present) |
| none of the above, or body is not an object | not a spec — discard |

A 200 response whose body does not parse as JSON/YAML, or parses but lacks every marker
(e.g. an unrelated JSON API payload or an HTML landing page), is **not** reported. This is
the observable contract that separates "found a spec" from "got some 2xx".

The detected spec type is derived from the marker (`OpenAPI <version>` / `Swagger
<version>`). Documented endpoints are the keys of the `paths` object, joined to the target
base URL and de-duplicated across all discovered specs.

## Testing

- Unit tests for the validator over representative bodies: an OpenAPI 3.x JSON doc, a
  Swagger 2.0 JSON doc, a YAML spec, an unrelated 2xx JSON payload, an HTML page, and a
  non-200 response — asserting only the genuine specs are accepted.
- Unit test for endpoint extraction: a spec with a `paths` object yields exactly its
  documented paths joined to the base URL, de-duplicated.
- Integration test against a **local mock HTTP server** serving a spec at one known
  location and unrelated 2xx content elsewhere; assert the scanner reports exactly the
  spec, lists its endpoints, and respects cancellation and pacing.
- **No real targets.** All tests are local and deterministic.
