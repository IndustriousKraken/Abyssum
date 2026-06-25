# Design: OpenAPI Discovery Scanner

## Technical Approach

Implement `OpenApiDiscoveryScanner` in `abyssum-scanners`, implementing the `BaseScanner`
trait from `abyssum-core` (defined in `add-scan-orchestration`). The scanner is given a
`ScanContext` with a progress callback, a cancellation signal, and a single paced `send()` —
**no raw HTTP client** — so it owns none of those concerns and cannot bypass pacing.

```
for each candidate spec path:
    ctx.check_cancellation()
    response = ctx.send(GET, target.full_url_for(path))   # paces + stamps a rotating UA
    if response is a valid OpenAPI/Swagger document:
        endpoints = extract documented paths
        record spec + endpoints
    ctx.report_progress(tested, total, current_path)
emit one finding summarizing every discovered spec and its endpoints
```

Probing is the same shape as `rest-discovery`; the difference is the per-response decision
("is this an API spec?") and the evidence (the documented endpoint set), not the engine
plumbing.

## Library / Data Choices

- **Spec-location wordlist:** obtained from the seeded reference-data store (see
  `add-seed-data`), loaded by the named list `openapi_paths`. The curated list ships in
  `assets/seed/wordlists/openapi_paths.txt` and is seeded into the database on first run; it
  covers the well-known locations (`/openapi.json`, `/swagger.json`, `/openapi.yaml`,
  `/swagger.yaml`, `/api-docs`, `/api/docs`, …). No user-uploaded wordlists in v1 (see
  `project.md` non-goals).
- **HTTP:** issued through `ScanContext::send` (paced, UA-stamped); no raw client is exposed.
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

### Canonical finding mapping

This scanner emits `Finding`s whose `severity` is drawn from the canonical `Severity` set
(`info | low | medium | high | critical`) and whose `status` is from `{vulnerable, safe,
info}` (per `add-scan-orchestration`). The detected spec type and the documented-endpoint
list live in the finding title/description and evidence, not in new status or severity
values.

- A published spec document discovered at a candidate location → `status: info`,
  `severity: info` (a documented surface is an observation, not by itself a weakness).
- A spec that exposes an unintended/internal surface treated as sensitive → `status:
  vulnerable`, with `severity` scaled to the exposure (`low`/`medium`).
- A candidate location that serves no spec → no finding (a non-spec 2xx is not reported).

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
