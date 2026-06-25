# Design: BAC Scanner

## Technical Approach

Implement `BacScanner` in `abyssum-scanners`, implementing the `BaseScanner` trait from
`abyssum-core` (defined in `add-scan-orchestration`). The scanner is given a `ScanContext`
with a progress callback, a cancellation signal, and a single paced `send()` — **no raw HTTP
client** — so it owns none of those concerns and cannot bypass pacing.

```
baseline = ctx.send(GET, base_url, credentials-omitted)   # reachability baseline
for each sensitive path in wordlist:
    ctx.check_cancellation()
    response = ctx.send(GET, base_url+path, credentials-omitted)   # paced + UA-stamped; the only way out
    evaluate(response, path) -> Finding | none
    ctx.report_progress(tested, total, current_path)
```

Each probe is a `RequestSpec` that **explicitly omits the context credential** (no bearer
token, no auth header/cookie) so a positive result means the endpoint is reachable *without*
authentication; `ctx.send` still paces it and stamps a UA. Redirects are not auto-followed; a
redirect to a sensitive location triggers one explicit follow-up `send` (which also paces).

## Library / Data Choices

- **Wordlist:** obtained from the seeded reference-data store (see `add-seed-data`), loaded
  by named list. BAC loads `bac_paths` (the full admin/sensitive-path list) by name, and the
  fast profile loads `bac_paths_short` by name instead. The curated lists ship in
  `assets/seed/wordlists/paths.txt` (with `paths_short.txt` as the fast profile) and are
  seeded into the database on first run: `/admin`, `/api/admin`, `/api/users`, `/dashboard`,
  `/manage`, `/settings`, `/internal`, `/logs`, `/backoffice`, `/api/debug`, and similar. No
  user-uploaded wordlists in v1 (see `project.md` non-goals).
- **HTTP:** `reqwest` client supplied by `ScanContext`, configured to *not* auto-follow
  redirects so the scanner can inspect `Location` itself.
- **Content matching:** `regex` for the sensitive-content, error-page, and admin-interface
  signal sets; JSON shape detection via `serde_json` for collection/data-dump responses.

## Evaluation Rules (inform the spec's behavior, kept testable)

Per unauthenticated response to a sensitive path:

| Observed | Outcome |
|----------|---------|
| 2xx + recognized not-found / generic-error body | discard (no finding) |
| 2xx + sensitive-content signals (user data, credentials, DB, config, PII, multi-record JSON) | finding; severity scales with endpoint type + data class |
| 2xx on an admin/sensitive-named endpoint, no obvious sensitive content | finding (medium) — admin endpoints must not be openly reachable |
| 3xx redirect to a sensitive location | follow once; flag if the redirect target is itself reachable unauthenticated with sensitive/admin content |
| 401 / 403 | properly protected — no finding |
| 404 / 5xx | absent or erroring — no finding (redirect target 404/5xx is informational only) |

Severity (per finding): admin endpoint + sensitive data, or credentials/database exposure
→ critical; user data / PII exposure or sensitive endpoint + data → high; admin/sensitive
endpoint reachable without obvious data → medium. The observable contract is the
"flagged vs. not, and roughly how severe" outcome, not the exact regex set.

The error-page suppression (recognized not-found phrasing, default server error pages, very
short HTML bodies) is the false-positive guard from v1; the *observable* contract is "a
recognized error/not-found page on a sensitive path is not reported as unauthorized access".

**Default sensitive-content signal set (overridable).** A 2xx body counts as sensitive when
any holds: (a) `Content-Type` is JSON and the body is a collection of at least a threshold
(default **5**) records/objects; (b) the body contains any default keyword, case-insensitive —
`password`, `passwd`, `secret`, `token`, `api_key`/`apikey`, `authorization`, `ssn`,
`credit_card`, `private_key`, `BEGIN RSA`, `db_password`, or many email addresses; or (c) a
recognizable admin-interface marker (e.g. an admin/dashboard page title). The not-found/error
guard discards a 2xx body matching common not-found phrasing or a default server-error page,
or shorter than a small byte threshold (default **512 bytes** of HTML). These defaults make
the severity scenarios deterministic; an implementation may tune the lists.

### Canonical finding mapping

This scanner emits `Finding`s whose `severity` is drawn from the canonical `Severity` set
(`info | low | medium | high | critical`) and whose `status` is from `{vulnerable, safe,
info}` (per `add-scan-orchestration`). The endpoint kind and exposed-data class live in the
finding title/description, not in new status or severity values. Note: the canonical word is
`medium`, never "moderate".

- Admin endpoint reachable unauthenticated exposing credentials/database details →
  `status: vulnerable`, `severity: critical`.
- User data / PII exposed, or a sensitive endpoint returning sensitive data →
  `status: vulnerable`, `severity: high`.
- Admin/sensitive-named endpoint reachable unauthenticated with no obvious sensitive data →
  `status: vulnerable`, `severity: medium`.
- A sensitive path that is properly protected (401/403) → `status: safe`, `severity: info`;
  an absent/erroring path yields no finding.

## Testing

- Unit tests for the evaluator over representative responses: 200 admin page with sensitive
  content, 200 admin page that is actually a not-found body, 200 on `/admin` with empty
  benign body, 401/403 protected, 404 absent, and a 302 to a sensitive location whose
  target is reachable.
- Integration test against a **local mock HTTP server** (e.g. `wiremock`/`axum` test
  server) exposing: one exposed admin endpoint with sensitive content, one properly
  protected endpoint (401/403), one not-found path, and one redirect-to-admin chain;
  assert the scanner flags exactly the exposed endpoints and the reachable redirect target.
- Verify each probe is sent without authorization credentials.
- Verify cancellation halts probing promptly and yields the partial set of findings.
- Verify probes are paced through the rate limiter (no probe precedes the floor).
- **No real targets.** All tests are local and deterministic.
