# Design: CORS Scanner

## Technical Approach

Implement `CorsScanner` in `abyssum-scanners`, implementing the `BaseScanner` trait from
`abyssum-core` (defined in `add-scan-orchestration`). The scanner receives a `ScanContext`
providing the HTTP client, the rate limiter, a progress callback, and a cancellation signal
— it owns none of those concerns itself. If the scan context carries an authorization token
(bearer/cookie), the scanner attaches it to each probe so credentialed responses are
exercised.

```
for each crafted origin in test_origins:
    check cancellation
    await rate_limiter.acquire(domain)        # enforces the user's pacing floor
    response = http.get(target_url, header Origin = crafted_origin [+ auth])
    acao = response.header("Access-Control-Allow-Origin")
    acac = response.header("Access-Control-Allow-Credentials")  # case-insensitive "true"
    classify(crafted_origin, acao, acac) -> Finding | none
    progress(tested, total, current_origin)
```

A response with no ACAO header is never a finding. Probing is sequential per target and
flows through the rate limiter, so it can never exceed the configured per-domain floor.

## Crafted Origins (mined from v1 `scanners/cors.py`)

The v1 scanner probed these `Origin` values; v2 preserves their intent:

| Crafted origin | Class | What a match reveals |
|----------------|-------|----------------------|
| attacker-controlled origin (e.g. `https://evil.example`) | arbitrary | server reflects an unrelated attacker origin |
| `null` | null-origin | server trusts the `null` origin (sandboxed iframes, redirects, `file://`) |
| target-domain look-alike (target domain as a substring of an attacker host) | untrusted look-alike | naive substring/regex origin allow-listing |
| non-default scheme/port (e.g. `http://localhost:8080`) | other reflected | reflects origins it should not |
| `file://` | null-equivalent | trusts a file/opaque origin |

The exact host strings are implementation detail; the *classes* (arbitrary, null,
look-alike, other-reflected) are what the spec pins down. The look-alike and `null`
variants must be derived from the target's own domain at scan time, not hard-coded, so the
substring-trust check is meaningful.

## Classification & Severity Rules (informs the spec, kept testable)

ACAC is "credentials allowed" only when the returned `Access-Control-Allow-Credentials`
header equals `true` (case-insensitive). Per the Fetch standard, a wildcard ACAO cannot be
combined with real credentials by a compliant browser, but a server returning both is a
clear misconfiguration and is reported.

| Condition | Misconfiguration reported | Severity (no creds → with creds) |
|-----------|---------------------------|----------------------------------|
| ACAO == `*` AND ACAC == `true` | wildcard with credentials | High |
| ACAO == crafted arbitrary/look-alike/other origin AND ACAC == `true` | reflected origin (credentialed) | High |
| ACAO == `null` AND server reflected our `null` probe | null origin accepted | Medium → High (with creds) |
| ACAO == crafted arbitrary/look-alike/other origin AND ACAC != `true` | reflected origin (no creds) | Medium |
| ACAO == `*` AND ACAC != `true` | bare wildcard | Low |

Severity is driven by exploitability: credentialed reflection (an attacker page can read a
*logged-in* victim's data) is the high-severity case; a bare wildcard with no credentials
leaks only public data and is Low. This mirrors v1's High/Medium/Low assignments while
making the credentialed-vs-not axis explicit.

### Canonical finding mapping

This scanner emits `Finding`s whose `severity` is drawn from the canonical `Severity` set
(`info | low | medium | high | critical`) and whose `status` is from `{vulnerable, safe,
info}` (per `add-scan-orchestration`). The named misconfiguration (wildcard-with-credentials,
reflected origin, null origin accepted, bare wildcard) lives in the finding
title/description, not in new status or severity values. The scanner crafts its `Origin`
values inline from the `Target` (`base_url`) and seeds no wordlist.

- Wildcard-with-credentials, or credentialed reflected/look-alike/null origin →
  `status: vulnerable`, `severity: high`.
- Reflected/look-alike origin without credentials, or null origin accepted without
  credentials → `status: vulnerable`, `severity: medium`.
- Bare wildcard without credentials → `status: vulnerable`, `severity: low`.
- A probe whose response omits ACAO or returns a properly restricted origin → no finding
  (a properly restricted result is sound, `status: safe` if recorded).

## Finding Evidence

Each finding records, at minimum: the named misconfiguration, the `Origin` value sent, the
returned `Access-Control-Allow-Origin`, the returned `Access-Control-Allow-Credentials`,
and the probed URL — enough to reproduce the check by hand.

## Testing

- Unit tests for the classifier over the full ACAO/ACAC matrix above (wildcard+creds,
  reflected arbitrary with/without creds, null with/without creds, look-alike reflection,
  bare wildcard, and the no-ACAO / properly-restricted negative cases).
- Integration test against a **local mock HTTP server** (e.g. `wiremock`/`axum` test server)
  configured to reflect the `Origin` header (and one variant that returns a fixed safe ACAO);
  assert the scanner reports exactly the expected misconfigurations with correct severity
  and evidence, and reports nothing for the safe origin.
- Tests assert the scanner respects cancellation, emits progress, and paces via the rate
  limiter.
- **No real targets.** All tests are local and deterministic.
