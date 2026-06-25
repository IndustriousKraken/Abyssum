# Tasks

## 1. Scanner skeleton
- [x] 1.1 Add `CorsScanner` in `abyssum-scanners` implementing the `BaseScanner` trait
- [x] 1.2 Declare scanner metadata: stable id `cors`, human name, description
- [x] 1.3 Register it in the scanner registry so it is selectable by id

## 2. Crafted origins
- [x] 2.1 Build the crafted-origin set: arbitrary attacker origin, `null`, target-domain look-alike, non-default scheme/port, file/opaque origin
- [x] 2.2 Derive the look-alike and per-target variants from the target's own domain at scan time

## 3. Probing loop
- [x] 3.1 For each crafted origin, send a request with that `Origin` header, acquiring the rate limiter before each request
- [x] 3.2 Attach the scan context's auth token (if present) so credentialed responses are exercised
- [x] 3.3 Honor the cancellation signal between requests
- [x] 3.4 Emit progress (tested / total / current origin) via the `ScanContext` callback

## 4. Detection & severity
- [x] 4.1 Parse `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` (treat credentials as enabled only when the value equals `true`, case-insensitive)
- [x] 4.2 Treat a missing `Access-Control-Allow-Origin` as no finding
- [x] 4.3 Classify: reflected arbitrary/look-alike/other origin, wildcard-with-credentials, null-origin accepted, bare wildcard
- [x] 4.4 Assign severity so credentialed exposure outranks the same misconfiguration without credentials
- [x] 4.5 Build `Finding` records naming the misconfiguration with evidence: origin sent, ACAO returned, ACAC returned, probed URL

## 5. Tests (local only — no real targets)
- [x] 5.1 Unit-test the classifier across the ACAO/ACAC matrix (wildcard+creds, reflected with/without creds, null with/without creds, look-alike, bare wildcard, no-ACAO, restricted-safe)
- [x] 5.2 Integration-test against a local mock server that reflects `Origin`; assert exact findings, severities, and evidence
- [x] 5.3 Test a local mock server returning a fixed safe `Access-Control-Allow-Origin` yields no finding
- [x] 5.4 Test that cancellation stops the scan promptly and yields a partial result
- [x] 5.5 Test that requests are paced through the rate limiter (no request precedes the floor)
