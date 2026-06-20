# Tasks

## 1. Request specification and auth assembly
- [ ] 1.1 Add a `custom_request` module in `abyssum-core` with a request spec (url, method, headers, optional body, optional content type, follow-redirects flag, TLS-verify flag, timeout)
- [ ] 1.7 Default TLS verification ON; disable it only when the explicit `--insecure` / `--no-verify-tls` flag is set (sets reqwest `danger_accept_invalid_certs` for that single request)
- [ ] 1.2 Normalize the URL and uppercase the method; default the method to GET
- [ ] 1.3 When a bearer token is supplied, add an `Authorization: Bearer <token>` header (do not double-prefix an already-`Bearer`-prefixed value)
- [ ] 1.4 When a cookie string is supplied, add a `Cookie` header
- [ ] 1.5 When neither token nor cookies are supplied, send the request with no auth headers added
- [ ] 1.6 When a body is supplied without an explicit content type and it parses as JSON, default the content type to JSON; otherwise send the body verbatim

## 2. Send and capture
- [ ] 2.1 Send exactly one request per invocation via the shared HTTP client, honoring the timeout and follow-redirects flag
- [ ] 2.2 Capture status code, response headers, body, round-trip elapsed time, the final URL/status after any redirects, and a redirect hop count (the full intermediate chain is optional, not required)
- [ ] 2.3 On timeout or transport error, return a result carrying the error instead of panicking

## 3. Response analysis
- [ ] 3.1 Implement a pure `analyze` function that takes a captured response and returns a list of advisory signals
- [ ] 3.2 Flag information-disclosure headers when present (server/technology/source-path banners)
- [ ] 3.3 Flag each expected security header that is absent
- [ ] 3.4 Flag error-detail leakage when the body contains stack-trace or debug indicators
- [ ] 3.5 Return no signals for a clean response with hardened headers and no error detail

## 4. Output rendering
- [ ] 4.1 Render a human-readable form: request line, status, timing, final URL and redirect hop count, response headers, a body preview truncated to a default cap of 64 KB (marked as truncated when exceeded), and the signals
- [ ] 4.2 Render a JSON form: one structured document containing the echoed request, the response, and the signals
- [ ] 4.3 Pretty-print the response body in both forms when the response declares a JSON content type

## 5. Tests (local only — no real targets)
- [ ] 5.1 Unit-test auth assembly: token-only, cookie-only, both, and neither (keyless)
- [ ] 5.2 Unit-test `analyze` over leaky-header, missing-header, stack-trace-body, and clean-response cases
- [ ] 5.3 Unit-test JSON-body auto-detection vs. verbatim body
- [ ] 5.4 Integration-test the send path against a local mock HTTP server, asserting method/headers/body arrive and the response is captured
- [ ] 5.5 Test that the human and JSON output forms describe the same outcome
- [ ] 5.6 Test that a transport error or timeout yields an error-carrying result rather than a crash
