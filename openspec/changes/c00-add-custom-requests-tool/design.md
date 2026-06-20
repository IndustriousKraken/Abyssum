## Design: Custom Requests Tool

## Technical Approach

Implement the tool in `abyssum-core` so both surfaces share one code path (the CLI in c01
and the web UI in c03 each render the same result). The tool takes a request specification,
sends it via the shared `reqwest` client, captures the response, runs a pure analysis pass,
and returns one result value that both surfaces format.

```
build request spec (url, method, headers, optional body, optional auth)
  -> add Authorization: Bearer header if a token is present
  -> add Cookie header if a cookie string is present
send via reqwest (TLS verification may be relaxed for testing targets)
capture status, response headers, body, elapsed time, redirect chain
analyze(response) -> Vec<Signal>          # pure function, no I/O
return RequestOutcome { request echo, response, signals }
```

Auth assembly is deliberately additive and optional: absent token → no `Authorization`
header; absent cookies → no `Cookie` header; absent both → an unauthenticated request. This
keeps keyless endpoints first-class (canon).

## Library Choices

- **HTTP:** `reqwest` (workspace dep from `bootstrap-rust-workspace`), one short-lived
  client per invocation; redirect-follow is configurable.
- **Serialization:** `serde` / `serde_json` for the JSON output mode and for pretty-printing
  JSON response bodies when the response declares a JSON content type.
- **Timing:** `std::time::Instant` for round-trip elapsed time.
- **CLI argument shape (wired in c01):** mirrors the v1 flags — `-X/--method`,
  `-H/--header` (repeatable), `-A/--auth` (bearer), `-c/--cookie`, `-d/--data`,
  `--content-type`, `--no-follow-redirects`, `--timeout`, `--output pretty|json`.

## Architecture Decisions

### Decision: Lives in `abyssum-core`, not `abyssum-scanners`
This is a manual tool, not a scanner. It does not implement the `BaseScanner` trait, does
not receive a `ScanContext`, produces no persisted `Finding`s, and is exempt from the scan
engine's progress/cancellation machinery. Placing it in `core` lets both binaries call it
without dragging in the orchestration layer.

### Decision: Not paced by the rate limiter
The pacing floor governs automated multi-request scans. This tool sends exactly one request
per invocation under direct operator control, so the per-domain limiter does not apply. A
single deliberate manual request is not a stealth concern.

### Decision: Signals are advisory, not findings
Analysis returns informational signals (missing/leaky headers, error-detail leakage) to
guide manual follow-up. They are explicitly *not* confirmed vulnerabilities and are not
written to the findings store. This matches v1, where the response analysis produced
low-severity hints separate from scanner findings.

### Decision: Auto-detect JSON body
When a body is supplied without an explicit content type and parses as JSON, default the
content type to JSON (matching v1 convenience); otherwise send the body verbatim. This is a
convenience default, not a behavior the spec mandates beyond "a body is sent as provided".

## Analysis Signals (informs the spec's behavior, kept testable)

| Source | Signal |
|--------|--------|
| Response header present: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Debug`, `X-SourceFiles` | information disclosure (version/tech/source banner) |
| Response header absent: `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Content-Security-Policy` | missing security header |
| Body contains `traceback` / `stack trace` / `exception` | error-detail leakage |
| Body contains `debug` / `development` / `localhost` | debug-information leakage |

The exact keyword/header lists are implementation detail; the observable contract is "a
present disclosure header, a missing security header, and an error-detailed body each yield
a signal".

## Testing

- Unit-test the analysis function over crafted responses: leaky headers present, security
  headers missing, body with a stack trace, and a clean response yielding no signals.
- Unit-test auth assembly: token-only adds the bearer header, cookie-only adds the cookie
  header, both add both, and neither adds neither (keyless request).
- Integration-test the send path against a **local mock HTTP server** (e.g. `wiremock`):
  assert the chosen method/headers/body reach the server and the response is captured.
- Assert both output modes render the same outcome (human text and a parseable JSON doc).
- **No real targets** — all tests are local and deterministic.
