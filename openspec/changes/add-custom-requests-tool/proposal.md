## Why

Bug bounty work needs a manual escape hatch alongside the automated scanners: a way to fire
a single arbitrary HTTP request — any method, headers, and body — to reproduce a finding,
poke at an endpoint by hand, or validate a fix. The v1 Python `custom_requests` tool did
exactly this and surfaced lightweight security signals from the response. v2 reimplements
that behavior as a shared capability available from both the CLI and the web surface.

This is a manual *tool*, not a scanner: it does not run through the scan engine, does not
produce `scan-session` `Finding` records, and issues exactly one request per invocation. It
depends only on the shared HTTP client and config from `bootstrap-rust-workspace`.

Authentication is **optional by design** — per canon, keyless endpoints matter, so a request
with no bearer token and no session cookies must work unchanged.

## What Changes

### 1. Send an arbitrary HTTP request

Accept a target URL plus a chosen HTTP method, zero or more custom headers, and an optional
request body, then issue exactly one request and capture the full response (status, headers,
body, timing, and any redirect chain).

### 2. Optional bearer-token and cookie authentication

Allow attaching a bearer token (sent as an `Authorization: Bearer` header) and/or a session
cookie string. Both are optional and independent — a request may carry one, both, or
neither. A request with no token and no cookies is valid and is sent as-is.

### 3. Response signal analysis

Inspect the captured response and surface notable security signals without judging them as
confirmed vulnerabilities: missing security headers, information-disclosure headers (server
and technology version banners), and error-detail leakage in the body (stack traces, debug
keywords). Signals are advisory hints for manual follow-up.

### 4. Shared across CLI and web, human and JSON output

Expose one shared implementation usable from both surfaces, rendering the request, response,
and analysis either as human-readable text or as a single structured JSON document.

## Impact

- Adds the `custom-requests` capability to `openspec/specs/`.
- Consumes only the shared HTTP client and config from `bootstrap-rust-workspace`; does not
  touch the scan engine, persistence, or the rate limiter.
- Gives the CLI (#12) and web UI (#14) a manual-request building block to wire up.
