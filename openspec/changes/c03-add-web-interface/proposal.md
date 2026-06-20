## Why

The web UI is Abyssum's interactive surface: the one place an operator launches a scan,
watches it run with live progress, cancels it mid-flight, and browses past findings. It is
the counterpart to the CLI and, per the canon, both call the same shared engine so they
cannot drift.

Because the instance is multi-user with authentication (see `project.md` and
`add-authentication`), the entire UI sits behind login and a user sees only their own scan
sessions unless they hold the `admin` role. This change depends on scan orchestration
(`add-scan-orchestration`) for session lifecycle, progress events, and cancellation; on
result persistence (`add-result-persistence`) for browsing/searching history; on the six
scanners (b00–b05) for something to run; on the custom-requests tool
(`add-custom-requests-tool`) for the manual-request surface; and on authentication (c02)
for the login gate and ownership rules.

## What Changes

### 1. Authenticated web surface

Every page and data endpoint requires an authenticated session. Unauthenticated requests
are redirected to login (for pages) or rejected (for data endpoints). No scan can be
started, viewed, cancelled, or searched anonymously.

### 2. Start a scan from the UI

An operator selects one or more targets and one or more scanners (from the registered
scanner ids), optionally sets pacing and auth/user-agent options, and submits. The server
creates an owned scan session and begins executing it in the background, returning the new
session id so the operator can watch it.

### 3. Live progress over a WebSocket, plus cancellation

While a scan runs, the operator watches live progress (which scanner, how many candidates
tested out of the total, findings so far) delivered as server-rendered fragments over a
per-session WebSocket. The operator can cancel a running scan; cancellation propagates to
the engine, which stops promptly and retains partial findings.

### 4. Browse, search, and filter past sessions and findings

The dashboard lists the operator's past sessions with summary stats. Sessions and their
findings are searchable and filterable by free text, status, scanner id, vulnerability
level, and target. Opening a session shows its findings with evidence.

### 5. Per-user visibility with admin override

A user sees and operates only on their own sessions and findings. An `admin` sees all
sessions across users. Attempts to view, cancel, or act on another user's session are
denied for non-admins.

### 6. Custom-requests tool in the UI

The manual HTTP request builder (`add-custom-requests-tool`) is reachable as an
authenticated page that lets the operator issue an ad-hoc request with optional bearer
token, cookies, and custom headers, and view the response.

## Impact

- Adds the `web-ui` capability to `openspec/specs/`.
- First surface to compose orchestration, persistence, the scanners, custom-requests, and
  authentication into one product experience.
- Depends on changes a02, a03, b00–b05, and c02 being archived first (per `IMPLEMENTATION_ORDER.md`).
