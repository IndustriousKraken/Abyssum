# Design: Web Interface

## Technical Approach

`abyssum-web` is the axum server binary. It is thin: it builds a router, wires shared state
(config, the orchestrator, the database/persistence layer, the authentication service, and
a WebSocket progress hub), and serves server-rendered HTML. All scanning, persistence, and
auth logic lives in `abyssum-core`; the web crate only translates HTTP/WebSocket traffic to
and from the engine. This is the canonical pattern in the Rust reference
(`/tmp/abyssum-rust/abyssum-web/`), extended here with the authentication gate the canon
requires.

```
browser ──HTTP/HTMX──► axum router ──► abyssum-core (orchestrator, persistence, auth)
   ▲                        │
   └──WebSocket fragments───┘  (live progress per session)
```

### Frontend: HTMX + Alpine.js, no SPA

Per the canon, the frontend is **HTMX + Alpine.js** over server-rendered HTML fragments —
no React/Vue, no SPA, no JS build step. Handlers return HTML partials that HTMX swaps into
the page; Alpine drives small client-side interactions (form state, modals, copy buttons).
Lists like the session table, recent-scans, and statistics cards are HTML fragments fetched
on demand, matching the reference's `get_sessions_table`, `get_recent_scans`, and
`get_statistics_cards` handlers.

### Routing shape (from the reference, plus auth)

- HTML pages: home / start-scan, dashboard, scan detail (`/scan/:session_id`),
  custom-requests.
- Data/fragment endpoints: start scan, session status, session results fragment, cancel,
  sessions list/table, recent scans, statistics, search, custom-request execution.
- WebSocket: `/ws/:session_id` for live progress.
- A login page and session-cookie auth gate (from `add-authentication`) wraps all of the
  above except the login route and static assets.

### Library / Crate Choices

- **Web framework:** `axum` (canon).
- **Async runtime / HTTP:** `tokio` + `reqwest` (canon; `reqwest` only for the
  custom-requests page, which reuses `add-custom-requests-tool`).
- **Templating / fragments:** server-rendered HTML — a templating crate (e.g. `askama`) or
  formatted strings as in the reference; the choice is implementation detail, not behavior.
- **Static assets:** `tower-http` `ServeDir` for CSS/JS/img.
- **WebSocket:** axum's built-in WebSocket upgrade; a broadcast hub (`tokio::sync::broadcast`)
  keyed by session id, fed by the orchestrator's progress subscription.
- **Auth integration:** the session/identity middleware and user model from
  `add-authentication`; this change consumes it, it does not define auth.

## Architecture Decisions

### Decision: One progress broadcast hub fed by the orchestrator
The orchestrator emits progress events (defined in `add-scan-orchestration`). A single
background task subscribes to that stream and fans each event out to the per-session
WebSocket channel. Connecting late simply yields the next update plus the current rendered
state; the WebSocket carries server-rendered progress fragments, not a client-side data
model. This mirrors the reference's broadcast task and `handle_websocket`.

### Decision: Sessions are owned; visibility is enforced server-side
Every scan session records its owning user (from the authenticated identity at creation).
List/search/detail/cancel handlers filter by owner for non-admins and bypass the filter for
admins. Ownership is enforced in the handler against the persisted owner — never trusted
from the client. This realizes the canon's "owner-only + admin-sees-all" decision.

### Decision: Background execution, foreground responsiveness
Starting a scan spawns engine execution as a background task and immediately returns the
session id, so the UI stays responsive and the operator is taken straight to live progress.
Cancellation calls the orchestrator's cancel path; the engine handles prompt stop and
partial-result retention (specified in `add-scan-orchestration`).

### Decision: Custom-requests reuses the tool capability
The custom-requests page is a thin UI over `add-custom-requests-tool`; this change does not
re-specify request-building behavior, only that the surface exists, is authenticated, and
shows the response. Keyless/absent-auth requests remain allowed per that capability.

## Testing

- Auth-gate tests: unauthenticated page request redirects to login; unauthenticated data
  endpoint is rejected; authenticated request succeeds.
- Ownership tests: user A cannot list/view/cancel user B's session; an admin can.
- Scan lifecycle test against a **local mock HTTP target**: start → observe progress
  fragments over the WebSocket → cancel → confirm prompt stop and partial findings persisted
  and visible.
- Search/filter tests over seeded fixtures: free-text, status, scanner-id, level, and target
  filters each narrow results correctly and only within the requesting user's scope.
- Custom-requests test against a local mock server (no real targets).
- **No real third-party targets** anywhere; all network tests use local mock servers or
  fixtures (canon ethics constraint).
