# Design: Web Interface

## Technical Approach

`abyssum-web` is the axum server binary. It is thin: it builds a router, wires shared state
(config, the orchestrator, the database/persistence layer, the authentication service, and
a WebSocket progress hub), and serves server-rendered HTML. All scanning, persistence, and
auth logic lives in `abyssum-core`; the web crate only translates HTTP/WebSocket traffic to
and from the engine, behind the authentication gate the canon requires. The concrete route
table is given below — there is no external reference implementation to mirror.

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
on demand.

### Route table

`public` = reachable without a session; everything else requires a valid session cookie, and
`+owner` additionally requires the requester to own the session (or be admin). Fragment routes
return HTML partials for HTMX to swap; page routes return full pages.

| Method | Path | Access | Returns |
|---|---|---|---|
| GET | `/login` | public | login page |
| POST | `/login` | public | verify credentials, set session cookie, redirect to `/` |
| GET | `/register` | public | registration page (first-user bootstrap) |
| POST | `/register` | public | create account (first user → admin), redirect to `/login` |
| POST | `/logout` | session | clear cookie, redirect to `/login` |
| GET | `/` | session | home / start-scan page |
| POST | `/scans` | session | start scan; create owned session, spawn execution, return new session id |
| GET | `/scan/:session_id` | session +owner | scan-detail page |
| GET | `/scan/:session_id/results` | session +owner | findings fragment for that session |
| POST | `/scan/:session_id/cancel` | session +owner | cancel scan, return status fragment |
| GET | `/ws/:session_id` | session +owner | WebSocket: live progress fragments |
| GET | `/dashboard` | session | dashboard page (sessions + statistics) |
| GET | `/sessions` | session | owner-scoped sessions table fragment |
| GET | `/stats` | session | statistics-cards fragment (owner-scoped counts) |
| GET | `/findings` | session | search/filter findings fragment (free-text/status/scanner/level/target) |
| GET | `/custom-requests` | session | custom-requests page |
| POST | `/custom-requests` | session | execute ad-hoc request, return response fragment |
| GET | `/static/*` | public | CSS / JS / images (`tower-http` `ServeDir`) |

The session-cookie auth gate (from `add-authentication`) wraps everything except the `public`
rows. Owner enforcement (`+owner`) is checked in the handler against the persisted owner —
never trusted from the client.

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
WebSocket channel, keyed by session id so concurrent scans don't cross-deliver. Connecting
late simply yields the next update plus the current rendered state; the WebSocket carries
server-rendered progress fragments, not a client-side data model.

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

### Decision: Registration page bootstraps the first (admin) user
`add-authentication` defines `register()` but no surface calls it. This change adds the
`GET/POST /register` routes so the first operator can create the admin account (first user →
admin, per the auth bootstrap) and so additional local accounts can be created. Open
registration is the v1 default; gating it once a user exists is a deferred refinement.

### Decision: Session cookie is HttpOnly, Secure, SameSite=Lax
The opaque session token from `add-authentication` is carried in a cookie set `HttpOnly` (no
JS access), `Secure` (HTTPS only), and `SameSite=Lax` (sent on top-level navigation, not on
cross-site sub-requests). The WebSocket upgrade authenticates from the same cookie and is
owner-checked before the socket is accepted; an unauthenticated or non-owner upgrade is
rejected, not upgraded.

### Decision: State-changing requests are CSRF-protected
`POST` routes (login, register, start scan, cancel, custom request, logout) require a CSRF
token issued with the session and validated on submit. `SameSite=Lax` is the first line of
defense; the token is the second, since fragment POSTs are same-site form submissions.

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
