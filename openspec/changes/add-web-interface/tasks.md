# Tasks

## 1. Server skeleton and shared state
- [ ] 1.1 Add the `abyssum-web` axum server entry point that builds shared state (config, orchestrator, persistence layer, authentication service, WebSocket hub)
- [ ] 1.2 Mount the router and serve static assets (CSS/JS/img) from a known path
- [ ] 1.3 Bind to the configured host/port and start serving; log the bound address

## 2. Authentication gate
- [ ] 2.1 Wrap all page and data routes (except the login route and static assets) with the session-identity middleware from the authentication capability
- [ ] 2.2 Redirect unauthenticated page requests to the login page; reject unauthenticated data/WebSocket requests
- [ ] 2.3 Expose the authenticated user's identity to handlers so ownership can be enforced

## 3. Start-scan flow
- [ ] 3.1 Render the start-scan page listing the registered scanner ids as selectable options and a target-entry field
- [ ] 3.2 Handle scan submission: validate that at least one target and one known scanner id are supplied
- [ ] 3.3 Create an owned scan session (owner = authenticated user) via the orchestrator and persist it
- [ ] 3.4 Spawn engine execution as a background task and return the new session id, directing the operator to live progress

## 4. Live progress over WebSocket
- [ ] 4.1 Add the `/ws/:session_id` WebSocket endpoint, authenticated and owner-checked
- [ ] 4.2 Run one background task subscribing to the orchestrator progress stream and fan events out to the matching per-session channel
- [ ] 4.3 On each progress event, send a server-rendered progress fragment (current scanner, tested/total, findings so far) to connected clients
- [ ] 4.4 Handle late connects (send current state), client keep-alive pings, and disconnect cleanup

## 5. Cancellation
- [ ] 5.1 Add a cancel endpoint that calls the orchestrator's cancel path for the session
- [ ] 5.2 Enforce ownership/admin before cancelling; deny cross-user cancellation for non-admins
- [ ] 5.3 Reflect the cancelled state and retained partial findings in subsequent status/results fragments

## 6. Dashboard, sessions, and findings
- [ ] 6.1 Render the dashboard with summary statistics fragments (totals, active scans) scoped to the requesting user (all users for admin)
- [ ] 6.2 Render the session list/table and recent-scans fragments, scoped by owner
- [ ] 6.3 Render a scan-detail page showing a session's findings with evidence
- [ ] 6.4 Return a session-results fragment (HTMX-swappable) that reflects findings as they accrue

## 7. Search and filter
- [ ] 7.1 Add a search endpoint accepting free-text plus status, scanner-id, vulnerability-level, and target filters
- [ ] 7.2 Apply filters against persisted findings and return matching results as a fragment, capped by a result limit
- [ ] 7.3 Restrict every search/filter result to the requesting user's sessions (all sessions for admin)

## 8. Per-user visibility enforcement
- [ ] 8.1 Filter list/recent/statistics/search/detail by owner for non-admins
- [ ] 8.2 Reject view/cancel/results requests for sessions the requester does not own when not admin
- [ ] 8.3 Allow admins to view and act on any user's sessions

## 9. Custom-requests page
- [ ] 9.1 Render the custom-requests page (URL, method, headers, optional bearer token, optional cookies, optional body)
- [ ] 9.2 Execute the request via the custom-requests tool capability, allowing keyless/absent-auth requests, and render the response
- [ ] 9.3 Require authentication for the page and the execution endpoint

## 10. Tests (local only — no real targets)
- [ ] 10.1 Auth-gate tests: unauthenticated page redirects to login; unauthenticated data endpoint rejected; authenticated request succeeds
- [ ] 10.2 Ownership tests: non-admin cannot list/view/cancel another user's session; admin can
- [ ] 10.3 Lifecycle test against a local mock target: start → receive progress fragments over the WebSocket → cancel → assert prompt stop and persisted partial findings
- [ ] 10.4 Search/filter tests over seeded fixtures for free-text, status, scanner-id, level, and target, all scoped to the requesting user
- [ ] 10.5 Custom-requests test against a local mock server, including a keyless request
