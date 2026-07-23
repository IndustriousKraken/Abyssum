# Make the dashboard the default screen after login

## Symptom

After logging in, the operator lands on the "Start a scan" page (`/`). The dashboard —
stats, past sessions, findings, search — is arguably the more useful home, and is where an
operator returning to the tool wants to start.

## Notes

No canonical requirement pins the post-login landing screen (the `web-ui` spec covers "Start
A Scan From The Web" and "Browse Past Sessions And Findings" as separate capabilities but
does not mandate which is the root), so this is a code change with no spec delta.

Today: `state.rs` routes `/` → `handlers::home` (start a scan) and `/dashboard` →
`handlers::dashboard`; `POST /login` redirects to `/`.

## Tasks

- [ ] Make the dashboard the default post-login view — e.g. redirect `/` (or the post-login
      redirect) to the dashboard, keeping the start-scan page reachable from the nav.
- [ ] Keep the nav links and all existing routes working; only the default/landing changes.
