# Design

Builds on `f01-add-observing-proxy-core`'s traffic store; adds analysis, no new capture path.

**Runs off the hot path.** Scoring/flagging operates over stored exchanges (on write via
the async writer, or on query), never inline in the relay — the proxy stays non-blocking.

**Flag categories** (heuristics, guidance not contract):
- **Auth material** — `Authorization` bearer/basic, `Cookie`/`Set-Cookie` session values,
  token-shaped query/body fields.
- **IDOR / pagination candidates** — numeric/UUID/sequential path segments and params
  (`id`, `user_id`, `page`, `offset`, `cursor`).
- **API endpoints** — JSON/those under `/api`, versioned paths, GraphQL.
- **Error responses** — 5xx and error-shaped bodies (stack traces, error codes).

**Interest score** — a simple additive score over the categories present, so an exchange
carrying a token *and* an object-reference param outranks a plain static asset. The score
orders the surfaced view; it is a ranking aid, not a verdict.

This deliberately mirrors the scanners' finding classes so surfaced traffic can later hand
IDOR/endpoint candidates to the scanner (a follow-on).
