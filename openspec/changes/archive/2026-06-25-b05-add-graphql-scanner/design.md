# Design: GraphQL Scanner

## Technical Approach

Implement `GraphqlScanner` in `abyssum-scanners`, implementing the `BaseScanner` trait from
`abyssum-core` (defined in `add-scan-orchestration`). The scanner is given a `ScanContext`
with a progress callback, a cancellation signal, and a single paced `send()` — **no raw HTTP
client** — so it owns none of those concerns and cannot bypass pacing.

The scan runs in two phases:

```
# Phase 1: detect a GraphQL endpoint
for each candidate path in graphql_paths:
    ctx.check_cancellation()
    response = probe(base_url + path)        # ctx.send GET, then ctx.send POST { __typename }
    if looks_like_graphql(response): record candidate; stop at the first hit
    ctx.report_progress(tested, total, current_path)

# Phase 2: probe the first detected endpoint
if a GraphQL endpoint was found:
    introspection_check(endpoint)            # -> Finding (+ schema evidence) | none
    query_depth_check(endpoint)              # -> Finding | none
    batching_check(endpoint)                 # -> Finding | none
    for q in sensitive_data_queries:         # -> Finding | none each
        disclosure_check(endpoint, q)
```

Every request goes through `ctx.send`, which paces per-domain, so "two phases" never means
"faster than the configured floor per domain". If no endpoint is detected, the scan completes
with no findings.

## Library / Data Choices

- **GraphQL path list & test queries:** obtained from the seeded reference-data store (see
  `add-seed-data`), loaded by named list. This scanner loads two named lists, each by name:
  `graphql_paths` (the candidate endpoint paths) and `graphql_queries` (the probe queries).
  Each `graphql_queries` entry carries a label plus a query body, so a check can select a
  query by label and send its body. The curated paths and probe queries ship in
  `assets/seed/wordlists/paths_graphql.txt` and `assets/seed/wordlists/graphql_queries.txt`
  and are seeded into the database on first run; default paths mirror the v1 fallback
  (`/graphql`, `/api/graphql`, `/v1/graphql`, `/graph`, `/query`). No user-uploaded wordlists
  in v1 (see `project.md` non-goals).
- **HTTP:** issued through `ScanContext::send` (paced, UA-stamped); no raw client is exposed.
  POST bodies are JSON (`{"query": "..."}`), with `Content-Type: application/json`.
- **JSON:** `serde_json` to build queries and walk introspection / response payloads.

## Detection & Check Rules (informs the spec's behavior, kept testable)

### Is this a GraphQL endpoint?

A response is treated as GraphQL when **all** of the following hold for the status, or the
body carries GraphQL signals:

| Signal | Treated as GraphQL |
|--------|--------------------|
| status in {200, 400, 401, 403, 405, 501} AND JSON body has a `data` or `errors` key | yes |
| JSON body `message` mentions graphql/query/syntax/field/type | yes |
| body text contains `graphql`, `__schema`, `__type`, `query`, or `mutation` | yes |
| 404 / unrelated content | no |

Detection tries GET first, then a POST of `{ __typename }`.

### Introspection

POST an introspection query; if the response is `200` and carries a non-empty `data` object,
introspection is **enabled** → a finding. Schema evidence extracted from `__schema`:

- `types_count`
- query field names (from the query root type's fields) and mutation field names
- type names matching sensitive keywords (`user`, `admin`, `password`, `token`, `secret`,
  `key`, `auth`) as "sensitive types"

### Additional exposures (each a separate finding)

| Check | Signal that it is exposed |
|-------|---------------------------|
| Unbounded query depth | a deeply nested query returns `200` with non-empty `data` |
| Query batching | an array of queries returns `200` with an array response of equal length |
| Information disclosure | a sensitive-data query returns `data` containing sensitive field names or values (emails, token-like strings) |

### Severity

Each check that fires is its own `Finding` with its own `severity` from the canonical set.
There is **no scan-level severity field** — any "overall" level a surface shows is a
presentation rollup (the max severity across the session's findings), not a stored value.
Per-finding severity:

- introspection enabled → high
- disclosure of `password`/`token`/`secret`, or an admin query → critical
- user data / emails / token-like values → high
- other sensitive data → medium
- unbounded depth, batching → medium

### Canonical finding mapping

This scanner emits `Finding`s whose `severity` is drawn from the canonical `Severity` set
(`info | low | medium | high | critical`) and whose `status` is from `{vulnerable, safe,
info}` (per `add-scan-orchestration`). The check kind and schema evidence
("introspection enabled", batching, unbounded depth, disclosed fields) live in the finding
title/description and evidence, not in new status or severity values.

- Disclosure of `password`/`token`/`secret` or an admin query → `status: vulnerable`,
  `severity: critical`.
- Introspection enabled, or disclosure of user data / emails / token-like values →
  `status: vulnerable`, `severity: high`.
- Unbounded query depth, query batching, or other sensitive data →
  `status: vulnerable`, `severity: medium`.
- A detected endpoint with a check that comes back sound (e.g. introspection disabled) →
  `status: safe`, `severity: info` if recorded; no endpoint detected → no findings.

## Testing

- Unit-test the GraphQL detector over: GraphQL JSON (`data`/`errors`), a GraphQL error
  `message`, a `__schema` body, and a plain non-GraphQL 404.
- Unit-test schema extraction over a representative introspection payload (asserts
  `types_count`, query/mutation names, sensitive type detection).
- Unit-test the disclosure analyzer (sensitive field names, email values, token-like values).
- Integration-test against a **local mock HTTP server** that serves a GraphQL endpoint at a
  known path with introspection enabled; assert the scanner detects the endpoint, reports an
  introspection finding with schema evidence, and respects cancellation. A second fixture
  with introspection disabled yields no introspection finding.
- **No real targets.** All tests are local and deterministic.
