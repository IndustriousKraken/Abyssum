# Tasks

## 1. Scanner skeleton
- [ ] 1.1 Add `GraphqlScanner` in `abyssum-scanners` implementing the `BaseScanner` trait
- [ ] 1.2 Declare scanner metadata: stable id `graphql`, human name, description
- [ ] 1.3 Register it in the scanner registry so it is selectable by id

## 2. Built-in path and query data
- [ ] 2.1 Load the GraphQL path list from the seeded reference-data store (see add-seed-data) by scanner id (defaults `/graphql`, `/api/graphql`, `/v1/graphql`, `/graph`, `/query`)
- [ ] 2.2 Load the introspection queries and sensitive-data test queries from the seeded store
- [ ] 2.3 Load both once per scan run; normalize leading slashes on paths

## 3. Endpoint detection
- [ ] 3.1 Iterate candidate paths, acquiring the rate limiter before each request and honoring cancellation between requests
- [ ] 3.2 Probe each path with GET, then a POST of `{ __typename }`
- [ ] 3.3 Implement the GraphQL detector (GraphQL-shaped JSON, content type, error indicators) and select the first detected endpoint
- [ ] 3.4 Emit progress (tested / total / current path) via the `ScanContext` callback

## 4. Introspection exposure check
- [ ] 4.1 POST an introspection query to the detected endpoint through the rate limiter
- [ ] 4.2 Treat a 200 with non-empty `data` as introspection enabled and build a `Finding`
- [ ] 4.3 Extract schema evidence: type count, query/mutation field names, sensitive type names
- [ ] 4.4 Attach the schema evidence to the finding

## 5. Additional exposure checks
- [ ] 5.1 Test unbounded query depth (a deeply nested query answered with non-empty `data`)
- [ ] 5.2 Test query batching (an array request answered with an equal-length array response)
- [ ] 5.3 Test sensitive-data queries and analyze responses for sensitive field names and values
- [ ] 5.4 Assign per-finding severity and compute the overall scan severity as the highest finding

## 6. Tests (local only — no real targets)
- [ ] 6.1 Unit-test the GraphQL detector over GraphQL JSON, a GraphQL error message, a `__schema` body, and a non-GraphQL 404
- [ ] 6.2 Unit-test schema extraction over a representative introspection payload
- [ ] 6.3 Unit-test the disclosure analyzer over sensitive field names, email values, and token-like values
- [ ] 6.4 Integration-test against a local mock server: detect the endpoint and report an introspection finding with schema evidence
- [ ] 6.5 Integration-test a mock endpoint with introspection disabled: no introspection finding
- [ ] 6.6 Test that cancellation stops the scan promptly and yields a partial result
- [ ] 6.7 Test that requests are paced through the rate limiter (no request precedes the floor)
