# Tasks

## 1. Scanner skeleton
- [x] 1.1 Add `GraphqlScanner` in `abyssum-scanners` implementing the `BaseScanner` trait
- [x] 1.2 Declare scanner metadata: stable id `graphql`, human name, description
- [x] 1.3 Register it in the scanner registry so it is selectable by id

## 2. Built-in path and query data
- [x] 2.1 Load the GraphQL path list from the seeded reference-data store (see add-seed-data) by scanner id (defaults `/graphql`, `/api/graphql`, `/v1/graphql`, `/graph`, `/query`)
- [x] 2.2 Load the introspection queries and sensitive-data test queries from the seeded store
- [x] 2.3 Load both once per scan run; normalize leading slashes on paths

## 3. Endpoint detection
- [x] 3.1 Iterate candidate paths, acquiring the rate limiter before each request and honoring cancellation between requests
- [x] 3.2 Probe each path with GET, then a POST of `{ __typename }`
- [x] 3.3 Implement the GraphQL detector (GraphQL-shaped JSON, content type, error indicators) and select the first detected endpoint
- [x] 3.4 Emit progress (tested / total / current path) via the `ScanContext` callback

## 4. Introspection exposure check
- [x] 4.1 POST an introspection query to the detected endpoint through the rate limiter
- [x] 4.2 Treat a 200 with non-empty `data` as introspection enabled and build a `Finding`
- [x] 4.3 Extract schema evidence: type count, query/mutation field names, sensitive type names
- [x] 4.4 Attach the schema evidence to the finding

## 5. Additional exposure checks
- [x] 5.1 Test unbounded query depth (a deeply nested query answered with non-empty `data`)
- [x] 5.2 Test query batching (an array request answered with an equal-length array response)
- [x] 5.3 Test sensitive-data queries and analyze responses for sensitive field names and values
- [x] 5.4 Assign per-finding severity and compute the overall scan severity as the highest finding

## 6. Tests (local only — no real targets)
- [x] 6.1 Unit-test the GraphQL detector over GraphQL JSON, a GraphQL error message, a `__schema` body, and a non-GraphQL 404
- [x] 6.2 Unit-test schema extraction over a representative introspection payload
- [x] 6.3 Unit-test the disclosure analyzer over sensitive field names, email values, and token-like values
- [x] 6.4 Integration-test against a local mock server: detect the endpoint and report an introspection finding with schema evidence
- [x] 6.5 Integration-test a mock endpoint with introspection disabled: no introspection finding
- [x] 6.6 Test that cancellation stops the scan promptly and yields a partial result
- [x] 6.7 Test that requests are paced through the rate limiter (no request precedes the floor)
