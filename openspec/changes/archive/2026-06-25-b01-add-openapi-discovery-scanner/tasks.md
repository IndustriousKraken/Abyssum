# Tasks

## 1. Scanner skeleton
- [x] 1.1 Add `OpenApiDiscoveryScanner` in `abyssum-scanners` implementing the `BaseScanner` trait
- [x] 1.2 Declare scanner metadata: stable id `openapi_discovery`, human name, description
- [x] 1.3 Register it in the scanner registry so it is selectable by id

## 2. Spec-location wordlist
- [x] 2.1 Load the OpenAPI/Swagger location wordlist from the seeded reference-data store (see add-seed-data) by scanner id
- [x] 2.2 Load it once per scan run; dedupe and normalize leading slashes

## 3. Probing loop
- [x] 3.1 Iterate candidate spec paths, acquiring the rate limiter before each request
- [x] 3.2 Honor the cancellation signal between requests
- [x] 3.3 Emit progress (tested / total / current path) via the `ScanContext` callback

## 4. Spec validation
- [x] 4.1 Parse candidate responses as JSON or YAML, choosing format from content-type and extension with the other as fallback
- [x] 4.2 Implement the validator: accept only bodies bearing an OpenAPI/Swagger marker (`openapi`, `swagger`, or a `paths` object)
- [x] 4.3 Reject unrelated 2xx responses (non-spec JSON, HTML, unparseable bodies) so they are not reported
- [x] 4.4 Derive the spec type from the marker for the finding evidence

## 5. Endpoint extraction
- [x] 5.1 Extract documented endpoints from each valid spec's `paths` object, joined to the target base URL
- [x] 5.2 De-duplicate the endpoint set across all discovered specs
- [x] 5.3 Build a `Finding` summarizing the discovered spec(s) and documented endpoints as evidence

## 6. Tests (local only — no real targets)
- [x] 6.1 Unit-test the validator over OpenAPI-JSON / Swagger-JSON / YAML-spec / non-spec-JSON / HTML / non-200
- [x] 6.2 Unit-test endpoint extraction from a spec's `paths` object (correct paths, de-duplicated)
- [x] 6.3 Integration-test against a local mock server serving a spec at a known location plus unrelated 2xx content; assert exactly the spec is reported with its endpoints
- [x] 6.4 Test that cancellation stops the scan promptly and yields a partial result
- [x] 6.5 Test that requests are paced through the rate limiter (no request precedes the floor)
