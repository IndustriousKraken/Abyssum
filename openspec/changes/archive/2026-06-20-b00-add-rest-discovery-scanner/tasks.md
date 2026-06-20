# Tasks

## 1. Scanner skeleton
- [x] 1.1 Add `RestDiscoveryScanner` in `abyssum-scanners` implementing the `BaseScanner` trait
- [x] 1.2 Declare scanner metadata: stable id `rest_discovery`, human name, description
- [x] 1.3 Register it in the scanner registry so it is selectable by id

## 2. Wordlist
- [x] 2.1 Load the endpoint wordlist from the seeded reference-data store (see add-seed-data) by scanner id
- [x] 2.2 Load it once per scan run; dedupe and normalize leading slashes

## 3. Probing loop
- [x] 3.1 Iterate candidate paths, acquiring the rate limiter before each request
- [x] 3.2 Honor the cancellation signal between requests
- [x] 3.3 Emit progress (tested / total / current path) via the `ScanContext` callback

## 4. Classification
- [x] 4.1 Implement the response classifier (present / protected / absent / erroring)
- [x] 4.2 Detect and discard soft-404s (2xx with not-found body) so they are not reported
- [x] 4.3 Build `Finding` records with evidence: path, status, salient signals

## 5. Tests (local only — no real targets)
- [x] 5.1 Unit-test the classifier over 200-API / 200-soft-404 / 401 / 403 / 404 / 500
- [x] 5.2 Integration-test against a local mock server with known endpoints; assert exact findings
- [x] 5.3 Test that cancellation stops the scan promptly and yields a partial result
- [x] 5.4 Test that requests are paced through the rate limiter (no request precedes the floor)
