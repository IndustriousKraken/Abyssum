# Tasks

## 1. Scanner skeleton
- [ ] 1.1 Add `RestDiscoveryScanner` in `abyssum-scanners` implementing the `BaseScanner` trait
- [ ] 1.2 Declare scanner metadata: stable id `rest_discovery`, human name, description
- [ ] 1.3 Register it in the scanner registry so it is selectable by id

## 2. Wordlist
- [ ] 2.1 Load the endpoint wordlist from the seeded reference-data store (see add-seed-data) by scanner id
- [ ] 2.2 Load it once per scan run; dedupe and normalize leading slashes

## 3. Probing loop
- [ ] 3.1 Iterate candidate paths, acquiring the rate limiter before each request
- [ ] 3.2 Honor the cancellation signal between requests
- [ ] 3.3 Emit progress (tested / total / current path) via the `ScanContext` callback

## 4. Classification
- [ ] 4.1 Implement the response classifier (present / protected / absent / erroring)
- [ ] 4.2 Detect and discard soft-404s (2xx with not-found body) so they are not reported
- [ ] 4.3 Build `Finding` records with evidence: path, status, salient signals

## 5. Tests (local only — no real targets)
- [ ] 5.1 Unit-test the classifier over 200-API / 200-soft-404 / 401 / 403 / 404 / 500
- [ ] 5.2 Integration-test against a local mock server with known endpoints; assert exact findings
- [ ] 5.3 Test that cancellation stops the scan promptly and yields a partial result
- [ ] 5.4 Test that requests are paced through the rate limiter (no request precedes the floor)
