# Tasks

## 1. Scanner skeleton
- [x] 1.1 Add `BacScanner` in `abyssum-scanners` implementing the `BaseScanner` trait
- [x] 1.2 Declare scanner metadata: stable id `bac`, human name, description
- [x] 1.3 Register it in the scanner registry so it is selectable by id

## 2. Wordlist
- [x] 2.1 Load the admin/sensitive-path wordlist from the seeded reference-data store (see add-seed-data) by scanner id
- [x] 2.2 Load it once per scan run; dedupe and normalize leading slashes

## 3. Probing loop
- [x] 3.1 Establish a baseline reachability probe of the base URL before iterating
- [x] 3.2 Iterate sensitive paths, stripping authorization credentials from every request
- [x] 3.3 Acquire the rate limiter before each request; honor cancellation between requests
- [x] 3.4 Emit progress (tested / total / current path) via the `ScanContext` callback

## 4. Unauthorized-access evaluation
- [x] 4.1 Implement the error/not-found page guard so recognized error bodies are discarded
- [x] 4.2 Detect sensitive-content signals (user data, credentials, DB, config, PII, multi-record JSON)
- [x] 4.3 Flag 2xx responses on admin/sensitive-named endpoints even without sensitive content
- [x] 4.4 Treat 401/403 responses as properly protected (no finding)
- [x] 4.5 Assign per-finding severity from endpoint sensitivity and exposed data class

## 5. Redirect follow-through
- [x] 5.1 On a 3xx whose `Location` points to a sensitive area, issue one follow-up probe
- [x] 5.2 Flag the redirect target when it is reachable unauthenticated with sensitive/admin content
- [x] 5.3 Treat a redirect target returning 401/403/404/5xx as not a vulnerability

## 6. Finding construction
- [x] 6.1 Build `Finding` records with evidence: endpoint, observed status, exposure signals, bounded response sample

## 7. Tests (local only — no real targets)
- [x] 7.1 Unit-test the evaluator over exposed-admin / soft-not-found / benign-200 / 401 / 403 / 404 / redirect cases
- [x] 7.2 Integration-test against a local mock server with exposed, protected, absent, and redirect-chain endpoints; assert exact findings
- [x] 7.3 Assert every probe is sent without authorization credentials
- [x] 7.4 Test that cancellation stops the scan promptly and yields a partial result
- [x] 7.5 Test that requests are paced through the rate limiter (no request precedes the floor)
