# Tasks

## 1. Scanner skeleton
- [x] 1.1 Add `IdorScanner` in `abyssum-scanners` implementing the `BaseScanner` trait
- [x] 1.2 Declare scanner metadata: stable id `idor`, human name, description
- [x] 1.3 Register it in the scanner registry so it is selectable by id

## 2. Reference seeding
- [x] 2.1 Add curated built-in lists: object-reference endpoint patterns, parameter names, parameter endpoints, and per-shape id wordlists (numeric/uuid/username/email)
- [x] 2.2 Probe likely "self" endpoints and harvest identifiers from response bodies (JSON-aware, regex fallback), grouping by id-shape
- [x] 2.3 Fall back to a default numeric baseline when no identifiers are harvested

## 3. Enumeration loop
- [x] 3.1 For each endpoint pattern + baseline reference, capture a baseline response, then derive and probe alternative references of the same shape
- [x] 3.2 Strip the `Authorization` header from enumeration requests so success proves unauthenticated reachability
- [x] 3.3 Acquire the rate limiter before each request and honor the cancellation signal between requests
- [x] 3.4 Add query-parameter enumeration: baseline `?param=1` versus an alternative reference
- [x] 3.5 Emit progress (tested / total / current) via the `ScanContext` callback

## 4. Detection and findings
- [x] 4.1 Implement the error/not-found classifier (negative-indicator scan of the body)
- [x] 4.2 Implement the baseline-difference comparator (JSON-aware, byte fallback)
- [x] 4.3 Confirm an IDOR only when a non-baseline reference returns success, is not an error page, and differs materially from the baseline
- [x] 4.4 Detect sensitive fields and score severity (critical/high/medium/low)
- [x] 4.5 Build `Finding` records with evidence: affected endpoint or parameter, the reference tried, the baseline reference, observed status, bounded response sample, and detected sensitive fields

## 5. Tests (local only — no real targets)
- [x] 5.1 Unit-test neighbour generation per id-shape, the error classifier, the difference comparator, and severity scoring
- [x] 5.2 Integration-test against a local mock server where some references return distinct unauthorized data (vulnerable) and others echo the caller's own object or a generic shell (safe); assert exactly the vulnerable references are reported with correct evidence
- [x] 5.3 Test that an identical-to-baseline response is not reported as an IDOR
- [x] 5.4 Test that cancellation stops the scan promptly and yields a partial result
- [x] 5.5 Test that requests are paced through the rate limiter (no request precedes the floor)
