# Tasks

## 1. Scanner skeleton
- [ ] 1.1 Add `IdorScanner` in `abyssum-scanners` implementing the `BaseScanner` trait
- [ ] 1.2 Declare scanner metadata: stable id `idor`, human name, description
- [ ] 1.3 Register it in the scanner registry so it is selectable by id

## 2. Reference seeding
- [ ] 2.1 Add curated built-in lists: object-reference endpoint patterns, parameter names, parameter endpoints, and per-shape id wordlists (numeric/uuid/username/email)
- [ ] 2.2 Probe likely "self" endpoints and harvest identifiers from response bodies (JSON-aware, regex fallback), grouping by id-shape
- [ ] 2.3 Fall back to a default numeric baseline when no identifiers are harvested

## 3. Enumeration loop
- [ ] 3.1 For each endpoint pattern + baseline reference, capture a baseline response, then derive and probe alternative references of the same shape
- [ ] 3.2 Strip the `Authorization` header from enumeration requests so success proves unauthenticated reachability
- [ ] 3.3 Acquire the rate limiter before each request and honor the cancellation signal between requests
- [ ] 3.4 Add query-parameter enumeration: baseline `?param=1` versus an alternative reference
- [ ] 3.5 Emit progress (tested / total / current) via the `ScanContext` callback

## 4. Detection and findings
- [ ] 4.1 Implement the error/not-found classifier (negative-indicator scan of the body)
- [ ] 4.2 Implement the baseline-difference comparator (JSON-aware, byte fallback)
- [ ] 4.3 Confirm an IDOR only when a non-baseline reference returns success, is not an error page, and differs materially from the baseline
- [ ] 4.4 Detect sensitive fields and score severity (critical/high/medium/low)
- [ ] 4.5 Build `Finding` records with evidence: affected endpoint or parameter, the reference tried, the baseline reference, observed status, bounded response sample, and detected sensitive fields

## 5. Tests (local only — no real targets)
- [ ] 5.1 Unit-test neighbour generation per id-shape, the error classifier, the difference comparator, and severity scoring
- [ ] 5.2 Integration-test against a local mock server where some references return distinct unauthorized data (vulnerable) and others echo the caller's own object or a generic shell (safe); assert exactly the vulnerable references are reported with correct evidence
- [ ] 5.3 Test that an identical-to-baseline response is not reported as an IDOR
- [ ] 5.4 Test that cancellation stops the scan promptly and yields a partial result
- [ ] 5.5 Test that requests are paced through the rate limiter (no request precedes the floor)
