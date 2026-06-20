# Tasks

## 1. Shared value types and scanner contract
- [ ] 1.1 Define the `Target` type (`base_url`, optional `path`, optional `id_template`) with derived `host()` and `full_url()`, plus serde
- [ ] 1.2 Define the `Severity` enum (`Info`, `Low`, `Medium`, `High`, `Critical`; ordered, `Info` is the floor) and the `Status` enum (`Vulnerable`, `Safe`, `Info`), both with serde
- [ ] 1.3 Define the `Finding` type in `abyssum-core` (scanner id, target, **required** `severity: Severity` defaulting to `Info`, `status: Status`, title, optional description, optional evidence, optional recommendations, timestamp) with serde + a builder; the stable `id` is assigned by persistence on save
- [ ] 1.4 Define the `BaseScanner` trait: `id()`, `name()`, `description()`, async `scan(target, ctx) -> Result<Vec<Finding>>`, and a default `validate_target`
- [ ] 1.5 Re-export `Target`, `Severity`, `Status`, `Finding`, `BaseScanner`, and the scanner-related types from the crate root

## 2. Scan context
- [ ] 2.1 Define `ScanContext` carrying config, the rate limiter handle, a `UserAgentSource` (default single-identity; replaced by the rotating pool in `add-seed-data`), an optional progress callback, a cancellation signal, and an optional `Credential` (bearer and/or cookie)
- [ ] 2.2 Provide `report_progress(update)` that forwards to the callback when present and is a no-op otherwise
- [ ] 2.3 Provide `is_cancelled()` and an awaitable `check_cancellation()` that returns a cancellation error when signalled
- [ ] 2.4 Provide `send(request)` as the **only** outbound path: it acquires the rate limiter for the request's host, stamps a User-Agent from the `UserAgentSource`, then sends. Do not expose a raw HTTP client to scanners, so the pacing floor cannot be bypassed

## 3. Progress model
- [ ] 3.1 Define `ProgressUpdate` with scanner id, items completed, total items, current item, and a message
- [ ] 3.2 Define the progress-callback type and an orchestrator-level progress stream other components can subscribe to

## 4. Scanner registry
- [ ] 4.1 Define the registry mapping stable scanner id -> scanner factory
- [ ] 4.2 Implement `register(id, factory)`, `available() -> Vec<id>`, and `create(id) -> Result<Box<dyn BaseScanner>>`
- [ ] 4.3 Return a scanner-not-found error from `create` for an unknown id
- [ ] 4.4 Unit-test: register two stub scanners, assert `available()` lists both ids, `create` builds each, and an unknown id errors

## 5. Session lifecycle
- [ ] 5.1 Define `ScanSession` (id, targets, selected scanner ids, status, aggregated findings, counts, timing) and a `SessionStatus` enum (`Pending`, `Running`, `Completed`, `Cancelled`, `Errored`)
- [ ] 5.2 Implement session creation that validates every requested scanner id up front and rejects the whole request if any id is unknown
- [ ] 5.3 Implement a `progress()` accessor reporting completion as tested-units / total-units

## 6. Orchestrator
- [ ] 6.1 Implement execution: mark `Running`, run each selected scanner over every target, extend the session with returned findings
- [ ] 6.2 On a per-target scanner error, increment the error count and continue (do not abort the session)
- [ ] 6.3 Emit an overall progress update after each scanner-target unit completes
- [ ] 6.4 Pass each scanner a `ScanContext` wired to the session's progress callback and cancellation signal
- [ ] 6.5 Finalize status: `Cancelled` if cancellation fired, `Errored` if no scanner could run, else `Completed`; record end time
- [ ] 6.6 Implement `cancel(session_id)` that signals cancellation, transitions a running session to `Cancelled`, and leaves findings-so-far intact
- [ ] 6.7 Race each scanner future against the cancellation signal so a long-awaiting scan unwinds promptly

## 7. Tests (local only — no real targets)
- [ ] 7.1 Stub scanner emitting a fixed set of progress updates and findings without any network access
- [ ] 7.2 Test: a normal run aggregates all stub findings and ends `Completed`
- [ ] 7.3 Test: orchestrator forwards progress carrying tested / total / current during the run
- [ ] 7.4 Test: cancelling mid-scan stops promptly, ends `Cancelled`, and returns partial findings
- [ ] 7.5 Test: a stub scanner that errors on one target increments the error count without aborting the session
- [ ] 7.6 Test: selecting an unknown scanner id is rejected before any scan begins
