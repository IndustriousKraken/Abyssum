# Tasks

## 1. Shared value types and scanner contract
- [x] 1.1 Define the `Target` type (`base_url`, optional `path`, optional `id_template`) with derived `host()` and `full_url()`, plus serde
- [x] 1.2 Define the `Severity` enum (`Info`, `Low`, `Medium`, `High`, `Critical`; ordered, `Info` is the floor) and the `Status` enum (`Vulnerable`, `Safe`, `Info`), both with serde
- [x] 1.3 Define the `Finding` type in `abyssum-core` (scanner id, target, **required** `severity: Severity` defaulting to `Info`, `status: Status`, title, optional description, optional evidence, optional recommendations, timestamp) with serde + a builder; the stable `id` is assigned by persistence on save
- [x] 1.4 Define the `BaseScanner` trait: `id()`, `name()`, `description()`, async `scan(target, ctx) -> Result<Vec<Finding>>`, and a default `validate_target`
- [x] 1.5 Re-export `Target`, `Severity`, `Status`, `Finding`, `BaseScanner`, and the scanner-related types from the crate root

## 2. Scan context
- [x] 2.1 Define `ScanContext` carrying config, the rate limiter handle, a `UserAgentSource` (default single-identity; replaced by the rotating pool in `add-seed-data`), an optional progress callback, a cancellation signal, and an optional `Credential` (bearer and/or cookie)
- [x] 2.2 Provide `report_progress(update)` that forwards to the callback when present and is a no-op otherwise
- [x] 2.3 Provide `is_cancelled()` and an awaitable `check_cancellation()` that returns a cancellation error when signalled
- [x] 2.4 Provide `send(request)` as the **only** outbound path: it acquires the rate limiter for the request's host, stamps a User-Agent from the `UserAgentSource`, then sends. Do not expose a raw HTTP client to scanners, so the pacing floor cannot be bypassed

## 3. Progress model
- [x] 3.1 Define `ProgressUpdate` with scanner id, items completed, total items, current item, and a message
- [x] 3.2 Define the progress-callback type and an orchestrator-level progress stream other components can subscribe to

## 4. Scanner registry
- [x] 4.1 Define the registry mapping stable scanner id -> scanner factory
- [x] 4.2 Implement `register(id, factory)`, `available() -> Vec<id>`, and `create(id) -> Result<Box<dyn BaseScanner>>`
- [x] 4.3 Return a scanner-not-found error from `create` for an unknown id
- [x] 4.4 Unit-test: register two stub scanners, assert `available()` lists both ids, `create` builds each, and an unknown id errors

## 5. Session lifecycle
- [x] 5.1 Define `ScanSession` (id, targets, selected scanner ids, status, aggregated findings, counts, timing) and a `SessionStatus` enum (`Pending`, `Running`, `Completed`, `Cancelled`, `Errored`)
- [x] 5.2 Implement session creation that validates every requested scanner id up front and rejects the whole request if any id is unknown
- [x] 5.3 Implement a `progress()` accessor reporting completion as tested-units / total-units

## 6. Orchestrator
- [x] 6.1 Implement execution: mark `Running`, run each selected scanner over every target, extend the session with returned findings
- [x] 6.2 On a per-target scanner error, increment the error count and continue (do not abort the session)
- [x] 6.3 Emit an overall progress update after each scanner-target unit completes
- [x] 6.4 Pass each scanner a `ScanContext` wired to the session's progress callback and cancellation signal
- [x] 6.5 Finalize status: `Cancelled` if cancellation fired, `Errored` if no scanner could run, else `Completed`; record end time
- [x] 6.6 Implement `cancel(session_id)` that signals cancellation, transitions a running session to `Cancelled`, and leaves findings-so-far intact
- [x] 6.7 Race each scanner future against the cancellation signal so a long-awaiting scan unwinds promptly

## 7. Tests (local only — no real targets)
- [x] 7.1 Stub scanner emitting a fixed set of progress updates and findings without any network access
- [x] 7.2 Test: a normal run aggregates all stub findings and ends `Completed`
- [x] 7.3 Test: orchestrator forwards progress carrying tested / total / current during the run
- [x] 7.4 Test: cancelling mid-scan stops promptly, ends `Cancelled`, and returns partial findings
- [x] 7.5 Test: a stub scanner that errors on one target increments the error count without aborting the session
- [x] 7.6 Test: selecting an unknown scanner id is rejected before any scan begins
