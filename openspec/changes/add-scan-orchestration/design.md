## Design: Scan Orchestration

## Technical Approach

The orchestration engine lives in `abyssum-core` and is the single dependency every scanner
and surface shares. It has four cooperating pieces:

```
BaseScanner (trait)   — what a scanner implements; identity + scan(target, ctx)
ScanContext (struct)  — what a scanner is handed at run time
ScannerRegistry       — maps stable id -> scanner factory; selection by id
Orchestrator/Session  — drives selected scanners over targets; lifecycle + progress + cancel
```

### `BaseScanner` trait

An `async_trait` object-safe trait so scanners can be stored as `Box<dyn BaseScanner>` /
`Arc<dyn BaseScanner>` in the registry:

```rust
#[async_trait]
pub trait BaseScanner: Send + Sync {
    fn id(&self) -> &str;            // stable scanner id, e.g. "rest_discovery"
    fn name(&self) -> &str;         // human-readable
    fn description(&self) -> &str;
    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>>;
    fn validate_target(&self, target: &Target) -> Result<()> { /* default: URL parses */ }
}
```

`Finding` is this build's name for the v1 `ScanResult` value (target, scanner id, status,
optional severity level, title, description, evidence, recommendations, timestamp). Keeping
one finding type means the registry, persistence (#4), and surfaces all speak the same shape.

### `ScanContext`

A cheaply-cloneable struct handed to `scan()`. It carries the four cross-cutting concerns so
the scanner owns none of them:

```rust
pub struct ScanContext {
    config: Arc<Config>,
    http: reqwest::Client,                 // shared connection-pooled client
    rate_limiter: Arc<RateLimiter>,        // from add-rate-limiting (#3)
    progress: Option<ProgressCallback>,    // Arc<dyn Fn(ProgressUpdate) + Send + Sync>
    cancel: CancellationToken,             // observable stop signal
    auth_token: Option<String>,
    user_agent: Option<String>,
}
```

Behaviorally the context must let a scanner: (a) send an HTTP request, (b) pace it through
the rate limiter before sending, (c) call `report_progress(ProgressUpdate)`, and (d) check
`is_cancelled()` / `check_cancellation()`. The spec describes those capabilities, not the
type — per `project.md`, crate/type names stay here.

### Cancellation

`tokio_util::sync::CancellationToken` (or a `tokio::sync::watch::<bool>` receiver). The
orchestrator holds the source; each `ScanContext` gets a child/clone. Scanners check it
between requests, so a cancel turns the loop into a prompt, clean stop that still returns
findings gathered so far. The orchestrator also races each `scan()` future against the
token so a scanner sitting in a long await unwinds promptly.

### Registry and selection

`HashMap<String, ScannerFactory>` behind an `RwLock` (or built once and frozen). A factory
is `Fn(Arc<Config>) -> Box<dyn BaseScanner>` so each session gets fresh scanner instances.
`available()` lists ids; `create(id)` errors with the workspace `Error::ScannerNotFound`
when the id is unknown. The orchestrator validates **all** requested ids up front and
rejects the whole request if any is unknown — fail fast before issuing traffic.

### Session lifecycle and aggregation

A `ScanSession` holds targets, selected ids, a status, the aggregated findings, and timing.
Status is an enum: `Running -> {Completed | Cancelled | Errored}` (plus an initial
`Pending`). The orchestrator:

1. marks the session `Running`, records start time,
2. for each selected id, builds a scanner and runs it over every target,
3. extends the session with returned findings; a per-target `scan()` error increments an
   error count and continues (one target's failure never aborts the session),
4. emits an overall progress update after each unit completes,
5. finalizes: `Cancelled` if cancellation fired, else `Errored` if it could not run any
   scanner at all, else `Completed`; records end time.

`Errored` is reserved for a session-level failure (e.g. no scanner could be constructed);
individual per-target errors are counted but leave the session `Completed`. This mirrors v1
intent while making the terminal states cleanly observable.

### Progress model

`ProgressUpdate { scanner_id, items_completed, total_items, current_item, message }`. Two
granularities flow through the same channel: scanner-internal progress (a scanner reporting
"tested 12 / 100, current /admin") via the context callback, and orchestrator-level progress
("completed 3 / 6 scanner-target units"). The web surface (#14) subscribes to a broadcast of
these; the CLI (#12) can render the latest. The spec only requires that progress carry
tested/total/current and be emitted during the scan.

### Library / Crate Choices

- **Async runtime:** `tokio` (canon-locked).
- **Trait objects:** `async-trait` for the object-safe `BaseScanner`.
- **Cancellation:** `tokio_util::sync::CancellationToken` (fallback: `tokio::sync::watch`).
- **Progress fan-out:** `tokio::sync::broadcast` for the orchestrator's progress stream.
- **Shared state:** `Arc` + `tokio::sync::RwLock`/`Mutex` for the registry and active
  sessions.
- **Ids:** `uuid` for session ids.
- **HTTP client type in the context:** `reqwest` (canon-locked); the rate limiter type comes
  from `add-rate-limiting`.

## Testing

- Unit: registry lists/selects by id; unknown id yields `ScannerNotFound`; a request naming
  one bad id is rejected before any scan runs.
- Unit: session state machine — a normal run ends `Completed`; a cancelled run ends
  `Cancelled` and keeps prior findings; a per-target scanner error increments the error
  count without changing the terminal state.
- Integration with a **stub scanner** (no network) that emits N progress updates and M
  findings: assert the orchestrator aggregates all M findings and forwards progress carrying
  tested/total/current.
- Cancellation: a stub scanner that awaits a barrier each iteration; fire cancellation
  mid-scan and assert it stops promptly and returns partial findings.
- A scanner-vs-real-server integration test belongs to the scanner changes and uses a
  **local mock HTTP server only**. Orchestration tests need no network at all.
