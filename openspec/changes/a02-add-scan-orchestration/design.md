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

### Shared value types

These are the cross-cutting types every scanner, the engine, persistence, reporting, and the
surfaces share. Defining them here (the change where the scanner trait is born) is what keeps
the six scanners from each inventing their own vocabulary.

```rust
/// What a scan points at. `base_url` identifies the origin; `path` is an optional route
/// beneath it; `id_template` is an optional path carrying an object-reference placeholder
/// (e.g. "/api/users/{id}") that reference-enumeration (IDOR) scanners substitute into.
pub struct Target {
    base_url: Url,                 // scheme + host + optional port
    path: Option<String>,
    id_template: Option<String>,
}
// host() (for per-domain pacing) and full_url() (base_url joined with path) are derived.

pub enum Severity { Info, Low, Medium, High, Critical }   // ordered, Info is the floor
pub enum Status   { Vulnerable, Safe, Info }              // disposition; reportable == Vulnerable
```

`Finding` is this build's name for the v1 `ScanResult` value: `scanner_id`, `target`,
`severity: Severity` (**required**, defaults to `Severity::Info` — never omitted), `status:
Status`, `title`, optional `description`, optional structured `evidence`, optional
`recommendations`, and a `timestamp`. Persistence (a03) assigns a stable `id` on save, which
annotations (d00) later reference. Scanner-specific labels ("accessible", "introspection
enabled") live in `title`/`description`, not in new `Status` values. Keeping one finding type
means the registry, persistence, and surfaces all speak the same shape.

### `ScanContext`

A cheaply-cloneable struct handed to `scan()`. It carries the cross-cutting concerns so the
scanner owns none of them. Crucially, the scanner is given **no raw HTTP client** — the only
way out to the network is `send()`, which paces through the limiter and stamps a User-Agent,
so a scanner cannot bypass the floor:

```rust
pub struct ScanContext {
    config: Arc<Config>,
    rate_limiter: Arc<RateLimiter>,        // from the preceding add-rate-limiting change
    ua_source: Arc<dyn UserAgentSource>,   // yields a UA per request; default = single identity,
                                           // replaced by the rotating realistic pool in add-seed-data (a04)
    progress: Option<ProgressCallback>,    // Arc<dyn Fn(ProgressUpdate) + Send + Sync>
    cancel: CancellationToken,             // observable stop signal
    auth: Option<Credential>,              // bearer token and/or cookie (see auth plumbing below)
}
// pub async fn send(&self, req: RequestSpec) -> Result<Response>
//   — acquires the limiter for req's host, applies ua_source.next(), then sends. No other path out.
```

`UserAgentSource` is a seam this change owns with a trivial default (one identity); `add-seed-data`
swaps in the rotating realistic pool without `ScanContext` changing shape. `Credential` carries a
bearer token and/or cookie so CORS can attach one and BAC/IDOR can run with it stripped.

Behaviorally the context must let a scanner: (a) send an HTTP request **only** via the paced
`send()`, (b) which paces through the rate limiter and applies a rotating User-Agent before
sending, (c) call `report_progress(ProgressUpdate)`, and (d) check
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
("completed 3 / 6 scanner-target units"). The web surface (c03) subscribes to a broadcast of
these; the CLI (c01) can render the latest. The spec only requires that progress carry
tested/total/current and be emitted during the scan.

### Library / Crate Choices

- **Async runtime:** `tokio` (canon-locked).
- **Trait objects:** `async-trait` for the object-safe `BaseScanner`.
- **Cancellation:** `tokio_util::sync::CancellationToken` (fallback: `tokio::sync::watch`).
- **Progress fan-out:** `tokio::sync::broadcast` for the orchestrator's progress stream.
- **Shared state:** `Arc` + `tokio::sync::RwLock`/`Mutex` for the registry and active
  sessions.
- **Ids:** `uuid` for session ids.
- **HTTP client:** `reqwest` (canon-locked), owned by the engine and reached only through
  `ScanContext::send` — never handed to a scanner directly. The `RateLimiter` type is already
  defined by `add-rate-limiting`, which now precedes this change, so there is no forward
  dependency.

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
