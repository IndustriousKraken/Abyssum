//! The orchestrator: drives selected scanners over targets.
//!
//! The orchestrator is the single engine every surface shares. It validates a
//! scan's selection up front (rejecting unknown ids before any traffic), runs
//! each selected scanner across every target, aggregates findings into the
//! session, emits progress as units complete, and supports prompt cancellation
//! that preserves the findings gathered so far.
//!
//! Lifecycle and aggregation rules (see the change's design):
//!
//! - A per-target scanner error increments the session's error count and the run
//!   continues — one target's failure never aborts the session.
//! - The terminal state is `Cancelled` if cancellation fired, `Errored` if no
//!   scanner could run at all, otherwise `Completed`.
//! - Each scanner future is raced against the cancellation signal, so a scanner
//!   sitting in a long await unwinds promptly on cancel.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::rate_limit::RateLimiter;

use super::context::{Credential, ScanContext, SingleUserAgent, UserAgentSource};
use super::progress::{ProgressCallback, ProgressUpdate};
use super::registry::ScannerRegistry;
use super::session::{ScanSession, SessionStatus};
use super::target::Target;

/// Capacity of the orchestrator's progress broadcast. Generous so brief
/// subscriber stalls do not drop updates under normal scan volumes.
const PROGRESS_CHANNEL_CAPACITY: usize = 1024;

/// A shared, observable handle to a session's live state. The caller holds this
/// across [`run`](Orchestrator::run); the orchestrator mutates it in place, so
/// progress and findings are visible as the scan proceeds.
pub type SessionHandle = Arc<Mutex<ScanSession>>;

/// An in-flight session the orchestrator can cancel by id.
#[derive(Clone)]
struct ActiveSession {
    cancel: CancellationToken,
    session: SessionHandle,
}

/// Drives scans. Holds the registry, the shared pacing authority, the engine's
/// HTTP client and User-Agent source, a progress broadcast, and the set of
/// active sessions.
pub struct Orchestrator {
    config: Arc<Config>,
    registry: Arc<ScannerRegistry>,
    rate_limiter: RateLimiter,
    ua_source: Arc<dyn UserAgentSource>,
    http: reqwest::Client,
    credential: Option<Credential>,
    progress_tx: broadcast::Sender<ProgressUpdate>,
    active: Mutex<HashMap<Uuid, ActiveSession>>,
}

impl Orchestrator {
    /// Build an orchestrator from the config and a populated registry. The shared
    /// rate limiter is derived from `config.scanning`, and the User-Agent source
    /// defaults to the single-identity source (`add-seed-data` swaps in the pool).
    pub fn new(config: Arc<Config>, registry: ScannerRegistry) -> Self {
        let rate_limiter = RateLimiter::from_config(&config.scanning);
        let (progress_tx, _) = broadcast::channel(PROGRESS_CHANNEL_CAPACITY);
        Self {
            config,
            registry: Arc::new(registry),
            rate_limiter,
            ua_source: Arc::new(SingleUserAgent::default()),
            http: reqwest::Client::new(),
            credential: None,
            progress_tx,
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Use a specific User-Agent source (builder-style).
    pub fn with_user_agent_source(mut self, source: Arc<dyn UserAgentSource>) -> Self {
        self.ua_source = source;
        self
    }

    /// Attach a credential applied to every scanner's requests (builder-style).
    pub fn with_credential(mut self, credential: Credential) -> Self {
        self.credential = Some(credential);
        self
    }

    /// Reuse a specific HTTP client (builder-style).
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http = client;
        self
    }

    /// The scanner registry.
    pub fn registry(&self) -> &ScannerRegistry {
        &self.registry
    }

    /// Subscribe to the orchestrator-level progress stream. Other components
    /// (e.g. the web surface) receive every [`ProgressUpdate`] emitted after they
    /// subscribe — both scanner-internal updates and orchestrator unit updates.
    pub fn subscribe(&self) -> broadcast::Receiver<ProgressUpdate> {
        self.progress_tx.subscribe()
    }

    /// Create a `Pending` session for `targets` and `scanner_ids`, **validating
    /// every requested id up front**. If any id is unknown the whole request is
    /// rejected with [`Error::ScannerNotFound`] and no session is created — so an
    /// unknown id never issues traffic.
    pub fn create_session(
        &self,
        targets: Vec<Target>,
        scanner_ids: Vec<String>,
    ) -> Result<SessionHandle> {
        for id in &scanner_ids {
            if !self.registry.contains(id) {
                return Err(Error::ScannerNotFound(id.clone()));
            }
        }

        let session = ScanSession::new(targets, scanner_ids);
        let id = session.id;
        let handle: SessionHandle = Arc::new(Mutex::new(session));
        self.active.lock().unwrap().insert(
            id,
            ActiveSession {
                cancel: CancellationToken::new(),
                session: handle.clone(),
            },
        );
        Ok(handle)
    }

    /// Convenience: create a session and run it to a terminal state, returning the
    /// final session. `progress` (if any) receives every update alongside the
    /// broadcast stream.
    pub async fn run_session(
        &self,
        targets: Vec<Target>,
        scanner_ids: Vec<String>,
        progress: Option<ProgressCallback>,
    ) -> Result<ScanSession> {
        let handle = self.create_session(targets, scanner_ids)?;
        let id = handle.lock().unwrap().id;
        self.run(id, progress).await
    }

    /// Run a previously created session to a terminal state, returning the final
    /// session snapshot. Mutates the shared [`SessionHandle`] in place as it goes.
    pub async fn run(
        &self,
        session_id: Uuid,
        progress: Option<ProgressCallback>,
    ) -> Result<ScanSession> {
        let active = self
            .active
            .lock()
            .unwrap()
            .get(&session_id)
            .cloned()
            .ok_or_else(|| Error::Other(format!("no such scan session: {session_id}")))?;
        let cancel = active.cancel.clone();
        let session = active.session.clone();

        // Snapshot the plan and mark Running.
        let (scanner_ids, targets) = {
            let mut s = session.lock().unwrap();
            s.status = SessionStatus::Running;
            s.started_at = Some(Utc::now());
            s.completed_units = 0;
            s.total_units = s.scanner_ids.len().saturating_mul(s.targets.len());
            (s.scanner_ids.clone(), s.targets.clone())
        };

        let fanout = self.build_fanout(progress);

        let mut ran_any = false;
        let mut cancelled = cancel.is_cancelled();

        'outer: for scanner_id in &scanner_ids {
            if cancelled {
                break;
            }
            let scanner = match self.registry.create(scanner_id) {
                Ok(scanner) => scanner,
                Err(_) => {
                    // Ids were validated in create_session, so this is unexpected;
                    // count it and continue rather than aborting.
                    session.lock().unwrap().error_count += 1;
                    continue;
                }
            };

            for target in &targets {
                if cancel.is_cancelled() {
                    cancelled = true;
                    break 'outer;
                }

                let ctx = self.context_for(&cancel, &fanout);

                // Race the scan against cancellation: a long-awaiting scan unwinds
                // promptly when the token fires (the scan future is dropped).
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        cancelled = true;
                        break 'outer;
                    }
                    result = scanner.scan(target, &ctx) => {
                        ran_any = true;
                        match result {
                            Ok(mut findings) => {
                                session.lock().unwrap().findings.append(&mut findings);
                            }
                            Err(_) => {
                                // One target's failure is recorded, not fatal.
                                session.lock().unwrap().error_count += 1;
                            }
                        }
                        let (completed, total) = {
                            let mut s = session.lock().unwrap();
                            s.completed_units += 1;
                            (s.completed_units, s.total_units)
                        };
                        // Overall progress after each scanner-target unit.
                        fanout(
                            ProgressUpdate::new(scanner_id.clone(), completed, total)
                                .current_item(target.full_url().to_string())
                                .message(format!("completed {completed}/{total} units")),
                        );
                    }
                }
            }
        }

        let final_session = {
            let mut s = session.lock().unwrap();
            s.finished_at = Some(Utc::now());
            s.status = if cancelled || cancel.is_cancelled() {
                SessionStatus::Cancelled
            } else if !ran_any {
                // No scanner-target unit ran at all (e.g. no scanner could be
                // built, or there were no targets): a session-level failure.
                SessionStatus::Errored
            } else {
                SessionStatus::Completed
            };
            s.clone()
        };

        self.active.lock().unwrap().remove(&session_id);
        Ok(final_session)
    }

    /// Signal cancellation for `session_id`: stops new requests promptly,
    /// transitions a still-running session to `Cancelled`, and leaves the
    /// findings gathered so far intact.
    pub fn cancel(&self, session_id: Uuid) -> Result<()> {
        let active = self.active.lock().unwrap().get(&session_id).cloned();
        match active {
            Some(active) => {
                active.cancel.cancel();
                let mut s = active.session.lock().unwrap();
                // Only transition a non-terminal session; never clobber a session
                // that already finished.
                if !s.status.is_terminal() {
                    s.status = SessionStatus::Cancelled;
                }
                Ok(())
            }
            None => Err(Error::Other(format!(
                "no active scan session to cancel: {session_id}"
            ))),
        }
    }

    /// Build the scan context for one unit, wired to the cancellation token, the
    /// shared limiter and HTTP client, the User-Agent source, the fan-out progress
    /// callback, and any configured credential.
    fn context_for(&self, cancel: &CancellationToken, fanout: &ProgressCallback) -> ScanContext {
        let ctx = ScanContext::new(
            self.config.clone(),
            self.rate_limiter.clone(),
            self.ua_source.clone(),
            cancel.clone(),
        )
        .with_http_client(self.http.clone())
        .with_progress(fanout.clone());
        match &self.credential {
            Some(credential) => ctx.with_credential(credential.clone()),
            None => ctx,
        }
    }

    /// Compose the progress fan-out: every update goes to the broadcast stream and
    /// to the caller's optional callback. The same callback is handed to each scan
    /// context (scanner-internal progress) and used for orchestrator unit updates.
    fn build_fanout(&self, user: Option<ProgressCallback>) -> ProgressCallback {
        let progress_tx = self.progress_tx.clone();
        Arc::new(move |update: ProgressUpdate| {
            // A send error only means "no subscribers"; that is fine.
            let _ = progress_tx.send(update.clone());
            if let Some(callback) = &user {
                callback(update);
            }
        })
    }
}
