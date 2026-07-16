//! The end-to-end CLI run: validate, scan, persist, render.
//!
//! [`execute`] is the whole spine behind one command. It loads and overlays
//! configuration, initializes logging, validates targets and scanner ids *before*
//! any request is issued, opens persistence, drives the selected scanners through
//! the shared [`Orchestrator`] while draining progress, stores the session and its
//! findings exactly as a web-initiated scan would, and renders the findings in the
//! requested format. The binary is a thin wrapper that prints the rendered output
//! and maps the outcome to a process exit code.

use std::sync::Arc;

use abyssum_core::{
    logging, Config, Credential, DatabaseManager, Identity, Orchestrator, ProgressCallback,
    ProgressKind, ProgressUpdate, ReferenceStore, ScanSession, ScannerRegistry, SessionStatus,
    Target,
};
use abyssum_scanners::register_builtins;
use uuid::Uuid;

use crate::cli::Cli;
use crate::config_overlay::{apply_overrides, Overrides};
use crate::{render, validate};

/// Process exit code: the scan completed.
pub const EXIT_SUCCESS: u8 = 0;
/// Process exit code: invalid input (unknown scanner, unparseable target, bad
/// configuration).
pub const EXIT_BAD_INPUT: u8 = 1;
/// Process exit code: the scan failed to run (engine, persistence, or render
/// error, or no scanner could run at all).
pub const EXIT_SCAN_FAILURE: u8 = 2;
/// Process exit code: the run was interrupted (Ctrl-C / SIGINT). Follows the
/// conventional `128 + SIGINT`.
pub const EXIT_INTERRUPTED: u8 = 130;

/// A failure that aborts the run before any output is produced. Carries the exit
/// code the process should return.
#[derive(Debug)]
pub enum CliError {
    /// Invalid input — rejected before any request is issued. Exits [`EXIT_BAD_INPUT`].
    BadInput(String),
    /// The scan could not run or its results could not be stored/rendered. Exits
    /// [`EXIT_SCAN_FAILURE`].
    ScanFailure(String),
}

impl CliError {
    /// The process exit code corresponding to this failure.
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::BadInput(_) => EXIT_BAD_INPUT,
            CliError::ScanFailure(_) => EXIT_SCAN_FAILURE,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::BadInput(msg) | CliError::ScanFailure(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for CliError {}

/// The result of a completed (or interrupted) run: the final session, the rendered
/// findings ready to print, and the process exit code that reflects the outcome.
#[derive(Debug)]
pub struct RunOutcome {
    /// The final session snapshot, as persisted.
    pub session: ScanSession,
    /// The findings rendered in the requested output format (trailing newline
    /// included).
    pub rendered: String,
    /// The process exit code: `0` completed, `130` interrupted, `2` errored.
    pub exit_code: u8,
}

/// Run the CLI end to end from already-parsed arguments.
///
/// Returns [`Err`] for a failure that prevents the scan from producing output
/// (bad input, or an engine/persistence/render error); otherwise [`Ok`] with the
/// rendered findings and an exit code (`0` on completion, `130` if interrupted,
/// `2` if no scanner ran). The findings are persisted before they are rendered, so
/// a returned [`RunOutcome`] always corresponds to a stored session.
pub async fn execute(cli: Cli) -> Result<RunOutcome, CliError> {
    // 1. Configuration: defaults < file < env < CLI flags. The base reflects the
    //    first three layers; the overlay adds the CLI layer for this run only.
    let base = Config::load(&cli.config)
        .map_err(|e| CliError::BadInput(format!("failed to load configuration: {e}")))?;
    let overrides = Overrides {
        min_delay: cli.min_delay,
        max_delay: cli.max_delay,
        log_level: cli.log_level.clone(),
    };
    let config = apply_overrides(base, &overrides);

    // 2. Logging at the chosen level, before the scan starts.
    logging::init(&config);

    // 3. Validate targets up front — no request is issued for a bad selection.
    let targets =
        validate::parse_targets(&cli.targets).map_err(|e| CliError::BadInput(e.to_string()))?;

    // 4. Open persistence (creates and seeds the store on first run).
    let db = DatabaseManager::connect_from_config(&config)
        .await
        .map_err(|e| CliError::ScanFailure(format!("failed to open the result store: {e}")))?;

    // 5. Build the registry from the seeded store, then validate the requested
    //    scanner ids against its `available()` ids — still before any request.
    let config = Arc::new(config);
    let store = db.reference_store();
    let scanner_ids = {
        let registry = build_registry(&config, &store);
        validate::resolve_scanners(&cli.scanners, &registry.available())
            .map_err(|e| CliError::BadInput(e.to_string()))?
    };

    // Parse the named identities. Two or more trigger an auth-differential run; a
    // single identity is an ordinary scan carrying its credential.
    let identities = parse_identities(&cli.identities).map_err(CliError::BadInput)?;
    if identities.len() >= 2 {
        return execute_differential(config, db, targets, scanner_ids, identities, cli.output)
            .await;
    }

    // 6. Create a session for the targets/scanners and run it through the shared
    //    engine, draining progress and honoring Ctrl-C. A credential from the
    //    `--cookie`/`--bearer` flags (or, failing that, a single supplied identity)
    //    is attached to every scanner's requests; BAC/IDOR strip it per-request.
    let credential = flag_credential(cli.cookie.clone(), cli.bearer.clone())
        .or_else(|| identities.into_iter().next().and_then(|id| id.credential));
    let registry = build_registry(&config, &store);
    let mut orchestrator = Orchestrator::new(config, registry);
    if let Some(credential) = credential {
        orchestrator = orchestrator.with_credential(credential);
    }
    let handle = orchestrator
        .create_session(targets, scanner_ids)
        .map_err(|e| CliError::BadInput(e.to_string()))?;
    let session_id = handle.lock().expect("session handle not poisoned").id;

    let session = run_to_completion(&orchestrator, session_id, progress_callback())
        .await
        .map_err(|e| CliError::ScanFailure(format!("scan failed: {e}")))?;

    // 7. Persist the session and its findings, identically to a web-initiated scan
    //    (the session row first, so the findings' foreign key resolves).
    db.save_session(&session)
        .await
        .map_err(|e| CliError::ScanFailure(format!("failed to persist the scan session: {e}")))?;
    for finding in &session.findings {
        db.save_finding(session.id, finding)
            .await
            .map_err(|e| CliError::ScanFailure(format!("failed to persist a finding: {e}")))?;
    }

    // 8. Render the findings, then map the terminal status to an exit code.
    let rendered = render::render(&session.findings, cli.output)
        .map_err(|e| CliError::ScanFailure(e.to_string()))?;
    let exit_code = match session.status {
        SessionStatus::Completed => EXIT_SUCCESS,
        SessionStatus::Cancelled => EXIT_INTERRUPTED,
        // Errored (no scanner ran) or any unexpected non-terminal status.
        _ => EXIT_SCAN_FAILURE,
    };

    Ok(RunOutcome {
        session,
        rendered,
        exit_code,
    })
}

/// Build a scanner registry from the seeded reference store. A fresh registry per
/// call — the differential run builds one per identity.
fn build_registry(config: &Arc<Config>, store: &ReferenceStore) -> ScannerRegistry {
    let mut registry = ScannerRegistry::new(config.clone());
    register_builtins(&mut registry, store);
    registry
}

/// Build a [`Credential`] from the `--cookie` / `--bearer` flags. The two are
/// independent; `None` only when neither is supplied — the scan then runs
/// unauthenticated (unchanged behavior).
fn flag_credential(cookie: Option<String>, bearer: Option<String>) -> Option<Credential> {
    match (bearer, cookie) {
        (None, None) => None,
        (bearer, cookie) => Some(Credential { bearer, cookie }),
    }
}

/// Parse each `--identity` spec into an [`Identity`]. A spec is
/// `label[:cookie=VALUE][:bearer=TOKEN]`: the text before the first `:` is the
/// label; each remaining `:`-separated segment is a `cookie=`/`bearer=` credential
/// field (values may contain `=` but not `:`). A bare label is the anonymous
/// identity.
fn parse_identities(specs: &[String]) -> Result<Vec<Identity>, String> {
    specs.iter().map(|spec| parse_identity(spec)).collect()
}

/// Parse one identity spec. See [`parse_identities`].
fn parse_identity(spec: &str) -> Result<Identity, String> {
    let mut segments = spec.split(':');
    let label = segments.next().unwrap_or("").trim().to_string();
    if label.is_empty() {
        return Err(format!("identity spec {spec:?} has an empty label"));
    }
    let mut bearer = None;
    let mut cookie = None;
    for segment in segments {
        let (key, value) = segment.split_once('=').ok_or_else(|| {
            format!("identity segment {segment:?} in {spec:?} is not a key=value pair")
        })?;
        match key.trim() {
            "bearer" => bearer = Some(value.to_string()),
            "cookie" => cookie = Some(value.to_string()),
            other => {
                return Err(format!(
                    "unknown identity field {other:?} in {spec:?} (expected 'cookie' or 'bearer')"
                ))
            }
        }
    }
    let credential = match (bearer, cookie) {
        (None, None) => None,
        (bearer, cookie) => Some(Credential { bearer, cookie }),
    };
    Ok(Identity { label, credential })
}

/// Run an auth-differential scan: the selected scanners run once per identity, then
/// every surfaced resource is re-probed under each identity and access-control
/// divergence is reported. The differential findings are persisted and rendered
/// exactly like an ordinary scan's.
async fn execute_differential(
    config: Arc<Config>,
    db: DatabaseManager,
    targets: Vec<Target>,
    scanner_ids: Vec<String>,
    identities: Vec<Identity>,
    output: crate::cli::OutputFormat,
) -> Result<RunOutcome, CliError> {
    let store = db.reference_store();
    let findings = {
        let make_registry = || build_registry(&config, &store);
        abyssum_core::run_differential(
            config.clone(),
            make_registry,
            &targets,
            &scanner_ids,
            &identities,
        )
        .await
        .map_err(|e| CliError::ScanFailure(format!("differential scan failed: {e}")))?
    };

    // Persist and render the differential findings under one session, identically
    // to an ordinary scan (the session row first, so each finding's foreign key
    // resolves).
    let mut session = ScanSession::new(targets, scanner_ids);
    session.status = SessionStatus::Completed;
    session.completed_units = session.total_units;
    session.findings = findings;
    // Stamp the session from a finding's timestamp (the CLI has no direct clock
    // dependency); a divergence-free run simply carries no timestamps.
    let stamp = session.findings.first().map(|finding| finding.timestamp);
    session.started_at = stamp;
    session.finished_at = stamp;

    db.save_session(&session)
        .await
        .map_err(|e| CliError::ScanFailure(format!("failed to persist the scan session: {e}")))?;
    for finding in &session.findings {
        db.save_finding(session.id, finding)
            .await
            .map_err(|e| CliError::ScanFailure(format!("failed to persist a finding: {e}")))?;
    }

    let rendered = render::render(&session.findings, output)
        .map_err(|e| CliError::ScanFailure(e.to_string()))?;
    Ok(RunOutcome {
        session,
        rendered,
        exit_code: EXIT_SUCCESS,
    })
}

/// Run the session to its terminal state, cancelling promptly on Ctrl-C.
///
/// On the first SIGINT the orchestrator's cancel path is signalled so the scan
/// stops promptly; the run future then resolves with the partial (`Cancelled`)
/// session, whose findings are still rendered and persisted by the caller.
async fn run_to_completion(
    orchestrator: &Orchestrator,
    session_id: Uuid,
    progress: ProgressCallback,
) -> abyssum_core::Result<ScanSession> {
    let run = orchestrator.run(session_id, Some(progress));
    tokio::pin!(run);
    loop {
        tokio::select! {
            // Bias toward completion so a run that finishes at the same time as a
            // signal is reported as completed, not interrupted.
            biased;
            result = &mut run => return result,
            signal = tokio::signal::ctrl_c() => {
                if signal.is_ok() {
                    // Best effort: a race where the run just finished leaves nothing
                    // active to cancel, which is fine.
                    let _ = orchestrator.cancel(session_id);
                }
                // Keep awaiting the run; it returns the Cancelled session promptly.
            }
        }
    }
}

/// Build the progress callback that drains updates to the terminal as the scan
/// runs. Orchestrator unit-level updates surface at `info`; the finer
/// scanner-internal probe updates at `debug`. The two are told apart by the
/// update's [`ProgressKind`] — a structural discriminator, not the wording of the
/// free-form message. Output goes through `tracing`, so it is plain log lines when
/// not attached to a TTY and its volume follows the chosen log level.
fn progress_callback() -> ProgressCallback {
    Arc::new(|update: ProgressUpdate| match update.kind {
        ProgressKind::Unit => {
            tracing::info!(
                target: "abyssum::progress",
                scanner = %update.scanner_id,
                completed = update.items_completed,
                total = update.total_items,
                item = update.current_item.as_deref().unwrap_or(""),
                "scan progress",
            );
        }
        ProgressKind::ScannerInternal => {
            tracing::debug!(
                target: "abyssum::progress",
                scanner = %update.scanner_id,
                completed = update.items_completed,
                total = update.total_items,
                item = update.current_item.as_deref().unwrap_or(""),
                "scanner progress",
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_identity_reads_label_and_credentials() {
        // A bare label is the anonymous identity.
        let anon = parse_identity("guest").unwrap();
        assert_eq!(anon.label, "guest");
        assert!(anon.credential.is_none());

        // Bearer only.
        let alice = parse_identity("alice:bearer=tok-a").unwrap();
        assert_eq!(alice.label, "alice");
        let cred = alice.credential.unwrap();
        assert_eq!(cred.bearer.as_deref(), Some("tok-a"));
        assert!(cred.cookie.is_none());

        // Cookie whose value itself contains '=' (split is on the first '=' only).
        let bob = parse_identity("bob:cookie=session=abc123").unwrap();
        assert_eq!(
            bob.credential.unwrap().cookie.as_deref(),
            Some("session=abc123")
        );

        // Both fields, either order.
        let both = parse_identity("carol:cookie=s=1:bearer=t").unwrap();
        let cred = both.credential.unwrap();
        assert_eq!(cred.cookie.as_deref(), Some("s=1"));
        assert_eq!(cred.bearer.as_deref(), Some("t"));
    }

    #[test]
    fn parse_identity_rejects_bad_specs() {
        assert!(parse_identity("").is_err());
        assert!(parse_identity(":bearer=t").is_err());
        // A segment that is not key=value.
        assert!(parse_identity("alice:token").is_err());
        // An unknown field name.
        assert!(parse_identity("alice:token=t").is_err());
    }

    #[test]
    fn flag_credential_builds_from_either_flag() {
        // Neither flag → no credential (unauthenticated scan).
        assert!(flag_credential(None, None).is_none());
        // Cookie only.
        let c = flag_credential(Some("session=abc".into()), None).unwrap();
        assert_eq!(c.cookie.as_deref(), Some("session=abc"));
        assert!(c.bearer.is_none());
        // Bearer only.
        let c = flag_credential(None, Some("tok".into())).unwrap();
        assert_eq!(c.bearer.as_deref(), Some("tok"));
        assert!(c.cookie.is_none());
        // Both.
        let c = flag_credential(Some("session=abc".into()), Some("tok".into())).unwrap();
        assert_eq!(c.cookie.as_deref(), Some("session=abc"));
        assert_eq!(c.bearer.as_deref(), Some("tok"));
    }

    #[test]
    fn parse_identities_collects_all() {
        let ids = parse_identities(&[
            "alice:bearer=a".to_string(),
            "bob:cookie=s=b".to_string(),
            "guest".to_string(),
        ])
        .unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[2].label, "guest");
        assert!(ids[2].is_anonymous());
    }

    #[test]
    fn exit_codes_map_from_error_kind() {
        assert_eq!(CliError::BadInput("x".into()).exit_code(), EXIT_BAD_INPUT);
        assert_eq!(
            CliError::ScanFailure("x".into()).exit_code(),
            EXIT_SCAN_FAILURE
        );
        // The conventional interrupt code.
        assert_eq!(EXIT_INTERRUPTED, 130);
    }
}
