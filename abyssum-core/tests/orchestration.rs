//! Orchestration integration tests — local only, no real targets, no network.
//!
//! Every test drives the public [`Orchestrator`] with a no-network **stub
//! scanner** (task 7.1). The stub emits progress and findings, and can be
//! configured to error on a given host (7.5) or block on a given host until
//! cancelled (7.4), so the lifecycle, aggregation, progress, and cancellation
//! behaviour can be exercised deterministically without touching the network.

use std::future;
use std::sync::{Arc, Mutex};

use abyssum_core::scan::BaseScanner;
use abyssum_core::{
    Config, Error, Finding, Orchestrator, ProgressCallback, ProgressUpdate, ScanContext,
    ScannerRegistry, SessionStatus, Severity, Status, Target,
};
use async_trait::async_trait;
use tokio::sync::Notify;

/// Task 7.1: a stub scanner that needs no network. It reports one progress
/// update per finding and returns `findings_per_target` findings, unless the
/// target's host matches `error_on_host` (then it errors), `block_on_host`
/// (then it signals `started` and blocks forever, to be cancelled), or
/// `panic_on_host` (then it panics, to exercise the run's unwind safety net).
#[derive(Clone)]
struct StubScanner {
    id: String,
    findings_per_target: usize,
    error_on_host: Option<String>,
    block_on_host: Option<String>,
    panic_on_host: Option<String>,
    started: Arc<Notify>,
}

impl StubScanner {
    fn simple(id: &str, findings_per_target: usize) -> Self {
        Self {
            id: id.to_string(),
            findings_per_target,
            error_on_host: None,
            block_on_host: None,
            panic_on_host: None,
            started: Arc::new(Notify::new()),
        }
    }
}

#[async_trait]
impl BaseScanner for StubScanner {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        "Stub scanner"
    }
    fn description(&self) -> &str {
        "Test stub — emits fixed progress and findings, no network"
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> abyssum_core::Result<Vec<Finding>> {
        let host = target.host().unwrap_or_default().to_string();

        if self.error_on_host.as_deref() == Some(host.as_str()) {
            return Err(Error::Other(format!("stub configured to fail on {host}")));
        }

        if self.panic_on_host.as_deref() == Some(host.as_str()) {
            panic!("stub configured to panic on {host}");
        }

        if self.block_on_host.as_deref() == Some(host.as_str()) {
            // Tell the test we have reached the blocking target, then await
            // forever; the orchestrator's cancellation race unwinds us.
            self.started.notify_one();
            return future::pending().await;
        }

        let mut findings = Vec::with_capacity(self.findings_per_target);
        for i in 0..self.findings_per_target {
            ctx.report_progress(
                ProgressUpdate::new(&self.id, i + 1, self.findings_per_target)
                    .current_item(format!("{}#{i}", target.full_url()))
                    .message("probing"),
            );
            findings.push(
                Finding::builder(&self.id, target.clone(), format!("finding {i} on {host}"))
                    .severity(Severity::Low)
                    .status(Status::Vulnerable)
                    .build(),
            );
        }
        Ok(findings)
    }
}

/// Build an orchestrator whose registry contains the given stub scanners.
fn orchestrator_with(stubs: Vec<StubScanner>) -> Orchestrator {
    let config = Arc::new(Config::default());
    let mut registry = ScannerRegistry::new(config.clone());
    for stub in stubs {
        let id = stub.id.clone();
        registry.register(
            id,
            Arc::new(move |_cfg| Box::new(stub.clone()) as Box<dyn BaseScanner>),
        );
    }
    Orchestrator::new(config, registry)
}

fn target(host: &str) -> Target {
    Target::parse(&format!("https://{host}")).unwrap()
}

/// Task 7.2: a normal run aggregates every stub finding and ends `Completed`.
#[tokio::test]
async fn normal_run_aggregates_findings_and_completes() {
    let orch = orchestrator_with(vec![StubScanner::simple("stub", 2)]);
    let targets = vec![target("a.test"), target("b.test"), target("c.test")];

    let session = orch
        .run_session(targets, vec!["stub".into()], None)
        .await
        .unwrap();

    assert_eq!(session.status, SessionStatus::Completed);
    assert_eq!(session.findings.len(), 6, "2 findings * 3 targets");
    assert_eq!(session.error_count, 0);
    assert_eq!(session.completed_units, 3);
    assert_eq!(session.total_units, 3);
    assert!(session.started_at.is_some());
    assert!(session.finished_at.is_some());
    // Every finding identifies its producing scanner.
    assert!(session.findings.iter().all(|f| f.scanner_id == "stub"));
}

/// Aggregation across *multiple* scanners and targets (lifecycle scenario).
#[tokio::test]
async fn aggregates_across_multiple_scanners() {
    let orch = orchestrator_with(vec![
        StubScanner::simple("alpha", 1),
        StubScanner::simple("beta", 2),
    ]);
    let targets = vec![target("a.test"), target("b.test")];

    let session = orch
        .run_session(targets, vec!["alpha".into(), "beta".into()], None)
        .await
        .unwrap();

    assert_eq!(session.status, SessionStatus::Completed);
    // alpha: 1*2 = 2, beta: 2*2 = 4 → 6 total.
    assert_eq!(session.findings.len(), 6);
    assert_eq!(session.total_units, 4); // 2 scanners * 2 targets
    assert_eq!(session.completed_units, 4);
}

/// Task 7.3: the orchestrator forwards progress carrying tested / total /
/// current during the run, before it reaches a terminal state.
#[tokio::test]
async fn forwards_progress_with_tested_total_and_current() {
    let orch = orchestrator_with(vec![StubScanner::simple("stub", 1)]);
    let targets = vec![target("a.test"), target("b.test")];

    let collected: Arc<Mutex<Vec<ProgressUpdate>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    let callback: ProgressCallback = Arc::new(move |u| sink.lock().unwrap().push(u));

    let session = orch
        .run_session(targets, vec!["stub".into()], Some(callback))
        .await
        .unwrap();
    assert_eq!(session.status, SessionStatus::Completed);

    let updates = collected.lock().unwrap();
    assert!(!updates.is_empty(), "progress must be forwarded");

    // A mid-run orchestrator unit update: 1 of 2 done, with the current item set.
    // That it reports 1/2 (not just 2/2) proves emission *during* the scan.
    assert!(
        updates
            .iter()
            .any(|u| u.items_completed == 1 && u.total_items == 2 && u.current_item.is_some()),
        "expected a mid-run update carrying tested/total/current: {updates:?}"
    );
    // And the final unit update reaching 2/2.
    assert!(updates
        .iter()
        .any(|u| u.items_completed == 2 && u.total_items == 2));
}

/// Task 3.2: components can subscribe to the orchestrator's progress stream.
#[tokio::test]
async fn subscribers_receive_progress_from_the_stream() {
    let orch = orchestrator_with(vec![StubScanner::simple("stub", 1)]);
    let mut rx = orch.subscribe();
    let targets = vec![target("a.test"), target("b.test")];

    orch.run_session(targets, vec!["stub".into()], None)
        .await
        .unwrap();

    let mut received = Vec::new();
    while let Ok(update) = rx.try_recv() {
        received.push(update);
    }
    assert!(!received.is_empty(), "subscriber should receive progress");
    assert!(received.iter().any(|u| u.total_items == 2));
}

/// Task 7.4: cancelling mid-scan stops promptly, ends `Cancelled`, and the
/// findings gathered before cancellation remain available.
#[tokio::test]
async fn cancel_mid_scan_is_prompt_and_keeps_partial_findings() {
    let started = Arc::new(Notify::new());
    let stub = StubScanner {
        id: "stub".into(),
        findings_per_target: 1,
        error_on_host: None,
        block_on_host: Some("block.test".into()),
        panic_on_host: None,
        started: started.clone(),
    };
    let orch = Arc::new(orchestrator_with(vec![stub]));

    // The first target completes (its finding is aggregated); the second blocks.
    let targets = vec![target("normal.test"), target("block.test")];
    let handle = orch.create_session(targets, vec!["stub".into()]).unwrap();
    let id = handle.lock().unwrap().id;

    let runner = orch.clone();
    let run = tokio::spawn(async move { runner.run(id, None).await });

    // Wait until the scanner reaches the blocking target, then cancel.
    started.notified().await;
    orch.cancel(id).unwrap();

    let session = run.await.unwrap().unwrap();

    assert_eq!(session.status, SessionStatus::Cancelled);
    assert_eq!(
        session.findings.len(),
        1,
        "the completed target's finding survives cancellation"
    );
    // The shared handle observes the same terminal state.
    assert_eq!(handle.lock().unwrap().status, SessionStatus::Cancelled);
}

/// A scanner that panics mid-run must not orphan the session: the run's unwind
/// safety net removes it from the active map (so a later `cancel()` no longer
/// finds a dead future) and leaves it in a terminal state (never stuck
/// `Running`). The panic itself still propagates out of `run`.
#[tokio::test]
async fn scanner_panic_does_not_orphan_session() {
    let stub = StubScanner {
        id: "stub".into(),
        findings_per_target: 1,
        error_on_host: None,
        block_on_host: None,
        panic_on_host: Some("boom.test".into()),
        started: Arc::new(Notify::new()),
    };
    let orch = Arc::new(orchestrator_with(vec![stub]));

    let handle = orch
        .create_session(vec![target("boom.test")], vec!["stub".into()])
        .unwrap();
    let id = handle.lock().unwrap().id;

    // The panic propagates out of `run`; capture it as a JoinError so the test
    // process survives and can inspect the aftermath.
    let runner = orch.clone();
    let result = tokio::spawn(async move { runner.run(id, None).await }).await;
    assert!(
        result.is_err(),
        "the scanner panic must propagate out of run"
    );

    // The session is no longer Running, and is no longer in the active map.
    assert!(
        handle.lock().unwrap().status.is_terminal(),
        "a panicking scanner must not leave the session stuck Running"
    );
    assert!(
        orch.cancel(id).is_err(),
        "the orphaned session must have been removed from the active map"
    );
}

/// Cancelling before the run even starts still ends `Cancelled`.
#[tokio::test]
async fn cancel_before_run_yields_cancelled() {
    let orch = orchestrator_with(vec![StubScanner::simple("stub", 1)]);
    let handle = orch
        .create_session(vec![target("a.test")], vec!["stub".into()])
        .unwrap();
    let id = handle.lock().unwrap().id;

    orch.cancel(id).unwrap();
    let session = orch.run(id, None).await.unwrap();
    assert_eq!(session.status, SessionStatus::Cancelled);
}

/// Task 7.5: a stub that errors on one target increments the error count without
/// aborting the session — the other targets still produce findings.
#[tokio::test]
async fn per_target_error_is_counted_without_aborting() {
    let stub = StubScanner {
        id: "stub".into(),
        findings_per_target: 1,
        error_on_host: Some("err.test".into()),
        block_on_host: None,
        panic_on_host: None,
        started: Arc::new(Notify::new()),
    };
    let orch = orchestrator_with(vec![stub]);
    let targets = vec![target("ok1.test"), target("err.test"), target("ok2.test")];

    let session = orch
        .run_session(targets, vec!["stub".into()], None)
        .await
        .unwrap();

    assert_eq!(
        session.status,
        SessionStatus::Completed,
        "one target's failure must not abort the session"
    );
    assert_eq!(session.error_count, 1);
    assert_eq!(
        session.findings.len(),
        2,
        "the two healthy targets produced findings"
    );
    assert_eq!(session.completed_units, 3, "every unit was attempted");
}

/// Task 7.6: selecting an unknown scanner id is rejected before any scan begins.
#[tokio::test]
async fn unknown_scanner_id_is_rejected_before_scanning() {
    let orch = orchestrator_with(vec![StubScanner::simple("stub", 1)]);
    let targets = vec![target("a.test")];

    // A selection mixing a known and an unknown id is rejected wholesale.
    match orch.create_session(targets.clone(), vec!["stub".into(), "ghost".into()]) {
        Err(Error::ScannerNotFound(id)) => assert_eq!(id, "ghost"),
        Err(other) => panic!("expected ScannerNotFound, got {other:?}"),
        Ok(_) => panic!("a request naming an unknown id must be rejected"),
    }

    // No session was registered, and run_session likewise rejects without scanning.
    let progressed: Arc<Mutex<Vec<ProgressUpdate>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = progressed.clone();
    let callback: ProgressCallback = Arc::new(move |u| sink.lock().unwrap().push(u));
    let result = orch
        .run_session(targets, vec!["ghost".into()], Some(callback))
        .await;
    assert!(matches!(result, Err(Error::ScannerNotFound(_))));
    assert!(
        progressed.lock().unwrap().is_empty(),
        "no progress (hence no scanning) may occur for a rejected selection"
    );
}
