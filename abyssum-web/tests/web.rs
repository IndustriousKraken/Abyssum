//! Integration tests for the `abyssum-web` surface, all local-only (no real
//! targets): the auth gate, registration/login, ownership enforcement, the live
//! scan lifecycle over a WebSocket, owner-scoped search/filter, and the
//! custom-requests tool.

mod common;

use std::time::Duration;

use abyssum_core::{Finding, ScanSession, Severity, Status, Target, User};
use common::{enc, spawn_cors_mock, spawn_echo_mock, Client, TestApp};
use uuid::Uuid;

/// Register an account (first registrant becomes admin) and return it.
async fn make_user(app: &TestApp, name: &str) -> User {
    app.state.auth.register(name, "password").await.unwrap()
}

/// A logged-in client for `name`, primed with a CSRF cookie (via `GET /`).
async fn authed_client(app: &TestApp, name: &str) -> Client {
    let token = app.state.auth.login(name, "password").await.unwrap();
    let mut client = app.client();
    client.set_session(&token);
    client.get("/").await; // mints the csrf cookie used by POST forms
    client
}

/// Persist a session owned by `owner` with the given findings (no scan run).
async fn seed_session(app: &TestApp, owner: i64, target: &str, findings: &[Finding]) -> Uuid {
    let session = ScanSession::new(vec![Target::parse(target).unwrap()], vec!["cors".into()])
        .with_owner(owner);
    let id = session.id;
    app.state.db.save_session(&session).await.unwrap();
    for finding in findings {
        app.state.db.save_finding(id, finding).await.unwrap();
    }
    id
}

fn finding(
    scanner: &str,
    target: &str,
    sev: Severity,
    status: Status,
    title: &str,
    desc: &str,
) -> Finding {
    Finding::builder(scanner, Target::parse(target).unwrap(), title)
        .severity(sev)
        .status(status)
        .description(desc)
        .build()
}

// --- 10.1 Auth gate --------------------------------------------------------

#[tokio::test]
async fn auth_gate_redirects_pages_rejects_data_and_admits_authenticated() {
    let app = TestApp::spawn().await;

    // Unauthenticated page request → redirect to login, no scan data disclosed.
    let mut anon = app.client();
    let resp = anon.get("/dashboard").await;
    assert_eq!(resp.status, 303);
    assert_eq!(resp.location(), Some("/login"));

    // Unauthenticated data endpoint → rejected as unauthorized.
    let resp = anon.get("/sessions").await;
    assert_eq!(resp.status, 401);

    // Authenticated request → served.
    make_user(&app, "admin").await;
    let mut client = authed_client(&app, "admin").await;
    let resp = client.get("/dashboard").await;
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("Dashboard"));
}

// --- Registration + login flow (web-ui register/login scenarios) -----------

#[tokio::test]
async fn registration_first_user_then_duplicate_then_login() {
    let app = TestApp::spawn().await;
    let mut client = app.client();

    // GET /register mints a csrf cookie.
    client.get("/register").await;
    let csrf = client.csrf();
    assert!(!csrf.is_empty(), "registration page must set a csrf cookie");

    // First operator registers → directed to log in.
    let body = format!("username=admin&password=pw&_csrf={}", enc(&csrf));
    let resp = client.post_form("/register", &body).await;
    assert_eq!(resp.status, 303);
    assert_eq!(resp.location(), Some("/login"));

    // Duplicate username is rejected and no second account is created.
    let body = format!("username=admin&password=other&_csrf={}", enc(&csrf));
    let resp = client.post_form("/register", &body).await;
    assert_eq!(resp.status, 409);
    assert!(resp.body.to_lowercase().contains("taken") || resp.body.contains("error"));

    // Full HTTP login sets the session cookie and serves the home page.
    let mut login = app.client();
    login.get("/login").await;
    let csrf = login.csrf();
    let body = format!("username=admin&password=pw&_csrf={}", enc(&csrf));
    let resp = login.post_form("/login", &body).await;
    assert_eq!(resp.status, 303);
    assert_eq!(resp.location(), Some("/"));
    assert!(
        login.cookies.contains_key("abyssum_session"),
        "login set a session cookie"
    );

    let resp = login.get("/").await;
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("Start a scan"));

    // Wrong password is rejected with the non-revealing error.
    let mut bad = app.client();
    bad.get("/login").await;
    let csrf = bad.csrf();
    let body = format!("username=admin&password=nope&_csrf={}", enc(&csrf));
    let resp = bad.post_form("/login", &body).await;
    assert_eq!(resp.status, 401);
    assert!(resp.body.contains("invalid username or password"));
}

#[tokio::test]
async fn csrf_is_required_on_state_changing_posts() {
    let app = TestApp::spawn().await;
    let mut client = app.client();
    client.get("/login").await; // establishes a csrf cookie

    // Missing token → rejected.
    let resp = client.post_form("/login", "username=x&password=y").await;
    assert_eq!(resp.status, 403);

    // Mismatched token → rejected.
    let resp = client
        .post_form("/login", "username=x&password=y&_csrf=wrong")
        .await;
    assert_eq!(resp.status, 403);
}

// --- 10.2 Ownership --------------------------------------------------------

#[tokio::test]
async fn ownership_is_enforced_for_non_admins_and_bypassed_for_admins() {
    let app = TestApp::spawn().await;
    let _admin = make_user(&app, "admin").await; // first → admin
    let alice = make_user(&app, "alice").await; // regular
    let _bob = make_user(&app, "bob").await; // regular

    let f = finding(
        "cors",
        "https://alice.test",
        Severity::High,
        Status::Vulnerable,
        "Alice finding",
        "owned by alice",
    );
    let session = seed_session(&app, alice.id, "https://alice.test", &[f]).await;

    // Bob (non-admin) cannot see, view, or cancel alice's session.
    let mut bob = authed_client(&app, "bob").await;
    let resp = bob.get("/sessions").await;
    assert!(
        !resp.body.contains(&session.to_string()[..8]),
        "bob's session list must not include alice's session"
    );
    assert_eq!(bob.get(&format!("/scan/{session}")).await.status, 404);
    assert_eq!(
        bob.get(&format!("/scan/{session}/results")).await.status,
        404
    );

    let body = format!("_csrf={}", enc(&bob.csrf()));
    let resp = bob
        .post_form(&format!("/scan/{session}/cancel"), &body)
        .await;
    assert_eq!(resp.status, 404, "non-owner cancel is denied");

    // Admin can see and view any session.
    let mut admin = authed_client(&app, "admin").await;
    let resp = admin.get("/sessions").await;
    assert!(
        resp.body.contains(&session.to_string()[..8]),
        "admin sees all sessions"
    );
    assert_eq!(admin.get(&format!("/scan/{session}")).await.status, 200);
}

// --- 10.3 Scan lifecycle over the WebSocket --------------------------------

#[tokio::test]
async fn scan_lifecycle_start_progress_cancel_and_persisted_partials() {
    // Slow pacing + a slow mock so the scan is still running when we cancel.
    let app = TestApp::spawn_with(|cfg| {
        cfg.scanning.min_delay = 0.02;
        cfg.scanning.max_delay = 0.02;
    })
    .await;
    let mock = spawn_cors_mock(Duration::from_millis(30)).await;
    make_user(&app, "operator").await;
    let mut client = authed_client(&app, "operator").await;

    // Start a scan over many copies of the mock target so it runs long enough.
    let target = format!("http://{mock}/");
    let targets = std::iter::repeat_n(target.as_str(), 25)
        .collect::<Vec<_>>()
        .join("\n");
    let body = format!(
        "targets={}&scanners=cors&_csrf={}",
        enc(&targets),
        enc(&client.csrf())
    );
    let resp = client.post_form("/scans", &body).await;
    assert_eq!(resp.status, 303);
    let location = resp.location().unwrap().to_string();
    let id: Uuid = location.strip_prefix("/scan/").unwrap().parse().unwrap();

    // Live progress arrives over the WebSocket.
    let mut ws = client.connect_ws(&format!("/ws/{id}")).await;
    let fragment = ws
        .recv_text(Duration::from_secs(5))
        .await
        .expect("a progress fragment over the websocket");
    assert!(
        fragment.contains("Findings so far") && fragment.contains("Status:"),
        "progress fragment conveys scanner/units/findings: {fragment}"
    );

    // Wait until at least one unit has completed (so a partial finding exists).
    wait_for(Duration::from_secs(5), || {
        app.state
            .hub
            .snapshot(id)
            .map(|s| !s.findings.is_empty())
            .unwrap_or(false)
    })
    .await
    .expect("a finding accrued before cancellation");

    // Cancel; the status fragment reflects the cancelled state.
    let body = format!("_csrf={}", enc(&client.csrf()));
    let resp = client.post_form(&format!("/scan/{id}/cancel"), &body).await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("cancelled"),
        "cancel returns a cancelled fragment: {}",
        resp.body
    );

    // The scan stops promptly and the partial findings are persisted + viewable.
    let session = wait_for_session(&app, id, Duration::from_secs(5)).await;
    assert_eq!(session.status, abyssum_core::SessionStatus::Cancelled);
    assert!(
        !session.findings.is_empty(),
        "partial findings discovered before cancellation are retained"
    );

    let resp = client.get(&format!("/scan/{id}")).await;
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("cancelled"));
    let resp = client.get(&format!("/scan/{id}/results")).await;
    assert!(
        resp.body.contains("cors"),
        "results show the retained findings"
    );
}

// --- 10.4 Search / filter, owner-scoped ------------------------------------

#[tokio::test]
async fn search_and_filter_are_scoped_to_the_requesting_user() {
    let app = TestApp::spawn().await;
    let _admin = make_user(&app, "admin").await;
    let alice = make_user(&app, "alice").await;
    let bob = make_user(&app, "bob").await;

    seed_session(
        &app,
        alice.id,
        "https://shop.test",
        &[
            finding(
                "cors",
                "https://shop.test",
                Severity::High,
                Status::Vulnerable,
                "Permissive CORS on shop",
                "reflects arbitrary origin",
            ),
            finding(
                "bac",
                "https://shop.test",
                Severity::Low,
                Status::Safe,
                "Admin path checked",
                "nothing reachable",
            ),
        ],
    )
    .await;
    seed_session(
        &app,
        bob.id,
        "https://bank.test",
        &[finding(
            "idor",
            "https://bank.test",
            Severity::Critical,
            Status::Vulnerable,
            "Bank IDOR leak",
            "uniquebobterm enumerable",
        )],
    )
    .await;

    let mut alice_c = authed_client(&app, "alice").await;

    // Unfiltered: alice sees only her own findings.
    let all = alice_c.get("/findings").await;
    assert!(all.body.contains("Permissive CORS on shop"));
    assert!(all.body.contains("Admin path checked"));
    assert!(!all.body.contains("Bank IDOR leak"), "scoped to alice");

    // Free text over title.
    let r = alice_c.get("/findings?q=Permissive").await;
    assert!(r.body.contains("Permissive CORS on shop"));
    assert!(!r.body.contains("Admin path checked"));

    // Free text over description.
    let r = alice_c.get("/findings?q=reflects").await;
    assert!(r.body.contains("Permissive CORS on shop"));

    // Free text that only matches bob's finding returns nothing for alice.
    let r = alice_c.get("/findings?q=uniquebobterm").await;
    assert!(!r.body.contains("Bank IDOR leak"));

    // Scanner-id filter.
    let r = alice_c.get("/findings?scanner=cors").await;
    assert!(r.body.contains("Permissive CORS on shop"));
    assert!(!r.body.contains("Admin path checked"));

    // Vulnerability-level filter.
    let r = alice_c.get("/findings?level=high").await;
    assert!(r.body.contains("Permissive CORS on shop"));
    assert!(!r.body.contains("Admin path checked"));

    // Status filter.
    let r = alice_c.get("/findings?status=vulnerable").await;
    assert!(r.body.contains("Permissive CORS on shop"));
    assert!(!r.body.contains("Admin path checked"));

    // Target filter (persisted full URL carries the trailing slash).
    let r = alice_c
        .get(&format!("/findings?target={}", enc("https://shop.test/")))
        .await;
    assert!(r.body.contains("Permissive CORS on shop"));
    assert!(r.body.contains("Admin path checked"));

    // Admin search spans all users.
    let mut admin_c = authed_client(&app, "admin").await;
    let r = admin_c.get("/findings?q=uniquebobterm").await;
    assert!(
        r.body.contains("Bank IDOR leak"),
        "admin sees everyone's findings"
    );
}

// --- 10.5 Custom requests --------------------------------------------------

#[tokio::test]
async fn custom_requests_keyless_and_authenticated() {
    let app = TestApp::spawn().await;
    let mock = spawn_echo_mock().await;
    make_user(&app, "operator").await;

    // Authentication is required for the execution endpoint.
    let mut anon = app.client();
    let resp = anon
        .post_form("/custom-requests", "url=http://x.test&_csrf=irrelevant")
        .await;
    assert_eq!(resp.status, 401);

    let mut client = authed_client(&app, "operator").await;
    let resp = client.get("/custom-requests").await;
    assert_eq!(resp.status, 200);

    // A keyless request (no bearer, no cookies) is issued and its response shown.
    let body = format!(
        "url={}&method=GET&_csrf={}",
        enc(&format!("http://{mock}/")),
        enc(&client.csrf())
    );
    let resp = client.post_form("/custom-requests", &body).await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("abyssum-custom-ok"),
        "renders the response body"
    );
    assert!(resp.body.contains("200"), "renders the status");

    // A request carrying a bearer token also succeeds.
    let body = format!(
        "url={}&method=GET&bearer=sometoken&_csrf={}",
        enc(&format!("http://{mock}/")),
        enc(&client.csrf())
    );
    let resp = client.post_form("/custom-requests", &body).await;
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("abyssum-custom-ok"));
}

// --- SSRF guard ------------------------------------------------------------

#[tokio::test]
async fn custom_request_blocks_private_targets_by_default() {
    // Flip the harness's local-only allowance back off to exercise the guard.
    let app = TestApp::spawn_with(|cfg| cfg.server.allow_private_custom_targets = false).await;
    make_user(&app, "operator").await;
    let mut client = authed_client(&app, "operator").await;

    // A loopback IP literal is refused before any request is issued.
    let body = format!(
        "url={}&method=GET&_csrf={}",
        enc("http://127.0.0.1:9/"),
        enc(&client.csrf())
    );
    let resp = client.post_form("/custom-requests", &body).await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.to_lowercase().contains("private or reserved"),
        "a private target is blocked: {}",
        resp.body
    );

    // The `localhost` name is refused too.
    let body = format!(
        "url={}&method=GET&_csrf={}",
        enc("http://localhost:9/"),
        enc(&client.csrf())
    );
    let resp = client.post_form("/custom-requests", &body).await;
    assert!(resp.body.to_lowercase().contains("private or reserved"));
}

// --- Brute-force throttle --------------------------------------------------

#[tokio::test]
async fn login_is_rate_limited_per_source_ip() {
    let app = TestApp::spawn().await;
    let mut client = app.client();
    client.get("/login").await; // establishes a csrf cookie

    // Ten attempts (all failing auth → 401) are allowed; the eleventh is throttled.
    let body = format!(
        "username=nobody&password=wrong&_csrf={}",
        enc(&client.csrf())
    );
    for _ in 0..10 {
        let resp = client.post_form("/login", &body).await;
        assert_ne!(resp.status, 429, "the first ten attempts are not throttled");
    }
    let resp = client.post_form("/login", &body).await;
    assert_eq!(resp.status, 429, "the eleventh attempt is rate-limited");
}

// --- polling helpers -------------------------------------------------------

/// Poll `condition` until true or the timeout elapses.
async fn wait_for(timeout: Duration, mut condition: impl FnMut() -> bool) -> Result<(), ()> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if condition() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if condition() {
        Ok(())
    } else {
        Err(())
    }
}

/// Poll the persisted session until it reaches a terminal state with findings.
async fn wait_for_session(app: &TestApp, id: Uuid, timeout: Duration) -> ScanSession {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(Some(session)) = app.state.db.get_session(id).await {
            if session.status.is_terminal() && !session.findings.is_empty() {
                return session;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return app
                .state
                .db
                .get_session(id)
                .await
                .unwrap()
                .expect("session persisted");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
