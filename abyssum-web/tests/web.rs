//! Integration tests for the `abyssum-web` surface, all local-only (no real
//! targets): the auth gate, registration/login, ownership enforcement, the live
//! scan lifecycle over a WebSocket, owner-scoped search/filter, and the
//! custom-requests tool.

mod common;

use std::time::Duration;

use abyssum_core::{Finding, ScanSession, Severity, Status, Target, User};
use common::{Client, TestApp, enc, spawn_cors_mock, spawn_echo_mock};
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

// --- Embedded static assets ------------------------------------------------

/// The `/static/*` assets `view.rs` references must all be served (200) from the
/// binary's embedded copy — no source tree, no `ABYSSUM_WEB_STATIC`, no filesystem
/// dependency. Regression for the shipped-binary "no CSS/JS" bug.
#[tokio::test]
async fn embedded_static_assets_are_served() {
    let app = TestApp::spawn().await; // built with the embedded (no-override) path
    let mut client = app.client(); // static assets are public — no auth needed

    let css = client.get("/static/app.css").await;
    assert_eq!(css.status, 200);
    assert!(
        css.header("content-type")
            .is_some_and(|ct| ct.contains("text/css")),
        "app.css should be served as CSS, got {:?}",
        css.header("content-type")
    );
    assert!(!css.body.is_empty(), "app.css body must not be empty");
    assert!(
        css.header("cache-control")
            .is_some_and(|cc| cc.contains("max-age")),
        "embedded assets should carry a Cache-Control, got {:?}",
        css.header("cache-control")
    );

    for asset in ["app.js", "htmx.min.js", "alpine.min.js"] {
        let resp = client.get(&format!("/static/{asset}")).await;
        assert_eq!(resp.status, 200, "{asset} should be served");
        assert!(!resp.body.is_empty(), "{asset} body must not be empty");
    }

    // An unknown asset still 404s (the handler is not a wildcard file server).
    let missing = client.get("/static/nope.js").await;
    assert_eq!(missing.status, 404);
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

    // Full HTTP login sets the session cookie and lands on the dashboard (`/`).
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

    // `/` is now the dashboard; the start-scan page keeps its own `/scan` route.
    let resp = login.get("/").await;
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("Dashboard"));
    let resp = login.get("/scan").await;
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

// --- Annotations: notes, tags, search (owner-scoped) -----------------------

#[tokio::test]
async fn annotations_notes_tags_and_search_over_the_web_surface() {
    let app = TestApp::spawn().await;
    let _admin = make_user(&app, "admin").await; // first → admin
    let alice = make_user(&app, "alice").await;
    let _bob = make_user(&app, "bob").await;

    let f = finding(
        "cors",
        "https://alice.test",
        Severity::High,
        Status::Vulnerable,
        "Permissive CORS",
        "reflects origin",
    );
    let sid = seed_session(&app, alice.id, "https://alice.test", &[f]).await;
    let fid = app.state.db.get_findings(sid).await.unwrap()[0].id.unwrap();

    let mut alice_c = authed_client(&app, "alice").await;

    // Add a session-level note; the returned fragment shows it.
    let body = format!(
        "content={}&_csrf={}",
        enc("triage: exploitable"),
        enc(&alice_c.csrf())
    );
    let resp = alice_c
        .post_form(&format!("/scan/{sid}/notes"), &body)
        .await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("triage: exploitable"),
        "note shown: {}",
        resp.body
    );

    // Add a finding-level note.
    let body = format!(
        "content={}&_csrf={}",
        enc("write this one up"),
        enc(&alice_c.csrf())
    );
    let resp = alice_c
        .post_form(&format!("/scan/{sid}/findings/{fid}/notes"), &body)
        .await;
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("write this one up"));

    // Apply a tag (auto-created), then see it on the session's tag fragment.
    let body = format!(
        "tags={}&color={}&_csrf={}",
        enc("Auth-Bypass"),
        enc("#ff0000"),
        enc(&alice_c.csrf())
    );
    let resp = alice_c.post_form(&format!("/scan/{sid}/tags"), &body).await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("auth-bypass"),
        "chip shown normalized: {}",
        resp.body
    );

    // The all-tags list reports the usage.
    let resp = alice_c.get("/tags").await;
    assert!(resp.body.contains("auth-bypass") && resp.body.contains("1 session"));

    // Search by note text returns the session.
    let resp = alice_c.get("/search/notes?q=triage").await;
    assert!(
        resp.body.contains(&sid.to_string()[..8]),
        "note search finds the session"
    );

    // Filter by tag (any) returns the session.
    let resp = alice_c.get("/search/tags?tags=auth-bypass&mode=any").await;
    assert!(
        resp.body.contains(&sid.to_string()[..8]),
        "tag filter finds the session"
    );

    // A non-owner non-admin is denied the notes fragment and any mutation.
    let mut bob_c = authed_client(&app, "bob").await;
    assert_eq!(bob_c.get(&format!("/scan/{sid}/notes")).await.status, 404);
    let body = format!("content={}&_csrf={}", enc("intrude"), enc(&bob_c.csrf()));
    assert_eq!(
        bob_c
            .post_form(&format!("/scan/{sid}/notes"), &body)
            .await
            .status,
        404
    );

    // Bob's own note search does not surface alice's session.
    let resp = bob_c.get("/search/notes?q=triage").await;
    assert!(
        !resp.body.contains(&sid.to_string()[..8]),
        "search is owner-scoped"
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

// --- AI-assist analysis surface (d02) --------------------------------------

/// Spawn a local mock OpenAI-compatible endpoint that always answers
/// `/chat/completions` with a fixed assistant message. Returns the base URL.
async fn spawn_ai_mock(answer: &'static str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await;
                let body = serde_json::json!({
                    "choices": [{ "message": { "role": "assistant", "content": answer } }]
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    format!("http://{addr}")
}

/// The "Analyze with AI" finding surface: the analysis renders for the owner,
/// CSRF is enforced, a non-owner is refused, and an unknown finding shows a notice
/// in place — never a 500 or a crash.
#[tokio::test]
async fn ai_analysis_surface_renders_result_and_enforces_access() {
    let provider = spawn_ai_mock("AI says: genuine high-severity issue.").await;
    let app = TestApp::spawn_with(|cfg| cfg.ai.base_url = provider.clone()).await;

    // First registrant is the admin/owner; the second is an unrelated regular user.
    let owner = make_user(&app, "owner").await;
    make_user(&app, "bob").await;

    let f = finding(
        "cors",
        "https://api.example.com",
        Severity::High,
        Status::Vulnerable,
        "Permissive CORS",
        "reflects arbitrary origin",
    );
    let sid = seed_session(&app, owner.id, "https://api.example.com", &[f]).await;
    let fid = app.state.db.get_findings(sid).await.unwrap()[0].id.unwrap();
    let path = format!("/scan/{sid}/findings/{fid}/analyze");

    let mut client = authed_client(&app, "owner").await;

    // CSRF is required.
    let resp = client.post_form(&path, "_csrf=wrong").await;
    assert_eq!(resp.status, 403);

    // The owner gets the model's analysis rendered in place.
    let body = format!("_csrf={}", enc(&client.csrf()));
    let resp = client.post_form(&path, &body).await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("AI analysis"),
        "renders the analysis block"
    );
    assert!(
        resp.body.contains("genuine high-severity issue"),
        "renders the model's text"
    );

    // An unknown finding id under an accessible session shows a notice, not a 500.
    let missing = format!("/scan/{sid}/findings/999999/analyze");
    let resp = client.post_form(&missing, &body).await;
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("not found"));

    // A non-owner regular user may not analyze the owner's finding.
    let mut bob = authed_client(&app, "bob").await;
    let body = format!("_csrf={}", enc(&bob.csrf()));
    let resp = bob.post_form(&path, &body).await;
    assert_eq!(resp.status, 404);
    // Nothing about the analysis or finding leaks to the unauthorized user.
    assert!(!resp.body.contains("AI analysis"));
}

/// "Failure shows a notice in place": when the provider is unreachable, the surface
/// returns a 200 notice rather than aborting or surfacing a 500.
#[tokio::test]
async fn ai_analysis_failure_shows_notice_in_place() {
    // Point the provider at a closed port so the call deterministically fails.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap();
    drop(closed);
    let app = TestApp::spawn_with(|cfg| {
        cfg.ai.base_url = format!("http://{dead}");
        cfg.ai.timeout_seconds = 2;
    })
    .await;

    let owner = make_user(&app, "owner").await;
    let f = finding(
        "cors",
        "https://api.example.com",
        Severity::High,
        Status::Vulnerable,
        "Permissive CORS",
        "reflects arbitrary origin",
    );
    let sid = seed_session(&app, owner.id, "https://api.example.com", &[f]).await;
    let fid = app.state.db.get_findings(sid).await.unwrap()[0].id.unwrap();

    let mut client = authed_client(&app, "owner").await;
    let body = format!("_csrf={}", enc(&client.csrf()));
    let resp = client
        .post_form(&format!("/scan/{sid}/findings/{fid}/analyze"), &body)
        .await;

    // A provider failure is a non-fatal notice: 200 with an error fragment, no 500.
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("error"),
        "shows a notice in place: {}",
        resp.body
    );
    assert!(!resp.body.contains("AI analysis"));
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

// --- Security headers ------------------------------------------------------

#[tokio::test]
async fn security_headers_are_set_on_every_response() {
    let app = TestApp::spawn().await;
    // A public, unauthenticated response still carries the headers.
    let mut client = app.client();
    let resp = client.get("/login").await;

    let csp = resp.header("content-security-policy").unwrap_or("");
    assert!(csp.contains("default-src 'self'"), "CSP present: {csp}");
    // Alpine's evaluator and the inline style attributes must remain allowed.
    assert!(csp.contains("'unsafe-eval'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(resp.header("x-frame-options"), Some("DENY"));
    assert_eq!(resp.header("x-content-type-options"), Some("nosniff"));
    assert!(
        resp.header("strict-transport-security")
            .is_some_and(|v| v.contains("max-age="))
    );
}

// --- 10.x Custom wordlist import + per-user visibility (g07) ----------------

/// Importing a wordlist stores a normalized list, reports the outcome on the page,
/// and the list is offered on the scan form — all private to its owner, so another
/// user sees neither the list nor it in their scan-form selector.
#[tokio::test]
async fn wordlist_import_reports_and_is_private_to_its_owner() {
    let app = TestApp::spawn().await;
    let _admin = make_user(&app, "admin").await;
    let alice = make_user(&app, "alice").await;
    let _bob = make_user(&app, "bob").await;

    // Alice imports a list with a comment, a duplicate, and mixed case.
    let mut alice_c = authed_client(&app, "alice").await;
    let text = "API\napi\n# a comment\nwww";
    let body = format!(
        "name={}&text={}&_csrf={}",
        enc("alice-secret-list"),
        enc(text),
        enc(&alice_c.csrf()),
    );
    let resp = alice_c.post_form("/wordlists", &body).await;
    assert_eq!(resp.status, 200);
    // The import is reported (not silent): 2 kept (api, www), 2 dropped.
    assert!(
        resp.body.contains("Imported") && resp.body.contains("alice-secret-list"),
        "the import result was reported"
    );
    assert!(
        resp.body.contains("2 entries"),
        "the stored entry count is shown: {}",
        resp.body
    );
    // It was actually stored, owner-scoped.
    let stored = app.state.wordlists.list_for_user(alice.id).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].entry_count, 2);

    // Alice's scan form offers the list.
    let scan_page = alice_c.get("/scan").await;
    assert!(
        scan_page.body.contains("alice-secret-list"),
        "alice's scan form offers her list"
    );

    // Bob sees neither the list on his wordlists page nor in his scan selector.
    let mut bob_c = authed_client(&app, "bob").await;
    let bob_lists = bob_c.get("/wordlists").await;
    assert!(
        !bob_lists.body.contains("alice-secret-list"),
        "alice's list leaked onto bob's wordlists page"
    );
    let bob_scan = bob_c.get("/scan").await;
    assert!(
        !bob_scan.body.contains("alice-secret-list"),
        "alice's list leaked into bob's scan selector"
    );
}

// --- Engagements (h01) -----------------------------------------------------

/// base64-encode bytes the way the browser submits a file upload (a data field).
fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Create an engagement via the web form and return its id (parsed from the
/// redirect Location).
async fn create_engagement(client: &mut Client, name: &str) -> i64 {
    let body = format!("name={}&_csrf={}", enc(name), enc(&client.csrf()));
    let resp = client.post_form("/engagements", &body).await;
    assert_eq!(resp.status, 303, "engagement create redirects");
    resp.location()
        .unwrap()
        .strip_prefix("/engagements/")
        .unwrap()
        .parse()
        .unwrap()
}

/// Create → attach text/URL/PDF → serve the PDF safely → reject a disallowed
/// upload → assign an existing scan, all as one authorized operator.
#[tokio::test]
async fn engagement_create_attach_serve_and_assign() {
    let app = TestApp::spawn().await;
    let alice = make_user(&app, "alice").await; // first → admin, but acts as owner here

    let mut c = authed_client(&app, "alice").await;
    let eid = create_engagement(&mut c, "Acme Q3").await;

    // The detail page opens and shows the engagement name.
    let detail = c.get(&format!("/engagements/{eid}")).await;
    assert_eq!(detail.status, 200);
    assert!(detail.body.contains("Acme Q3"));

    // Attach pasted scope text — shown inline as text.
    let body = format!(
        "kind=text&content={}&_csrf={}",
        enc("In scope: *.acme.example"),
        enc(&c.csrf())
    );
    assert_eq!(
        c.post_form(&format!("/engagements/{eid}/documents"), &body)
            .await
            .status,
        303
    );

    // Attach a scope URL — shown as a link.
    let body = format!(
        "kind=url&url={}&_csrf={}",
        enc("https://acme.example/security"),
        enc(&c.csrf())
    );
    assert_eq!(
        c.post_form(&format!("/engagements/{eid}/documents"), &body)
            .await
            .status,
        303
    );

    // Upload a PDF authorization (bytes are ASCII so the raw client can compare them).
    let pdf = b"%PDF-1.7 signed authorization";
    let body = format!(
        "kind=file&file_name=auth.pdf&file_data={}&_csrf={}",
        enc(&b64(pdf)),
        enc(&c.csrf())
    );
    assert_eq!(
        c.post_form(&format!("/engagements/{eid}/documents"), &body)
            .await
            .status,
        303
    );

    // The detail page now renders the text inline, the URL as a link, and the PDF
    // inline via a same-origin <iframe> (the browser's native viewer, no external code).
    let detail = c.get(&format!("/engagements/{eid}")).await;
    assert!(
        detail.body.contains("In scope: *.acme.example"),
        "text shown inline"
    );
    assert!(
        detail.body.contains("https://acme.example/security"),
        "url shown"
    );
    assert!(
        detail.body.contains("<iframe")
            && detail
                .body
                .contains(&format!("/engagements/{eid}/documents/")),
        "PDF embedded inline via a same-origin iframe: {}",
        detail.body
    );
    assert!(
        !detail.body.contains("http://") || !detail.body.contains("://cdn"),
        "no external code is loaded to render the document"
    );

    // Find the served document's URL and fetch it: served with a fixed document
    // content type, sniffing off, a Content-Disposition, and NOT as text/html.
    // (Document ids autoincrement across the table, so resolve the file's id.)
    let file_id = app
        .state
        .engagements
        .documents(&alice, eid)
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.kind == abyssum_core::DocumentKind::File)
        .unwrap()
        .id;
    let doc_path = format!("/engagements/{eid}/documents/{file_id}");
    let served = c.get(&doc_path).await;
    assert_eq!(served.status, 200);
    let ct = served.header("content-type").unwrap_or("");
    assert!(
        ct.contains("application/pdf"),
        "fixed document content type: {ct}"
    );
    assert!(!ct.contains("text/html"), "never served as active HTML");
    assert_eq!(served.header("x-content-type-options"), Some("nosniff"));
    assert!(
        served
            .header("content-disposition")
            .is_some_and(|v| v.contains("inline")),
        "carries a Content-Disposition"
    );
    assert!(
        served
            .header("content-security-policy")
            .is_some_and(|v| v.contains("sandbox")),
        "sandboxed so it cannot execute in the app origin"
    );
    assert_eq!(served.header("x-frame-options"), Some("SAMEORIGIN"));
    assert!(
        served.body.contains("signed authorization"),
        "the stored bytes are served"
    );

    // A disallowed upload (a PNG — binary, not a PDF, not text) is rejected and
    // not stored: the page re-renders with an error and no new document endpoint.
    let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00rejectme";
    let body = format!(
        "kind=file&file_name=logo.png&file_data={}&_csrf={}",
        enc(&b64(png)),
        enc(&c.csrf())
    );
    let resp = c
        .post_form(&format!("/engagements/{eid}/documents"), &body)
        .await;
    assert_eq!(
        resp.status, 200,
        "a rejected upload re-renders the page, not a redirect"
    );
    assert!(
        resp.body.to_lowercase().contains("unsupported"),
        "rejection reported: {}",
        resp.body
    );
    // Only the three valid documents exist; the PNG endpoint 404s.
    let store = app.state.engagements.documents(&alice, eid).await.unwrap();
    assert_eq!(store.len(), 3, "the disallowed upload was not stored");

    // Assign an existing scan to the engagement; it then appears under it.
    let sid = seed_session(&app, alice.id, "https://scan.example", &[]).await;
    let body = format!("engagement={eid}&_csrf={}", enc(&c.csrf()));
    let resp = c.post_form(&format!("/scan/{sid}/assign"), &body).await;
    assert_eq!(resp.status, 303);
    let detail = c.get(&format!("/engagements/{eid}")).await;
    assert!(
        detail.body.contains(&sid.to_string()[..8]),
        "the assigned scan is listed under the engagement"
    );
}

/// Per-user visibility: a non-admin cannot list, open, or fetch documents of an
/// engagement they are not authorized for; an admin can.
#[tokio::test]
async fn engagement_visibility_is_owner_only_with_admin_override() {
    let app = TestApp::spawn().await;
    let _admin = make_user(&app, "admin").await; // first → admin
    let alice = make_user(&app, "alice").await;
    let _bob = make_user(&app, "bob").await;

    let mut alice_c = authed_client(&app, "alice").await;
    let eid = create_engagement(&mut alice_c, "alice-private-engagement").await;
    let pdf = b"%PDF-1.4 alice secret";
    let body = format!(
        "kind=file&file_name=auth.pdf&file_data={}&_csrf={}",
        enc(&b64(pdf)),
        enc(&alice_c.csrf())
    );
    alice_c
        .post_form(&format!("/engagements/{eid}/documents"), &body)
        .await;
    let doc_path = format!("/engagements/{eid}/documents/1");

    // Bob sees nothing of it: not in his list, and detail/document both 404.
    let mut bob_c = authed_client(&app, "bob").await;
    let list = bob_c.get("/engagements").await;
    assert!(
        !list.body.contains("alice-private-engagement"),
        "not in bob's list"
    );
    assert_eq!(bob_c.get(&format!("/engagements/{eid}")).await.status, 404);
    assert_eq!(bob_c.get(&doc_path).await.status, 404);
    // Bob cannot attach to it either.
    let body = format!("kind=text&content=intrude&_csrf={}", enc(&bob_c.csrf()));
    assert_eq!(
        bob_c
            .post_form(&format!("/engagements/{eid}/documents"), &body)
            .await
            .status,
        404
    );

    // Admin can list, open, and fetch the document.
    let mut admin_c = authed_client(&app, "admin").await;
    assert!(
        admin_c
            .get("/engagements")
            .await
            .body
            .contains("alice-private-engagement")
    );
    assert_eq!(
        admin_c.get(&format!("/engagements/{eid}")).await.status,
        200
    );
    let served = admin_c.get(&doc_path).await;
    assert_eq!(served.status, 200);
    assert!(served.body.contains("alice secret"));

    // Bob's own list stays empty even though alice has one.
    assert!(
        app.state
            .engagements
            .list_for_user(&alice)
            .await
            .unwrap()
            .len()
            == 1
    );
}

/// The engagement rollup counts and findings cover exactly the engagement's
/// sessions — a session in another engagement and an unassociated one are excluded.
#[tokio::test]
async fn engagement_rollup_scopes_to_the_engagements_sessions() {
    let app = TestApp::spawn().await;
    let alice = make_user(&app, "alice").await; // first → admin, sole operator here
    let mut c = authed_client(&app, "alice").await;

    let eid = create_engagement(&mut c, "In scope").await;
    let other = create_engagement(&mut c, "Other engagement").await;

    // One session in the engagement (counts), one in another engagement, and one
    // unassociated (neither counts). Distinct titles isolate the rollup findings.
    let in_scope = seed_session(
        &app,
        alice.id,
        "https://in.example",
        &[finding(
            "cors",
            "https://in.example",
            Severity::High,
            Status::Vulnerable,
            "InScopeFinding",
            "d",
        )],
    )
    .await;
    let other_sid = seed_session(
        &app,
        alice.id,
        "https://other.example",
        &[finding(
            "cors",
            "https://other.example",
            Severity::Critical,
            Status::Vulnerable,
            "OtherEngagementFinding",
            "d",
        )],
    )
    .await;
    seed_session(
        &app,
        alice.id,
        "https://free.example",
        &[finding(
            "cors",
            "https://free.example",
            Severity::Low,
            Status::Vulnerable,
            "UnassociatedFinding",
            "d",
        )],
    )
    .await;

    app.state
        .engagements
        .assign_session(&alice, Some(eid), in_scope)
        .await
        .unwrap();
    app.state
        .engagements
        .assign_session(&alice, Some(other), other_sid)
        .await
        .unwrap();

    let detail = c.get(&format!("/engagements/{eid}")).await;
    assert_eq!(detail.status, 200);
    assert!(
        detail.body.contains("InScopeFinding"),
        "the engagement's own finding is in the rollup"
    );
    assert!(
        !detail.body.contains("OtherEngagementFinding"),
        "another engagement's finding is excluded"
    );
    assert!(
        !detail.body.contains("UnassociatedFinding"),
        "an unassociated session's finding is excluded"
    );
    // The severity breakdown counts exactly the one in-scope session and finding.
    assert!(
        detail.body.contains("<strong>1</strong><br>sessions"),
        "rollup counts one session"
    );
    assert!(
        detail.body.contains("<strong>1</strong><br>findings"),
        "rollup counts one finding"
    );
}

/// The rollup follows per-user session visibility: a non-admin's rollup omits an
/// engagement-associated session owned by another operator, while an admin viewing
/// the same engagement sees all of its sessions.
#[tokio::test]
async fn engagement_rollup_respects_per_user_session_visibility() {
    let app = TestApp::spawn().await;
    let admin = make_user(&app, "admin").await; // first → admin
    let alice = make_user(&app, "alice").await;
    let bob = make_user(&app, "bob").await;

    let mut alice_c = authed_client(&app, "alice").await;
    let eid = create_engagement(&mut alice_c, "shared engagement").await;

    // Alice's own session in her engagement.
    let alice_sid = seed_session(
        &app,
        alice.id,
        "https://alice.example",
        &[finding(
            "cors",
            "https://alice.example",
            Severity::Medium,
            Status::Vulnerable,
            "AliceFinding",
            "d",
        )],
    )
    .await;
    app.state
        .engagements
        .assign_session(&alice, Some(eid), alice_sid)
        .await
        .unwrap();

    // An admin associates a session Bob owns with Alice's engagement.
    let bob_sid = seed_session(
        &app,
        bob.id,
        "https://bob.example",
        &[finding(
            "cors",
            "https://bob.example",
            Severity::Critical,
            Status::Vulnerable,
            "BobFinding",
            "d",
        )],
    )
    .await;
    app.state
        .engagements
        .assign_session(&admin, Some(eid), bob_sid)
        .await
        .unwrap();

    // Alice (non-admin) sees only her own finding in the rollup, never Bob's, and
    // her rollup counts one session — not the two the engagement holds.
    let detail = alice_c.get(&format!("/engagements/{eid}")).await;
    assert_eq!(detail.status, 200);
    assert!(
        detail.body.contains("AliceFinding"),
        "alice's finding is in her rollup"
    );
    assert!(
        !detail.body.contains("BobFinding"),
        "bob's finding is not disclosed to alice via the rollup"
    );
    assert!(
        detail.body.contains("<strong>1</strong><br>sessions"),
        "alice's rollup counts only her session"
    );

    // The admin, viewing the same engagement, sees both sessions in the rollup.
    let mut admin_c = authed_client(&app, "admin").await;
    let detail = admin_c.get(&format!("/engagements/{eid}")).await;
    assert_eq!(detail.status, 200);
    assert!(
        detail.body.contains("AliceFinding") && detail.body.contains("BobFinding"),
        "admin's rollup includes every associated session's findings"
    );
    assert!(
        detail.body.contains("<strong>2</strong><br>sessions"),
        "admin's rollup counts both sessions"
    );
}

/// The start-scan form offers an engagement selector, and choosing one associates
/// the created scan with it — while the scan still runs unchanged.
#[tokio::test]
async fn start_scan_can_select_an_engagement() {
    let app = TestApp::spawn().await;
    make_user(&app, "operator").await;
    let mut c = authed_client(&app, "operator").await;
    let eid = create_engagement(&mut c, "Live engagement").await;

    // The scan form now offers the engagement.
    let form = c.get("/scan").await;
    assert!(
        form.body.contains("Live engagement"),
        "scan form offers the engagement"
    );
    assert!(
        form.body.contains("name=\"engagement\""),
        "scan form has the engagement selector"
    );

    // Start a scan choosing that engagement.
    let mock = spawn_cors_mock(Duration::from_millis(0)).await;
    let target = format!("http://{mock}/");
    let body = format!(
        "targets={}&scanners=cors&engagement={eid}&_csrf={}",
        enc(&target),
        enc(&c.csrf())
    );
    let resp = c.post_form("/scans", &body).await;
    assert_eq!(resp.status, 303);
    let sid = resp.location().unwrap().strip_prefix("/scan/").unwrap();

    // The scan is associated with the engagement (visible on its detail page).
    let detail = c.get(&format!("/engagements/{eid}")).await;
    assert!(
        detail.body.contains(&sid[..8]),
        "the started scan is associated with the chosen engagement"
    );
}

/// An oversized upload is rejected and not stored (size bound enforced).
#[tokio::test]
async fn oversized_document_upload_is_rejected() {
    // A tiny per-document cap so a small payload trips the bound.
    let app = TestApp::spawn_with(|cfg| cfg.server.max_document_bytes = 16).await;
    let alice = make_user(&app, "alice").await;
    let mut c = authed_client(&app, "alice").await;
    let eid = create_engagement(&mut c, "Bounds").await;

    // 40 bytes of PDF > the 16-byte cap.
    let pdf = b"%PDF-1.7 this document is over the size cap";
    let body = format!(
        "kind=file&file_name=big.pdf&file_data={}&_csrf={}",
        enc(&b64(pdf)),
        enc(&c.csrf())
    );
    let resp = c
        .post_form(&format!("/engagements/{eid}/documents"), &body)
        .await;
    assert_eq!(
        resp.status, 200,
        "re-renders with an error rather than storing"
    );
    assert!(
        resp.body.to_lowercase().contains("too large"),
        "size rejection reported: {}",
        resp.body
    );
    assert!(
        app.state
            .engagements
            .documents(&alice, eid)
            .await
            .unwrap()
            .is_empty(),
        "the oversized upload was not stored"
    );
}

/// A document upload whose *encoded request body* exceeds axum's 2 MiB default
/// still reaches the handler (and the store's friendly size error), rather than
/// being cut off with a bare 413. Guards the `DefaultBodyLimit` layer sized from
/// `max_document_bytes`: without it a >2 MiB body is 413'd before the handler runs,
/// so the configured cap (default 10 MiB) is unreachable for real uploads.
#[tokio::test]
async fn large_document_body_reaches_handler_not_a_bare_413() {
    // A 3 MiB document cap ⇒ the route admits bodies up to ~6 MiB, well over axum's
    // 2 MiB default. The upload below is over the cap, so the store rejects it.
    let app = TestApp::spawn_with(|cfg| cfg.server.max_document_bytes = 3 * 1024 * 1024).await;
    let alice = make_user(&app, "alice").await;
    let mut c = authed_client(&app, "alice").await;
    let eid = create_engagement(&mut c, "Large upload").await;

    // A 3.5 MiB "PDF" (> the 3 MiB cap) → base64+urlencoded body ≈ 5 MiB: safely over
    // axum's 2 MiB default yet under this route's ~6 MiB limit.
    let mut pdf = b"%PDF-1.7\n".to_vec();
    pdf.resize(3 * 1024 * 1024 + 512 * 1024, b'A');
    let body = format!(
        "kind=file&file_name=big.pdf&file_data={}&_csrf={}",
        enc(&b64(&pdf)),
        enc(&c.csrf())
    );
    assert!(
        body.len() > 2 * 1024 * 1024,
        "the request body must exceed axum's 2 MiB default to exercise the fix"
    );
    let resp = c
        .post_form(&format!("/engagements/{eid}/documents"), &body)
        .await;

    // Not a bare 413 from axum: the body reached the handler, and the store reported
    // the over-cap document with a friendly message on a re-rendered page.
    assert_ne!(
        resp.status, 413,
        "the >2 MiB body must not be cut off by axum's default body limit"
    );
    assert_eq!(resp.status, 200, "re-renders with a friendly error");
    assert!(
        resp.body.to_lowercase().contains("too large"),
        "friendly size rejection from the store, not a raw 413"
    );
    assert!(
        app.state
            .engagements
            .documents(&alice, eid)
            .await
            .unwrap()
            .is_empty(),
        "the over-cap upload was not stored"
    );
}

/// A file whose bytes are HTML/script is stored and served as inert text/plain,
/// never as active HTML — so it cannot execute in the app's origin (stored-XSS
/// guard). The served type is decided from the bytes, not the upload's claim.
#[tokio::test]
async fn uploaded_html_is_served_as_inert_text_not_active_content() {
    let app = TestApp::spawn().await;
    let alice = make_user(&app, "alice").await;
    let mut c = authed_client(&app, "alice").await;
    let eid = create_engagement(&mut c, "XSS check").await;

    // A file whose bytes could be interpreted as HTML/script by a sniffing browser.
    let html = b"<html><script>alert(document.domain)</script></html>";
    let body = format!(
        "kind=file&file_name=evil.html&file_data={}&_csrf={}",
        enc(&b64(html)),
        enc(&c.csrf())
    );
    assert_eq!(
        c.post_form(&format!("/engagements/{eid}/documents"), &body)
            .await
            .status,
        303,
        "HTML bytes are valid text, so the upload is accepted (as text)"
    );

    let file_id = app.state.engagements.documents(&alice, eid).await.unwrap()[0].id;
    let served = c
        .get(&format!("/engagements/{eid}/documents/{file_id}"))
        .await;
    assert_eq!(served.status, 200);
    let ct = served.header("content-type").unwrap_or("");
    assert!(ct.contains("text/plain"), "served as plain text, got {ct}");
    assert!(
        !ct.contains("text/html"),
        "must never be served as active HTML content"
    );
    assert_eq!(served.header("x-content-type-options"), Some("nosniff"));
    // The bytes are returned verbatim as data, not executed.
    assert!(
        served
            .body
            .contains("<script>alert(document.domain)</script>")
    );
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
    if condition() { Ok(()) } else { Err(()) }
}

/// Poll the persisted session until it reaches a terminal state with findings.
async fn wait_for_session(app: &TestApp, id: Uuid, timeout: Duration) -> ScanSession {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(Some(session)) = app.state.db.get_session(id).await
            && session.status.is_terminal()
            && !session.findings.is_empty()
        {
            return session;
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
