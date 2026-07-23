//! Server-rendered HTML: full pages and the HTMX-swappable fragments.
//!
//! The web surface is server-rendered HTML over HTMX + Alpine (no SPA, no JS
//! build step). Handlers return either a full [`page`] or a bare fragment that
//! HTMX swaps into the DOM. Rendering is plain `format!` over the core types —
//! `askama`/`tera` would be a build-step dependency this surface does not need.
//! Every value that originates from a user or a target is run through [`esc`]
//! before it lands in markup.

use abyssum_core::custom_request::RequestOutcome;
use abyssum_core::{
    CustomWordlist, DocumentKind, Engagement, EngagementDocument, Finding, Note, PacingPolicy,
    ScanSession, SessionStatus, Severity, Summary, Tag, TagUsage, TimingProfile, User,
};
use uuid::Uuid;

/// HTML-escape text destined for element content or a double-quoted attribute.
pub fn esc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Wrap a page body in the shared HTML shell (nav, styles, scripts).
pub fn page(title: &str, user: Option<&User>, body: &str) -> String {
    let nav = match user {
        Some(user) => format!(
            "<nav><span class=\"brand\">Abyssum</span>\
             <a href=\"/scan\">Scan</a><a href=\"/dashboard\">Dashboard</a>\
             <a href=\"/custom-requests\">Custom request</a>\
             <a href=\"/engagements\">Engagements</a>\
             <a href=\"/timing-profiles\">Timing</a>\
             <a href=\"/wordlists\">Wordlists</a>\
             <span class=\"muted\">{name}{admin}</span>\
             <form method=\"post\" action=\"/logout\" style=\"display:inline\">\
             {csrf}<button type=\"submit\">Log out</button></form></nav>",
            name = esc(&user.username),
            admin = if user.is_admin() { " (admin)" } else { "" },
            csrf = csrf_field_for(user),
        ),
        None => String::new(),
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title} — Abyssum</title>\
         <link rel=\"stylesheet\" href=\"/static/app.css\">\
         <!-- htmx/alpine are vendored in abyssum-web/static and embedded into the binary (see assets.rs). -->\
         <script src=\"/static/htmx.min.js\" defer></script>\
         <script src=\"/static/alpine.min.js\" defer></script>\
         </head><body><header>{nav}</header><main>{body}</main>\
         <script src=\"/static/app.js\" defer></script></body></html>",
        title = esc(title),
    )
}

/// The hidden CSRF input embedded in every state-changing form. The token is a
/// double-submit value also carried in the `csrf` cookie; see `auth::csrf`.
pub fn csrf_field(token: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"_csrf\" value=\"{}\">",
        esc(token)
    )
}

/// The logout form lives in the shared nav, which does not thread the live CSRF
/// token; Alpine reads it from the `csrf` cookie at submit time. Rendered as a
/// no-op placeholder the client fills in (`x-bind`), keeping the token out of
/// cached page markup. Falls back to an empty value when JS is off — the POST is
/// then rejected, which is the safe default.
fn csrf_field_for(_user: &User) -> String {
    csrf_alpine()
}

/// A hidden CSRF input whose value Alpine fills from the `csrf` cookie at submit
/// time — used by HTMX fragments (notes, tags, cancel) that are re-rendered
/// without the live token threaded through. Falls back to empty (POST rejected)
/// when JS is off.
fn csrf_alpine() -> String {
    "<input type=\"hidden\" name=\"_csrf\" \
     x-data x-bind:value=\"(document.cookie.match(/(?:^|; )csrf=([^;]*)/)||[])[1]||''\">"
        .to_string()
}

/// The login page.
pub fn login(csrf: &str, error: Option<&str>) -> String {
    let err = error
        .map(|e| format!("<p class=\"error\">{}</p>", esc(e)))
        .unwrap_or_default();
    let body = format!(
        "<h1>Log in</h1>{err}\
         <form method=\"post\" action=\"/login\">{csrf}\
         <label>Username <input name=\"username\" autocomplete=\"username\" required></label>\
         <label>Password <input name=\"password\" type=\"password\" \
           autocomplete=\"current-password\" required></label>\
         <button type=\"submit\">Log in</button></form>\
         <p class=\"muted\">No account yet? <a href=\"/register\">Register</a>.</p>",
        csrf = csrf_field(csrf),
    );
    page("Log in", None, &body)
}

/// The registration page (first user bootstraps the admin account).
pub fn register(csrf: &str, error: Option<&str>) -> String {
    let err = error
        .map(|e| format!("<p class=\"error\">{}</p>", esc(e)))
        .unwrap_or_default();
    let body = format!(
        "<h1>Register</h1>{err}\
         <p class=\"muted\">The first account created becomes the admin.</p>\
         <form method=\"post\" action=\"/register\">{csrf}\
         <label>Username <input name=\"username\" autocomplete=\"username\" required></label>\
         <label>Password <input name=\"password\" type=\"password\" \
           autocomplete=\"new-password\" required></label>\
         <button type=\"submit\">Register</button></form>\
         <p class=\"muted\">Already have an account? <a href=\"/login\">Log in</a>.</p>",
        csrf = csrf_field(csrf),
    );
    page("Register", None, &body)
}

/// The start-scan page: pick scanners + targets, choose a timing profile and an
/// optional custom wordlist, submit.
pub fn scan_page(
    user: &User,
    csrf: &str,
    scanner_ids: &[String],
    profiles: &[TimingProfile],
    wordlists: &[CustomWordlist],
    engagements: &[Engagement],
) -> String {
    let options = scanner_ids
        .iter()
        .map(|id| {
            format!(
                "<label><input type=\"checkbox\" name=\"scanners\" value=\"{v}\"> {v}</label>",
                v = esc(id)
            )
        })
        .collect::<String>();
    // The pacing selector: the conservative default plus each of the user's own
    // profiles. The value carried is the profile id, resolved server-side to a
    // policy (a blank selection ⇒ the conservative default).
    let profile_options = profiles
        .iter()
        .map(|p| {
            format!(
                "<option value=\"{id}\">{name} — {desc}</option>",
                id = p.id,
                name = esc(&p.name),
                desc = esc(&describe_policy(&p.policy)),
            )
        })
        .collect::<String>();
    // The wordlist selector: the seeded default plus each of the user's own custom
    // lists (private to them). The value carried is the list id, owner-scoped
    // server-side; a blank selection ⇒ the seeded default. Only the subdomain
    // brute-force pass consumes it today, so it lives beside that toggle.
    let wordlist_options = wordlists
        .iter()
        .map(|w| {
            format!(
                "<option value=\"{id}\">{name} ({count} entries)</option>",
                id = w.id,
                name = esc(&w.name),
                count = w.entry_count,
            )
        })
        .collect::<String>();
    let wordlist_field = format!(
        "<label>Subdomain wordlist \
           <select name=\"opt.wordlist\">\
             <option value=\"\">Seeded default</option>{wordlist_options}\
           </select></label> \
         <a href=\"/wordlists\" class=\"muted\">Manage wordlists</a>"
    );
    // The optional engagement selector: the conservative default (none) plus each
    // of the operator's authorized engagements. Reference-only — the association
    // never changes what the scan targets or how it paces.
    let engagement_field = if engagements.is_empty() {
        "<a href=\"/engagements\" class=\"muted\">Create an engagement</a>".to_string()
    } else {
        let opts = engagement_options(engagements);
        format!(
            "<label>Engagement (optional) \
               <select name=\"engagement\">\
                 <option value=\"\">— none —</option>{opts}\
               </select></label> \
             <a href=\"/engagements\" class=\"muted\">Manage engagements</a>"
        )
    };
    let body = format!(
        "<h1>Start a scan</h1>\
         <form method=\"post\" action=\"/scans\">{csrf}\
         <label>Targets (one per line)<br>\
           <textarea name=\"targets\" rows=\"4\" cols=\"60\" required \
             placeholder=\"https://api.example.com\"></textarea></label>\
         <fieldset><legend>Scanners</legend>{options}</fieldset>\
         <fieldset><legend>Engagement</legend>{engagement_field}</fieldset>\
         <fieldset><legend>Pacing</legend>\
           <label>Timing profile \
             <select name=\"opt.timing_profile\">\
               <option value=\"\">Conservative default</option>{profile_options}\
             </select></label> \
           <a href=\"/timing-profiles\" class=\"muted\">Manage profiles</a>\
         </fieldset>\
         <fieldset><legend>Subdomain reconnaissance</legend>\
           <label><input type=\"checkbox\" name=\"opt.subdomain_bruteforce\" value=\"true\"> \
             Active subdomain brute-force (opt-in; off by default, stays passive otherwise)</label><br>\
           {wordlist_field}\
         </fieldset>\
         <button type=\"submit\">Start scan</button></form>",
        csrf = csrf_field(csrf),
    );
    page("Start a scan", Some(user), &body)
}

/// The timing-profiles management page: the user's reusable pacing shapes, each
/// with an inline adjust form, plus an add-a-profile form. Private to the user.
pub fn timing_profiles_page(user: &User, csrf: &str, profiles: &[TimingProfile]) -> String {
    let rows = profiles
        .iter()
        .map(|p| {
            let (shape, min, max) = policy_form_values(&p.policy);
            let builtin = if p.built_in {
                " <span class=\"muted\">(built-in)</span>"
            } else {
                ""
            };
            format!(
                "<li><form method=\"post\" action=\"/timing-profiles/{id}\">{csrf}\
                   <input name=\"name\" value=\"{name}\" required>{builtin} \
                   <select name=\"shape\">{shape_opts}</select> \
                   <input name=\"min\" type=\"number\" step=\"0.01\" min=\"0\" value=\"{min}\"> to \
                   <input name=\"max\" type=\"number\" step=\"0.01\" min=\"0\" value=\"{max}\"> s \
                   <button type=\"submit\">Save</button></form></li>",
                id = p.id,
                csrf = csrf_field(csrf),
                name = esc(&p.name),
                shape_opts = shape_options(shape),
                min = fmt_secs(min),
                max = fmt_secs(max),
            )
        })
        .collect::<String>();
    let body = format!(
        "<h1>Timing profiles</h1>\
         <p class=\"muted\">Reusable pacing shapes for your scans — only you can see or use \
           these. Organic profiles draw irregular, heavy-tailed gaps that avoid a detectable \
           cadence. Adaptive backoff and the target-distress halt apply under every profile.</p>\
         <ul class=\"profiles\">{rows}</ul>\
         <h2>Add a profile</h2>\
         <form method=\"post\" action=\"/timing-profiles\">{csrf}\
           <label>Name <input name=\"name\" required></label> \
           <label>Shape <select name=\"shape\">{default_shape}</select></label> \
           <label>Min delay (s) \
             <input name=\"min\" type=\"number\" step=\"0.01\" min=\"0\" value=\"1\"></label> \
           <label>Max delay (s) \
             <input name=\"max\" type=\"number\" step=\"0.01\" min=\"0\" value=\"3\"></label> \
           <button type=\"submit\">Add profile</button></form>",
        rows = rows,
        csrf = csrf_field(csrf),
        default_shape = shape_options("uniform"),
    );
    page("Timing profiles", Some(user), &body)
}

/// The custom-wordlists page: the user's imported lists plus an import form
/// (paste or `.txt` upload). Private to the user. An optional `notice` surfaces
/// the result of the last import (imported/dropped counts, or an error).
pub fn wordlists_page(
    user: &User,
    csrf: &str,
    lists: &[CustomWordlist],
    notice: Option<&str>,
) -> String {
    let notice_html = notice
        .map(|n| format!("<p class=\"notice\">{}</p>", esc(n)))
        .unwrap_or_default();
    let rows = if lists.is_empty() {
        "<p class=\"muted\">No custom wordlists yet.</p>".to_string()
    } else {
        let items = lists
            .iter()
            .map(|w| {
                format!(
                    "<li><strong>{name}</strong> \
                     <span class=\"muted\">{count} entries</span></li>",
                    name = esc(&w.name),
                    count = w.entry_count,
                )
            })
            .collect::<String>();
        format!("<ul class=\"wordlists\">{items}</ul>")
    };
    // The file input is read into the textarea client-side (see app.js), so the
    // server only ever handles pasted/urlencoded text — no multipart parsing. The
    // `data-wordlist-file` attribute names the textarea id its contents load into.
    let body = format!(
        "<h1>Custom wordlists</h1>\
         <p class=\"muted\">Import your own wordlists — paste terms or upload a <code>.txt</code> \
           file. Only you can see or select these. On import, entries are trimmed, lowercased, \
           and de-duplicated, and blank/comment (<code>#</code>) lines are dropped; the result \
           is reported below. A scan can select one of your lists for active subdomain \
           brute-force.</p>\
         {notice_html}\
         <h2>Your wordlists</h2>{rows}\
         <h2>Import a wordlist</h2>\
         <form method=\"post\" action=\"/wordlists\">{csrf}\
           <label>Name <input name=\"name\" required maxlength=\"80\"></label>\
           <label>Upload a .txt file \
             <input type=\"file\" accept=\".txt,text/plain\" data-wordlist-file=\"wordlist-text\"></label>\
           <label>Or paste terms (one per line)<br>\
             <textarea id=\"wordlist-text\" name=\"text\" rows=\"10\" cols=\"60\" \
               placeholder=\"api&#10;www&#10;mail\"></textarea></label>\
           <button type=\"submit\">Import wordlist</button></form>",
        csrf = csrf_field(csrf),
    );
    page("Custom wordlists", Some(user), &body)
}

/// A short human description of a pacing policy for the selector labels.
fn describe_policy(policy: &PacingPolicy) -> String {
    match policy {
        PacingPolicy::Uniform { min_secs, max_secs } => {
            format!("uniform {}–{}s", fmt_secs(*min_secs), fmt_secs(*max_secs))
        }
        PacingPolicy::Organic {
            min_secs, max_secs, ..
        } => format!(
            "organic {}–{}s, heavy-tailed",
            fmt_secs(*min_secs),
            fmt_secs(*max_secs)
        ),
    }
}

/// The (shape, min, max) triple the management form edits for a policy. Organic's
/// extra knobs are derived on save, so the form exposes just the window + shape.
fn policy_form_values(policy: &PacingPolicy) -> (&'static str, f64, f64) {
    match policy {
        PacingPolicy::Uniform { min_secs, max_secs } => ("uniform", *min_secs, *max_secs),
        PacingPolicy::Organic {
            min_secs, max_secs, ..
        } => ("organic", *min_secs, *max_secs),
    }
}

/// The `<option>`s for a shape `<select>`, marking `selected` current.
fn shape_options(selected: &str) -> String {
    ["uniform", "organic"]
        .iter()
        .map(|shape| {
            let sel = if *shape == selected { " selected" } else { "" };
            format!("<option value=\"{shape}\"{sel}>{shape}</option>")
        })
        .collect()
}

/// Format a delay in seconds without a trailing `.0` on whole numbers. A value
/// outside `i64`'s exact range (or non-finite) falls back to the float formatter,
/// so a huge stored delay never renders as a saturated `as i64` garbage integer.
fn fmt_secs(secs: f64) -> String {
    if secs.fract() == 0.0 && secs.abs() < i64::MAX as f64 {
        format!("{}", secs as i64)
    } else {
        format!("{secs}")
    }
}

/// The dashboard shell: statistics + sessions, each lazily loaded as a fragment.
pub fn dashboard(user: &User) -> String {
    let body = "<h1>Dashboard</h1>\
         <section id=\"stats\" hx-get=\"/stats\" hx-trigger=\"load\">Loading stats…</section>\
         <h2>Find</h2>\
         <form hx-get=\"/findings\" hx-target=\"#findings\" hx-trigger=\"submit\">\
           <input name=\"q\" placeholder=\"free text\">\
           <input name=\"target\" placeholder=\"target URL\">\
           <input name=\"scanner\" placeholder=\"scanner id\">\
           <select name=\"level\"><option value=\"\">any level</option>\
             <option>info</option><option>low</option><option>medium</option>\
             <option>high</option><option>critical</option></select>\
           <select name=\"status\"><option value=\"\">any status</option>\
             <option>vulnerable</option><option>safe</option><option>info</option></select>\
           <button type=\"submit\">Search</button></form>\
         <div id=\"findings\"></div>\
         <h2>Find sessions</h2>\
         <form hx-get=\"/search/notes\" hx-target=\"#session-search\" hx-trigger=\"submit\">\
           <input name=\"q\" placeholder=\"note text\" required>\
           <button type=\"submit\">Search notes</button></form>\
         <form hx-get=\"/search/tags\" hx-target=\"#session-search\" hx-trigger=\"submit\">\
           <input name=\"tags\" placeholder=\"tag names\" required>\
           <select name=\"mode\"><option value=\"any\">any tag</option>\
             <option value=\"all\">all tags</option></select>\
           <button type=\"submit\">Filter by tags</button></form>\
         <div id=\"session-search\"></div>\
         <h2>All tags</h2>\
         <section id=\"tag-list\" hx-get=\"/tags\" hx-trigger=\"load\">Loading tags…</section>\
         <h2>Sessions</h2>\
         <section id=\"sessions\" hx-get=\"/sessions\" hx-trigger=\"load\">Loading sessions…</section>";
    page("Dashboard", Some(user), body)
}

/// The statistics-cards fragment (owner-scoped counts).
pub fn stats(summary: &Summary) -> String {
    let sev = |s: Severity| summary.by_severity.get(&s).copied().unwrap_or(0);
    format!(
        "<div class=\"cards\">\
         <div class=\"card\"><strong>{sessions}</strong><br>sessions</div>\
         <div class=\"card\"><strong>{findings}</strong><br>findings</div>\
         <div class=\"card sev-critical\"><strong>{crit}</strong><br>critical</div>\
         <div class=\"card sev-high\"><strong>{high}</strong><br>high</div>\
         <div class=\"card sev-medium\"><strong>{med}</strong><br>medium</div>\
         <div class=\"card sev-low\"><strong>{low}</strong><br>low</div>\
         <div class=\"card sev-info\"><strong>{info}</strong><br>info</div></div>",
        sessions = summary.session_count,
        findings = summary.finding_count,
        crit = sev(Severity::Critical),
        high = sev(Severity::High),
        med = sev(Severity::Medium),
        low = sev(Severity::Low),
        info = sev(Severity::Info),
    )
}

/// The sessions-table fragment, scoped by owner.
pub fn sessions_table(sessions: &[ScanSession], viewer: &User) -> String {
    if sessions.is_empty() {
        return "<p class=\"muted\">No scan sessions yet.</p>".to_string();
    }
    let owner_col = viewer.is_admin();
    let rows = sessions
        .iter()
        .map(|s| {
            let targets = s
                .targets
                .iter()
                .map(|t| t.full_url().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let owner = if owner_col {
                format!(
                    "<td>{}</td>",
                    s.owner_user_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "—".to_string())
                )
            } else {
                String::new()
            };
            format!(
                "<tr><td><a href=\"/scan/{id}\">{short}</a></td>{owner}\
                 <td>{status}</td><td>{completed}/{total}</td><td>{findings}</td>\
                 <td>{targets}</td></tr>",
                id = s.id,
                short = &s.id.to_string()[..8],
                status = status_pill(s.status),
                completed = s.completed_units,
                total = s.total_units,
                findings = s.findings.len(),
                targets = esc(&targets),
            )
        })
        .collect::<String>();
    let owner_head = if owner_col { "<th>owner</th>" } else { "" };
    format!(
        "<table><thead><tr><th>session</th>{owner_head}<th>status</th>\
         <th>units</th><th>findings</th><th>targets</th></tr></thead><tbody>{rows}</tbody></table>"
    )
}

/// The scan-detail page: live progress region + the persisted results fragment.
pub fn scan_detail(
    user: &User,
    csrf: &str,
    session: &ScanSession,
    engagements: &[Engagement],
) -> String {
    let id = session.id;
    let active = !session.status.is_terminal();
    let live = if active {
        format!("<section id=\"live\" data-session=\"{id}\">Connecting to live progress…</section>")
    } else {
        format!("<section id=\"live\">{}</section>", progress(session, None))
    };
    let body = format!(
        "<h1>Scan {short}</h1>\
         <p>Status: {status}</p>\
         {cancel}\
         {live}\
         {assign}\
         <h2>Tags</h2>\
         <section hx-get=\"/scan/{id}/tags\" hx-trigger=\"load\">Loading tags…</section>\
         <h2>Notes</h2>\
         <section hx-get=\"/scan/{id}/notes\" hx-trigger=\"load\">Loading notes…</section>\
         <h2>Findings</h2>\
         <div id=\"results\" hx-get=\"/scan/{id}/results\" \
           hx-trigger=\"load, refresh\">Loading…</div>",
        short = &id.to_string()[..8],
        status = status_pill(session.status),
        cancel = cancel_form(user, session),
        assign = assign_engagement_form(csrf, id, engagements),
    );
    page("Scan detail", Some(user), &body)
}

/// The "assign this scan to an engagement" form (a full-page POST). The selection
/// is optional; a blank choice clears any existing association. With no
/// engagements yet, it points the operator at where to create one. The association
/// is reference-only — it never changes what the scan targets or how it paces.
fn assign_engagement_form(csrf: &str, id: Uuid, engagements: &[Engagement]) -> String {
    if engagements.is_empty() {
        return "<p class=\"muted\">Assign to an engagement: \
                <a href=\"/engagements\">create one first</a>.</p>"
            .to_string();
    }
    format!(
        "<form method=\"post\" action=\"/scan/{id}/assign\">{csrf}\
           <label>Engagement \
             <select name=\"engagement\">\
               <option value=\"\">— none —</option>{opts}\
             </select></label> \
           <button type=\"submit\">Assign</button></form>",
        csrf = csrf_field(csrf),
        opts = engagement_options(engagements),
    )
}

/// The `<option>` list of a set of engagements (value = id, label = name).
fn engagement_options(engagements: &[Engagement]) -> String {
    engagements
        .iter()
        .map(|e| {
            format!(
                "<option value=\"{id}\">{name}</option>",
                id = e.id,
                name = esc(&e.name),
            )
        })
        .collect()
}

/// The cancel button (only while the scan is still running and the viewer may act).
fn cancel_form(_user: &User, session: &ScanSession) -> String {
    if session.status.is_terminal() {
        return String::new();
    }
    format!(
        "<form method=\"post\" action=\"/scan/{id}/cancel\" \
           hx-post=\"/scan/{id}/cancel\" hx-target=\"#live\">\
         {csrf}<button type=\"submit\">Cancel scan</button></form>",
        id = session.id,
        csrf = csrf_alpine(),
    )
}

/// The live-progress fragment pushed over the WebSocket (and rendered inline for
/// a terminal session). Conveys the current scanner, units tested out of the
/// total, and findings discovered so far.
pub fn progress(session: &ScanSession, scanner: Option<&str>) -> String {
    let terminal = session.status.is_terminal();
    let scanner = scanner.unwrap_or(if terminal { "—" } else { "(starting)" });
    format!(
        "<div data-terminal=\"{terminal}\">\
         <p>Status: {status}</p>\
         <p>Current scanner: <strong>{scanner}</strong></p>\
         <p>Units: {completed} / {total}</p>\
         <p>Findings so far: <strong>{findings}</strong></p></div>",
        status = status_pill(session.status),
        scanner = esc(scanner),
        completed = session.completed_units,
        total = session.total_units,
        findings = session.findings.len(),
    )
}

/// The findings fragment for a session's results (and the search results list).
///
/// When `session_id` is `Some`, each persisted finding gets an "Analyze with AI"
/// action wired to that session (the finding-detail surface). The dashboard search
/// list passes `None`, since its rows are summaries across many sessions.
pub fn findings(findings: &[Finding], session_id: Option<Uuid>) -> String {
    if findings.is_empty() {
        return "<p class=\"muted\">No findings.</p>".to_string();
    }
    let rows = findings
        .iter()
        .map(|f| finding_row(f, session_id))
        .collect::<String>();
    format!(
        "<table><thead><tr><th>severity</th><th>status</th><th>scanner</th>\
         <th>target</th><th>finding</th></tr></thead><tbody>{rows}</tbody></table>"
    )
}

fn finding_row(f: &Finding, session_id: Option<Uuid>) -> String {
    let description = f
        .description
        .as_deref()
        .map(|d| format!("<br><span class=\"muted\">{}</span>", esc(d)))
        .unwrap_or_default();
    let evidence = f
        .evidence
        .as_ref()
        .map(|e| {
            let pretty = serde_json::to_string_pretty(e).unwrap_or_else(|_| e.to_string());
            format!(
                "<details><summary>evidence</summary><pre>{}</pre></details>",
                esc(&pretty)
            )
        })
        .unwrap_or_default();
    let analyze = match (session_id, f.id) {
        (Some(sid), Some(fid)) => analyze_action(sid, fid),
        _ => String::new(),
    };
    format!(
        "<tr><td class=\"sev-{sev}\">{sev}</td><td>{status}</td><td>{scanner}</td>\
         <td>{target}</td><td><strong>{title}</strong>{description}{evidence}{analyze}</td></tr>",
        sev = severity_str(f.severity),
        status = finding_status_pill(f.status),
        scanner = esc(&f.scanner_id),
        target = esc(f.target.full_url().as_str()),
        title = esc(&f.title),
    )
}

/// The "Analyze with AI" action for one finding: a form that POSTs to the analyze
/// endpoint and swaps the returned analysis (or notice) into the finding's own
/// result slot.
fn analyze_action(session_id: Uuid, finding_id: i64) -> String {
    format!(
        "<div class=\"ai-assist\">\
         <form hx-post=\"/scan/{session_id}/findings/{finding_id}/analyze\" \
           hx-target=\"#ai-{finding_id}\" hx-swap=\"innerHTML\" style=\"display:inline\">{csrf}\
           <button type=\"submit\">Analyze with AI</button></form>\
         <div id=\"ai-{finding_id}\"></div></div>",
        csrf = csrf_alpine(),
    )
}

/// The AI-analysis result fragment swapped in beneath a finding on success.
pub fn ai_analysis(text: &str) -> String {
    format!(
        "<div class=\"ai-analysis\"><h4>AI analysis</h4><pre>{}</pre></div>",
        esc(text)
    )
}

/// The custom-requests page.
pub fn custom_requests(user: &User, csrf: &str) -> String {
    let body = format!(
        "<h1>Custom request</h1>\
         <p class=\"muted\">Issue one ad-hoc HTTP request. Bearer token and cookies are \
           optional; omit both for a keyless request.</p>\
         <form hx-post=\"/custom-requests\" hx-target=\"#response\">{csrf}\
         <label>URL <input name=\"url\" required placeholder=\"https://api.example.com/health\"></label>\
         <label>Method <input name=\"method\" value=\"GET\"></label>\
         <label>Headers (one <code>Name: value</code> per line)<br>\
           <textarea name=\"headers\" rows=\"3\" cols=\"60\"></textarea></label>\
         <label>Bearer token <input name=\"bearer\"></label>\
         <label>Cookies <input name=\"cookie\"></label>\
         <label>Body<br><textarea name=\"body\" rows=\"4\" cols=\"60\"></textarea></label>\
         <button type=\"submit\">Send</button></form>\
         <div id=\"response\"></div>",
        csrf = csrf_field(csrf),
    );
    page("Custom request", Some(user), &body)
}

/// The custom-request response fragment.
pub fn custom_response(outcome: &RequestOutcome) -> String {
    let req = format!(
        "<p><strong>{} {}</strong></p>",
        esc(&outcome.request.method),
        esc(&outcome.request.url)
    );
    match outcome.response() {
        Some(resp) => {
            let headers = resp
                .headers
                .iter()
                .map(|(n, v)| format!("{}: {}\n", esc(n), esc(v)))
                .collect::<String>();
            let (body, truncated) = resp.display_body(outcome.body_preview_cap);
            let trunc = if truncated {
                "<p class=\"muted\">(body truncated)</p>"
            } else {
                ""
            };
            format!(
                "{req}<p>Status: <strong>{status}</strong> · {ms} ms · {url}</p>\
                 <h3>Response headers</h3><pre>{headers}</pre>\
                 <h3>Body</h3><pre>{body}</pre>{trunc}",
                status = resp.status,
                ms = resp.elapsed.as_millis(),
                url = esc(&resp.final_url),
                body = esc(&body),
            )
        }
        None => format!(
            "{req}<p class=\"error\">Request failed: {}</p>",
            esc(outcome.error().unwrap_or("unknown error"))
        ),
    }
}

/// A standalone error fragment (e.g. a rejected scan submission).
pub fn error_fragment(message: &str) -> String {
    format!("<p class=\"error\">{}</p>", esc(message))
}

// --- Engagements -----------------------------------------------------------

/// The engagements list page: the operator's authorized engagements plus a form to
/// create one. Private to the authorized set (an admin sees all).
pub fn engagements_page(user: &User, csrf: &str, engagements: &[Engagement]) -> String {
    let rows = if engagements.is_empty() {
        "<p class=\"muted\">No engagements yet.</p>".to_string()
    } else {
        let items = engagements
            .iter()
            .map(|e| {
                format!(
                    "<li><a href=\"/engagements/{id}\">{name}</a> \
                     <span class=\"muted\">created {created} · owner #{owner}</span></li>",
                    id = e.id,
                    name = esc(&e.name),
                    created = e.created_at.format("%Y-%m-%d"),
                    owner = e.owner_user_id,
                )
            })
            .collect::<String>();
        format!("<ul class=\"engagements\">{items}</ul>")
    };
    let body = format!(
        "<h1>Engagements</h1>\
         <p class=\"muted\">Group scans under a recorded authorization. Attach the job's scope \
           and proof of authorization for reference — the stored scope never constrains scanning. \
           Only you (and an admin) can see your engagements.</p>\
         <h2>Your engagements</h2>{rows}\
         <h2>Create an engagement</h2>\
         <form method=\"post\" action=\"/engagements\">{csrf}\
           <label>Name <input name=\"name\" required maxlength=\"120\"></label>\
           <button type=\"submit\">Create engagement</button></form>",
        csrf = csrf_field(csrf),
    );
    page("Engagements", Some(user), &body)
}

/// One engagement's detail page: its associated scans, its attached documents
/// (pasted text inline, a URL as a link, an uploaded PDF inline via the browser's
/// native viewer), and forms to attach more. An optional `notice` reports a failed
/// attach.
#[allow(clippy::too_many_arguments)]
pub fn engagement_detail(
    user: &User,
    csrf: &str,
    engagement: &Engagement,
    sessions: &[ScanSession],
    rollup: &Summary,
    rollup_findings: &[Finding],
    documents: &[EngagementDocument],
    notice: Option<&str>,
) -> String {
    let notice_html = notice
        .map(|n| format!("<p class=\"notice\">{}</p>", esc(n)))
        .unwrap_or_default();
    let scans = if sessions.is_empty() {
        "<p class=\"muted\">No scans associated yet.</p>".to_string()
    } else {
        sessions_table(sessions, user)
    };
    // Results rollup: the severity breakdown plus the findings aggregated across
    // the engagement's sessions the operator may see (findings span sessions, so
    // no per-finding session action — `None`, like the dashboard search list).
    let rollup_html = format!("{}{}", stats(rollup), findings(rollup_findings, None));
    let docs = if documents.is_empty() {
        "<p class=\"muted\">No documents attached yet.</p>".to_string()
    } else {
        documents
            .iter()
            .map(|d| document_view(engagement.id, d))
            .collect::<String>()
    };
    let body = format!(
        "<h1>Engagement: {name}</h1>\
         <p class=\"muted\">created {created} · owner #{owner}</p>\
         {notice}\
         <h2>Results rollup</h2>\
         <p class=\"muted\">Findings across this engagement's scans you can see.</p>\
         {rollup}\
         <h2>Scans</h2>{scans}\
         <h2>Scope &amp; authorization documents</h2>\
         <p class=\"muted\">Reference material only — never used to decide what a scan targets \
           or how a scanner behaves.</p>\
         {docs}\
         <h2>Attach a document</h2>{forms}",
        name = esc(&engagement.name),
        created = engagement.created_at.format("%Y-%m-%d %H:%M"),
        owner = engagement.owner_user_id,
        notice = notice_html,
        rollup = rollup_html,
        forms = attach_document_forms(csrf, engagement.id),
    );
    page("Engagement", Some(user), &body)
}

/// Render one attached document for reference: pasted text inline as text, a URL
/// as a deliberate link, and an uploaded file via the safe serving endpoint — a
/// PDF embedded inline (the browser's native viewer) plus an open link.
fn document_view(engagement_id: i64, doc: &EngagementDocument) -> String {
    let meta = format!(
        "<p class=\"muted\">added by operator #{by} · {at}</p>",
        by = doc.added_by_user_id,
        at = doc.added_at.format("%Y-%m-%d %H:%M"),
    );
    let inner = match doc.kind {
        DocumentKind::Text => format!(
            "<pre class=\"doc-text\">{}</pre>",
            esc(doc.content.as_deref().unwrap_or(""))
        ),
        DocumentKind::Url => {
            let url = esc(doc.content.as_deref().unwrap_or(""));
            format!(
                "<a href=\"{url}\" rel=\"noopener noreferrer nofollow\" target=\"_blank\">{url}</a>"
            )
        }
        DocumentKind::File => {
            let src = format!("/engagements/{engagement_id}/documents/{}", doc.id);
            let name = esc(doc.filename.as_deref().unwrap_or("document"));
            // Only a PDF is embedded inline via the native viewer; any file also
            // gets a plain open link (served safely from the same-origin endpoint,
            // no external code).
            let embed = if doc.content_type.as_deref() == Some("application/pdf") {
                format!(
                    "<iframe class=\"doc-pdf\" src=\"{src}\" title=\"{name}\" \
                       width=\"100%\" height=\"600\"></iframe>"
                )
            } else {
                String::new()
            };
            format!("{embed}<p><a href=\"{src}\">Open {name}</a></p>")
        }
    };
    format!("<div class=\"doc\">{inner}{meta}</div>")
}

/// The three attach-a-document forms (pasted text, a URL, an uploaded file), each
/// a full-page POST to the engagement's documents endpoint. The file form's chosen
/// file is read client-side into the hidden `file_data`/`file_name` fields (see
/// app.js), so the server handles ordinary urlencoded input — no multipart parsing.
fn attach_document_forms(csrf: &str, engagement_id: i64) -> String {
    let action = format!("/engagements/{engagement_id}/documents");
    format!(
        "<form method=\"post\" action=\"{action}\">{csrf}\
           <input type=\"hidden\" name=\"kind\" value=\"text\">\
           <label>Paste scope text<br>\
             <textarea name=\"content\" rows=\"6\" cols=\"60\" required \
               placeholder=\"In scope: *.example.com\"></textarea></label>\
           <button type=\"submit\">Attach text</button></form>\
         <form method=\"post\" action=\"{action}\">{csrf2}\
           <input type=\"hidden\" name=\"kind\" value=\"url\">\
           <label>Scope URL <input name=\"url\" type=\"url\" required \
             placeholder=\"https://example.com/security\"></label>\
           <button type=\"submit\">Attach URL</button></form>\
         <form method=\"post\" action=\"{action}\">{csrf3}\
           <input type=\"hidden\" name=\"kind\" value=\"file\">\
           <input type=\"hidden\" name=\"file_name\">\
           <input type=\"hidden\" name=\"file_data\">\
           <label>Upload a PDF or .txt authorization \
             <input type=\"file\" accept=\"application/pdf,text/plain,.pdf,.txt\" data-doc-file></label>\
           <button type=\"submit\">Attach file</button></form>",
        csrf = csrf_field(csrf),
        csrf2 = csrf_field(csrf),
        csrf3 = csrf_field(csrf),
    )
}

// --- Annotations: notes + color tags ---------------------------------------

/// The notes fragment for a session (`finding_id == None`) or a finding. Carries
/// an add form plus each note with inline edit/delete. The whole block is the
/// HTMX swap target, so add/edit/delete re-render it in place.
pub fn notes_block(session_id: Uuid, finding_id: Option<i64>, notes: &[Note]) -> String {
    let wrapper = match finding_id {
        Some(fid) => format!("notes-f{fid}"),
        None => "notes".to_string(),
    };
    let add_url = match finding_id {
        Some(fid) => format!("/scan/{session_id}/findings/{fid}/notes"),
        None => format!("/scan/{session_id}/notes"),
    };
    let items = if notes.is_empty() {
        "<p class=\"muted\">No notes yet.</p>".to_string()
    } else {
        notes
            .iter()
            .map(|n| note_item(&wrapper, n))
            .collect::<String>()
    };
    format!(
        "<div id=\"{wrapper}\" class=\"notes\">\
         <form hx-post=\"{add_url}\" hx-target=\"#{wrapper}\" hx-swap=\"outerHTML\">{csrf}\
           <textarea name=\"content\" rows=\"2\" placeholder=\"Add a note…\" required></textarea>\
           <button type=\"submit\">Add note</button></form>{items}</div>",
        csrf = csrf_alpine(),
    )
}

/// One note: content, author/timestamps, an inline edit form, and a delete form,
/// all re-targeting the enclosing notes block (`wrapper`).
fn note_item(wrapper: &str, note: &Note) -> String {
    let edited = note
        .edited_at
        .map(|t| format!(" · edited {}", t.format("%Y-%m-%d %H:%M")))
        .unwrap_or_default();
    format!(
        "<div class=\"note\"><p>{content}</p>\
         <p class=\"muted\">{author} · {created}{edited}</p>\
         <details><summary>edit</summary>\
           <form hx-post=\"/notes/{id}/edit\" hx-target=\"#{wrapper}\" hx-swap=\"outerHTML\">{csrf}\
             <textarea name=\"content\" rows=\"2\" required>{content}</textarea>\
             <button type=\"submit\">Save</button></form></details>\
         <form hx-post=\"/notes/{id}/delete\" hx-target=\"#{wrapper}\" hx-swap=\"outerHTML\" \
           style=\"display:inline\">{csrf}<button type=\"submit\">Delete</button></form></div>",
        content = esc(&note.content),
        author = esc(&note.author),
        created = note.created_at.format("%Y-%m-%d %H:%M"),
        id = note.id,
        csrf = csrf_alpine(),
    )
}

/// The tags fragment for a session: the applied tag chips (each removable) plus
/// an apply form. The block is the HTMX swap target for apply/remove.
pub fn session_tags_block(session_id: Uuid, tags: &[Tag]) -> String {
    let chips = if tags.is_empty() {
        "<span class=\"muted\">No tags.</span>".to_string()
    } else {
        tags.iter()
            .map(|t| tag_chip(session_id, t))
            .collect::<String>()
    };
    format!(
        "<div id=\"session-tags\" class=\"tags\">{chips}\
         <form hx-post=\"/scan/{session_id}/tags\" hx-target=\"#session-tags\" \
           hx-swap=\"outerHTML\" style=\"display:inline\">{csrf}\
           <input name=\"tags\" placeholder=\"tag names\" required>\
           <input name=\"color\" placeholder=\"#RRGGBB\" size=\"8\">\
           <button type=\"submit\">Apply</button></form></div>",
        csrf = csrf_alpine(),
    )
}

/// One applied tag chip with a remove control.
fn tag_chip(session_id: Uuid, tag: &Tag) -> String {
    format!(
        "<span class=\"tag-chip\" style=\"background:{color}\">{name}\
         <form hx-post=\"/scan/{session_id}/tags/{tag_id}/remove\" hx-target=\"#session-tags\" \
           hx-swap=\"outerHTML\" style=\"display:inline\">{csrf}\
           <button type=\"submit\" title=\"remove\">×</button></form></span>",
        color = esc(&tag.color),
        name = esc(&tag.name),
        tag_id = tag.id,
        csrf = csrf_alpine(),
    )
}

/// The all-tags list with usage counts, plus a create form. The block is the
/// HTMX swap target for create.
pub fn tag_list(tags: &[TagUsage]) -> String {
    let rows = if tags.is_empty() {
        "<p class=\"muted\">No tags defined yet.</p>".to_string()
    } else {
        let items = tags
            .iter()
            .map(|u| {
                let desc = u
                    .tag
                    .description
                    .as_deref()
                    .map(|d| format!(" — {}", esc(d)))
                    .unwrap_or_default();
                format!(
                    "<li><span class=\"tag-chip\" style=\"background:{color}\">{name}</span> \
                     <span class=\"muted\">{count} session{plural}</span>{desc}</li>",
                    color = esc(&u.tag.color),
                    name = esc(&u.tag.name),
                    count = u.session_count,
                    plural = if u.session_count == 1 { "" } else { "s" },
                )
            })
            .collect::<String>();
        format!("<ul class=\"tag-usage\">{items}</ul>")
    };
    format!(
        "<div id=\"tag-list\">\
         <form hx-post=\"/tags\" hx-target=\"#tag-list\" hx-swap=\"outerHTML\">{csrf}\
           <input name=\"name\" placeholder=\"tag name\" required>\
           <input name=\"color\" placeholder=\"#RRGGBB\" size=\"8\">\
           <input name=\"description\" placeholder=\"description (optional)\">\
           <button type=\"submit\">Create tag</button></form>{rows}</div>",
        csrf = csrf_alpine(),
    )
}

fn status_str(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Pending => "pending",
        SessionStatus::Running => "running",
        SessionStatus::Completed => "completed",
        SessionStatus::Cancelled => "cancelled",
        SessionStatus::Errored => "errored",
    }
}

/// A session-status pill (`<span class="status status-…">`); CSS colors it by state.
fn status_pill(status: SessionStatus) -> String {
    let s = status_str(status);
    format!("<span class=\"status status-{s}\">{s}</span>")
}

fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn finding_status_str(status: abyssum_core::Status) -> &'static str {
    use abyssum_core::Status;
    match status {
        Status::Vulnerable => "vulnerable",
        Status::Safe => "safe",
        Status::Info => "info",
    }
}

/// A finding-status pill (`<span class="status status-…">`); CSS colors it by state.
fn finding_status_pill(status: abyssum_core::Status) -> String {
    let s = finding_status_str(status);
    format!("<span class=\"status status-{s}\">{s}</span>")
}
