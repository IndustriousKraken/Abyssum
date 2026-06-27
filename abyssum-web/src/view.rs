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
    Finding, Note, ScanSession, SessionStatus, Severity, Summary, Tag, TagUsage, User,
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
            "<nav><a href=\"/\">Scan</a><a href=\"/dashboard\">Dashboard</a>\
             <a href=\"/custom-requests\">Custom request</a>\
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
         <!-- ponytail: htmx/alpine are vendored into /static by install.sh (packaging step). -->\
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

/// The start-scan home page: pick scanners + targets and submit.
pub fn home(user: &User, csrf: &str, scanner_ids: &[String]) -> String {
    let options = scanner_ids
        .iter()
        .map(|id| {
            format!(
                "<label><input type=\"checkbox\" name=\"scanners\" value=\"{v}\"> {v}</label>",
                v = esc(id)
            )
        })
        .collect::<String>();
    let body = format!(
        "<h1>Start a scan</h1>\
         <form method=\"post\" action=\"/scans\">{csrf}\
         <label>Targets (one per line)<br>\
           <textarea name=\"targets\" rows=\"4\" cols=\"60\" required \
             placeholder=\"https://api.example.com\"></textarea></label>\
         <fieldset><legend>Scanners</legend>{options}</fieldset>\
         <button type=\"submit\">Start scan</button></form>",
        csrf = csrf_field(csrf),
    );
    page("Start a scan", Some(user), &body)
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
                status = status_str(s.status),
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
pub fn scan_detail(user: &User, session: &ScanSession) -> String {
    let id = session.id;
    let active = !session.status.is_terminal();
    let live = if active {
        format!("<section id=\"live\" data-session=\"{id}\">Connecting to live progress…</section>")
    } else {
        format!("<section id=\"live\">{}</section>", progress(session, None))
    };
    let body = format!(
        "<h1>Scan {short}</h1>\
         <p>Status: <strong>{status}</strong></p>\
         {cancel}\
         {live}\
         <h2>Tags</h2>\
         <section hx-get=\"/scan/{id}/tags\" hx-trigger=\"load\">Loading tags…</section>\
         <h2>Notes</h2>\
         <section hx-get=\"/scan/{id}/notes\" hx-trigger=\"load\">Loading notes…</section>\
         <h2>Findings</h2>\
         <div id=\"results\" hx-get=\"/scan/{id}/results\" \
           hx-trigger=\"load, refresh\">Loading…</div>",
        short = &id.to_string()[..8],
        status = status_str(session.status),
        cancel = cancel_form(user, session),
    );
    page("Scan detail", Some(user), &body)
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
         <p>Status: <strong>{status}</strong></p>\
         <p>Current scanner: <strong>{scanner}</strong></p>\
         <p>Units: {completed} / {total}</p>\
         <p>Findings so far: <strong>{findings}</strong></p></div>",
        status = status_str(session.status),
        scanner = esc(scanner),
        completed = session.completed_units,
        total = session.total_units,
        findings = session.findings.len(),
    )
}

/// The findings fragment for a session's results (and the search results list).
pub fn findings(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "<p class=\"muted\">No findings.</p>".to_string();
    }
    let rows = findings.iter().map(finding_row).collect::<String>();
    format!(
        "<table><thead><tr><th>severity</th><th>status</th><th>scanner</th>\
         <th>target</th><th>finding</th></tr></thead><tbody>{rows}</tbody></table>"
    )
}

fn finding_row(f: &Finding) -> String {
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
    format!(
        "<tr><td class=\"sev-{sev}\">{sev}</td><td>{status}</td><td>{scanner}</td>\
         <td>{target}</td><td><strong>{title}</strong>{description}{evidence}</td></tr>",
        sev = severity_str(f.severity),
        status = finding_status_str(f.status),
        scanner = esc(&f.scanner_id),
        target = esc(f.target.full_url().as_str()),
        title = esc(&f.title),
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
