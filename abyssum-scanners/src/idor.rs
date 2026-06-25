//! Insecure Direct Object Reference (IDOR) scanner.
//!
//! [`IdorScanner`] looks for object-reference points — endpoint paths that embed
//! an object identifier (`/api/users/{id}`) and query parameters that carry one
//! (`?id=1`) — establishes a *baseline* reference for each, then probes
//! adjacent/alternative references of the same id-shape. It reports an IDOR when a
//! non-baseline reference, requested *without the caller's authorization*, returns a
//! successful response carrying a materially different object's data — not an error
//! page and not the same object echoed back.
//!
//! Like every scanner it owns none of the cross-cutting concerns: every probe goes
//! through [`ScanContext::send`], so pacing, the rotating User-Agent, cancellation,
//! and progress all apply uniformly and the stealth floor cannot be bypassed. The
//! IDOR-specific twist is that each *enumeration* probe is issued with
//! [`RequestSpec::without_credential`], so a positive result reflects access
//! available to an anonymous caller (the essence of an IDOR) even when the scan is
//! otherwise configured with a credential. The baseline capture and the
//! identifier-harvest probes keep the credential, so the baseline reflects the
//! caller's own authorized view.
//!
//! ## The three phases
//!
//! 1. **Harvest** — probe a few likely "self" endpoints (`/api/me`, `/api/user`,
//!    …) and harvest real identifiers from their bodies (JSON-aware, regex-free
//!    fallback for non-JSON), grouping by id-shape (numeric / UUID / username /
//!    email). These become the per-shape baseline references. If nothing is
//!    harvested a default numeric baseline (`"1"`) is used so enumeration can still
//!    proceed.
//! 2. **Capture baselines** — for each object-reference point (a path template ×
//!    an available id-shape, or a query-parameter endpoint) capture the baseline
//!    response. A point whose baseline is not a clean success (or is itself an
//!    error page) is dropped, so the candidate total reflects only viable points.
//! 3. **Enumerate** — for each viable point, probe its alternative references
//!    (credential stripped) and confirm an IDOR per the rules below, emitting a
//!    `tested / total` progress update per reference.
//!
//! ## What counts as an IDOR
//!
//! `confirmed_idor(baseline, alt)` is true iff **all** hold: the alternative's
//! status is success (2xx); the alternative reference is not the baseline
//! reference; the alternative body is not a recognized error/not-found page; and
//! the alternative body differs *materially* from the baseline body (so an
//! identical echo of the caller's own object, or a generic shell served for every
//! id, is not reported). Material difference is a whitespace-normalized
//! length-then-structural comparison (JSON-aware, byte-length fallback).

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use abyssum_core::{
    BaseScanner, Error, Finding, ProgressUpdate, RequestSpec, Result, ScanContext, ScannerFactory,
    ScannerRegistry, Severity, Status, Target,
};

/// The stable scanner id. The registry keys on this and a scan selects by it; it
/// must never change.
const ID: &str = "idor";

/// Upper bound on the response body buffered per probe. A probed endpoint is
/// untrusted and could stream an unbounded body, so the scanner never reads a whole
/// body into memory: bytes beyond this cap are dropped and the response is flagged
/// `truncated`.
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// How many leading bytes of the response body to keep as the bounded evidence
/// sample (UTF-8 lossy). Enough to recognize the exposure, never the whole body.
const SAMPLE_BYTES: usize = 512;

/// Largest body (bytes) the error/not-found phrase scan inspects; a recognized
/// not-found phrase is characteristic of short stub pages, so a large real body that
/// merely mentions one somewhere is not suppressed.
const ERROR_PAGE_MAX_BYTES: usize = 4096;

/// The whitespace-normalized length tolerance below which two bodies are *not*
/// considered to differ on length alone (5%).
const LENGTH_TOLERANCE: f64 = 0.05;

/// The built-in "self" endpoints probed to harvest the caller's own identifiers.
/// These are detection heuristics kept in code, not DB-seeded wordlists.
const SELF_ENDPOINTS: &[&str] = &[
    "/api/me",
    "/api/user",
    "/api/users/me",
    "/api/account",
    "/api/profile",
    "/me",
    "/user",
    "/account",
    "/profile",
];

/// Built-in object-reference endpoint patterns: paths embedding an `{id}`
/// placeholder. The target's own `id_template` (if any) is probed alongside these.
const PATH_TEMPLATES: &[&str] = &[
    "/api/users/{id}",
    "/api/user/{id}",
    "/api/accounts/{id}",
    "/api/orders/{id}",
    "/api/documents/{id}",
    "/api/files/{id}",
    "/users/{id}",
];

/// Built-in query-parameter endpoints probed for parameter-carried references.
const PARAM_ENDPOINTS: &[&str] = &[
    "/api/user",
    "/api/account",
    "/api/profile",
    "/api/document",
    "/api/order",
];

/// Built-in object-reference parameter names.
const PARAM_NAMES: &[&str] = &["id", "user_id", "account_id", "uid"];

/// A small fixed set of well-known / sentinel UUIDs probed as alternative
/// references when a UUID baseline is harvested.
const SENTINEL_UUIDS: &[&str] = &[
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
];

/// A small fixed set of common account names probed as alternative references when
/// a username baseline is harvested.
const COMMON_USERNAMES: &[&str] = &["admin", "administrator", "root", "test", "guest"];

/// A small fixed set of common addresses probed as alternative references when an
/// email baseline is harvested.
const COMMON_EMAILS: &[&str] = &["admin@example.com", "test@example.com", "root@example.com"];

/// The shape of an object identifier. Neighbour generation and harvesting both key
/// on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdShape {
    Numeric,
    Uuid,
    Username,
    Email,
}

impl IdShape {
    fn label(self) -> &'static str {
        match self {
            IdShape::Numeric => "numeric",
            IdShape::Uuid => "uuid",
            IdShape::Username => "username",
            IdShape::Email => "email",
        }
    }
}

/// The class of data a confirmed IDOR response exposes, ordered least to most
/// sensitive so the overall class is the maximum over the signals seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DataClass {
    /// No structured/sensitive content.
    None,
    /// A user-shaped record without recognized PII.
    UserData,
    /// Personally-identifiable information.
    Pii,
    /// Credentials, secrets, or financial data.
    Credentials,
}

impl DataClass {
    fn label(self) -> &'static str {
        match self {
            DataClass::None => "none",
            DataClass::UserData => "user_data",
            DataClass::Pii => "pii",
            DataClass::Credentials => "credentials",
        }
    }
}

/// The sensitive-field table: each `(needle, class, label)` flags `class` when
/// `needle` appears (case-insensitive) in the body, recording `label` as a detected
/// sensitive field. The set is a tunable default — the observable contract is the
/// data class it yields, not the exact strings.
const SENSITIVE_FIELDS: &[(&str, DataClass, &str)] = &[
    ("password", DataClass::Credentials, "password"),
    ("passwd", DataClass::Credentials, "password"),
    ("api_key", DataClass::Credentials, "api_key"),
    ("apikey", DataClass::Credentials, "api_key"),
    ("secret", DataClass::Credentials, "secret"),
    ("token", DataClass::Credentials, "token"),
    ("private_key", DataClass::Credentials, "private_key"),
    ("credit_card", DataClass::Credentials, "credit_card"),
    ("creditcard", DataClass::Credentials, "credit_card"),
    ("card_number", DataClass::Credentials, "card_number"),
    ("iban", DataClass::Credentials, "iban"),
    ("account_number", DataClass::Credentials, "account_number"),
    ("bank", DataClass::Credentials, "bank"),
    ("ssn", DataClass::Pii, "ssn"),
    ("social_security", DataClass::Pii, "ssn"),
    ("email", DataClass::Pii, "email"),
    ("phone", DataClass::Pii, "phone"),
    ("telephone", DataClass::Pii, "phone"),
    ("address", DataClass::Pii, "address"),
    ("date_of_birth", DataClass::Pii, "date_of_birth"),
];

/// The per-shape baseline references harvested (or defaulted). First harvested
/// value of each shape wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct References {
    numeric: Option<String>,
    uuid: Option<String>,
    username: Option<String>,
    email: Option<String>,
}

impl References {
    /// Record `value` as the baseline for its shape if that shape has none yet.
    fn store(&mut self, value: &str) {
        match id_shape(value) {
            Some(IdShape::Numeric) if self.numeric.is_none() => {
                self.numeric = Some(value.to_string())
            }
            Some(IdShape::Uuid) if self.uuid.is_none() => self.uuid = Some(value.to_string()),
            Some(IdShape::Username) if self.username.is_none() => {
                self.username = Some(value.to_string())
            }
            Some(IdShape::Email) if self.email.is_none() => self.email = Some(value.to_string()),
            _ => {}
        }
    }

    /// Record only a distinctive (UUID / email) value, regardless of its source
    /// key — used for values under keys that are not obviously id-like, where a
    /// bare number or word would be too noisy to trust but a UUID/email is not.
    fn store_distinctive(&mut self, value: &str) {
        match id_shape(value) {
            Some(IdShape::Uuid) if self.uuid.is_none() => self.uuid = Some(value.to_string()),
            Some(IdShape::Email) if self.email.is_none() => self.email = Some(value.to_string()),
            _ => {}
        }
    }

    /// The (shape, baseline) pairs to enumerate, in a stable order. Numeric first
    /// (always present after the default fallback), then any harvested shapes.
    fn shapes(&self) -> Vec<(IdShape, String)> {
        let mut out = Vec::new();
        if let Some(n) = &self.numeric {
            out.push((IdShape::Numeric, n.clone()));
        }
        if let Some(u) = &self.uuid {
            out.push((IdShape::Uuid, u.clone()));
        }
        if let Some(u) = &self.username {
            out.push((IdShape::Username, u.clone()));
        }
        if let Some(e) = &self.email {
            out.push((IdShape::Email, e.clone()));
        }
        out
    }
}

/// What an object-reference point is: a path template carrying an `{id}`
/// placeholder, or a query parameter on an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PointKind {
    Path { template: String },
    Param { endpoint: String, param: String },
}

/// A reference point to enumerate: where the reference lives, the id-shape, the
/// baseline reference, and the alternative references to probe.
#[derive(Debug, Clone)]
struct ReferencePoint {
    kind: PointKind,
    shape: IdShape,
    baseline_ref: String,
    alternatives: Vec<String>,
}

/// The curated lists an [`IdorScanner`] runs with. Defaults are the inline
/// production lists; tests inject small deterministic ones via the builder.
#[derive(Debug, Clone)]
struct IdorConfig {
    self_endpoints: Vec<String>,
    path_templates: Vec<String>,
    param_endpoints: Vec<String>,
    param_names: Vec<String>,
}

impl IdorConfig {
    /// The full inline production lists.
    fn builtin() -> Self {
        Self {
            self_endpoints: SELF_ENDPOINTS.iter().map(|s| s.to_string()).collect(),
            path_templates: PATH_TEMPLATES.iter().map(|s| s.to_string()).collect(),
            param_endpoints: PARAM_ENDPOINTS.iter().map(|s| s.to_string()).collect(),
            param_names: PARAM_NAMES.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// An empty config (no probes). The builder opts in to specific lists.
    fn empty() -> Self {
        Self {
            self_endpoints: Vec::new(),
            path_templates: Vec::new(),
            param_endpoints: Vec::new(),
            param_names: Vec::new(),
        }
    }
}

/// Detects insecure direct object references by enumerating alternative object
/// references unauthenticated and comparing them to a baseline.
pub struct IdorScanner {
    config: IdorConfig,
}

impl Default for IdorScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl IdorScanner {
    /// The stable scanner id, exposed for registration and selection.
    pub const ID: &'static str = ID;

    /// Build a scanner with the full inline curated lists (the production
    /// constructor; see [`register`]).
    pub fn new() -> Self {
        Self {
            config: IdorConfig::builtin(),
        }
    }

    /// Start building a scanner with explicit, small lists — for deterministic
    /// tests and previews. Every list starts empty; set only what the test needs.
    pub fn builder() -> IdorScannerBuilder {
        IdorScannerBuilder {
            config: IdorConfig::empty(),
        }
    }
}

/// Builder for an [`IdorScanner`] with explicit lists.
pub struct IdorScannerBuilder {
    config: IdorConfig,
}

impl IdorScannerBuilder {
    /// Set the "self" endpoints probed to harvest identifiers.
    pub fn self_endpoints<I, S>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.self_endpoints = endpoints.into_iter().map(Into::into).collect();
        self
    }

    /// Set the object-reference path templates (each carrying an `{id}`).
    pub fn path_templates<I, S>(mut self, templates: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.path_templates = templates.into_iter().map(Into::into).collect();
        self
    }

    /// Set the query-parameter endpoints.
    pub fn param_endpoints<I, S>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.param_endpoints = endpoints.into_iter().map(Into::into).collect();
        self
    }

    /// Set the object-reference parameter names.
    pub fn param_names<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.param_names = names.into_iter().map(Into::into).collect();
        self
    }

    /// Finish building.
    pub fn build(self) -> IdorScanner {
        IdorScanner {
            config: self.config,
        }
    }
}

#[async_trait]
impl BaseScanner for IdorScanner {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "Insecure Direct Object Reference"
    }

    fn description(&self) -> &str {
        "Establishes a baseline object reference, then probes adjacent/alternative \
         references of the same shape (numeric neighbours, well-known UUIDs, common \
         usernames/emails) with any authorization credential stripped, reporting \
         references that return another object's data without authentication."
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        self.validate_target(target)?;
        let base = target.base_url().clone();

        // Phase 1: harvest baseline references from the caller's own objects, then
        // fall back to a default numeric baseline so enumeration can always proceed.
        let mut refs = References::default();
        for endpoint in &self.config.self_endpoints {
            if ctx.is_cancelled() {
                return Ok(Vec::new());
            }
            let url = match base.join(endpoint) {
                Ok(url) => url,
                Err(_) => continue,
            };
            match probe(ctx, url, false).await {
                Ok(response) if is_success(response.status) => {
                    harvest_from_body(&response.body, &mut refs);
                }
                Ok(_) => {}
                Err(Error::Cancelled) => return Ok(Vec::new()),
                Err(err) => {
                    tracing::warn!(
                        scanner = ID,
                        endpoint = %endpoint,
                        error = %err,
                        "harvest probe failed; continuing with the references gathered so far"
                    );
                    break;
                }
            }
        }
        if refs.numeric.is_none() {
            refs.numeric = Some("1".to_string());
        }

        // Build the candidate reference points (no network yet).
        let points = self.reference_points(target, &refs);

        // Phase 2: capture each point's baseline (credential kept), keeping only the
        // points whose baseline is a clean success — so the candidate total below
        // reflects the real, viable candidate count rather than a placeholder.
        let mut viable: Vec<(ReferencePoint, ProbeResponse)> = Vec::new();
        for point in points {
            if ctx.is_cancelled() {
                return Ok(Vec::new());
            }
            let url = match point_url(&base, &point.kind, &point.baseline_ref) {
                Some(url) => url,
                None => continue,
            };
            match probe(ctx, url, false).await {
                Ok(response) => {
                    if is_success(response.status) && !looks_like_error_page(&response) {
                        viable.push((point, response));
                    }
                }
                Err(Error::Cancelled) => return Ok(Vec::new()),
                Err(err) => {
                    tracing::warn!(
                        scanner = ID,
                        error = %err,
                        "baseline probe failed; stopping baseline capture and enumerating what is viable"
                    );
                    break;
                }
            }
        }

        // Phase 3: enumerate alternatives (credential stripped) against each viable
        // baseline, reporting tested/total against the now-known candidate count.
        let total: usize = viable.iter().map(|(p, _)| p.alternatives.len()).sum();
        let mut tested = 0usize;
        let mut findings = Vec::new();

        'outer: for (point, baseline) in &viable {
            for alt_ref in &point.alternatives {
                if ctx.is_cancelled() {
                    break 'outer;
                }
                let url = match point_url(&base, &point.kind, alt_ref) {
                    Some(url) => url,
                    None => {
                        // An unbuildable alternative URL still counts as tested so
                        // progress does not stall below the total.
                        tested += 1;
                        ctx.report_progress(progress(tested, total, alt_ref));
                        continue;
                    }
                };
                match probe(ctx, url.clone(), true).await {
                    Ok(response) => {
                        tested += 1;
                        if confirmed_idor(baseline, &response, &point.baseline_ref, alt_ref) {
                            findings.push(build_finding(
                                target,
                                point,
                                &point.baseline_ref,
                                alt_ref,
                                &url,
                                &response,
                            ));
                        }
                        ctx.report_progress(progress(tested, total, alt_ref));
                    }
                    Err(Error::Cancelled) => return Ok(findings),
                    Err(err) => {
                        tracing::warn!(
                            scanner = ID,
                            error = %err,
                            "enumeration probe failed; returning the findings gathered so far"
                        );
                        break 'outer;
                    }
                }
            }
        }

        Ok(findings)
    }
}

impl IdorScanner {
    /// Build the candidate reference points from the configured templates/params
    /// and the harvested baselines. Pure over its inputs (no network), so the whole
    /// candidate plan is unit-testable.
    fn reference_points(&self, target: &Target, refs: &References) -> Vec<ReferencePoint> {
        let mut points = Vec::new();

        // Path templates: the configured built-ins plus the target's own template.
        let mut templates: Vec<String> = self.config.path_templates.clone();
        if let Some(template) = target.id_template() {
            if !templates.iter().any(|t| t == template) {
                templates.push(template.to_string());
            }
        }
        for template in &templates {
            for (shape, baseline_ref) in refs.shapes() {
                let alternatives = neighbours(shape, &baseline_ref);
                if alternatives.is_empty() {
                    continue;
                }
                points.push(ReferencePoint {
                    kind: PointKind::Path {
                        template: template.clone(),
                    },
                    shape,
                    baseline_ref,
                    alternatives,
                });
            }
        }

        // Query parameters: a numeric `?param=1` baseline versus its neighbours.
        for endpoint in &self.config.param_endpoints {
            for param in &self.config.param_names {
                let baseline_ref = "1".to_string();
                let alternatives = neighbours(IdShape::Numeric, &baseline_ref);
                if alternatives.is_empty() {
                    continue;
                }
                points.push(ReferencePoint {
                    kind: PointKind::Param {
                        endpoint: endpoint.clone(),
                        param: param.clone(),
                    },
                    shape: IdShape::Numeric,
                    baseline_ref,
                    alternatives,
                });
            }
        }

        points
    }
}

/// Register the IDOR scanner under its stable id. It reads no seeded store (its
/// detection lists are inline heuristics), so the factory ignores the config.
pub fn register(registry: &mut ScannerRegistry) {
    let factory: ScannerFactory =
        Arc::new(|_config| Box::new(IdorScanner::new()) as Box<dyn BaseScanner>);
    registry.register(ID, factory);
}

/// Build a scanner-internal progress update naming the reference currently probed.
fn progress(tested: usize, total: usize, current: &str) -> ProgressUpdate {
    ProgressUpdate::new(ID, tested, total)
        .current_item(current.to_string())
        .message(format!("testing references {tested}/{total}"))
}

/// Resolve the concrete URL for a reference point at `value`: substitute a path
/// template's placeholder, or set a query parameter. `None` if the result does not
/// parse.
fn point_url(base: &Url, kind: &PointKind, value: &str) -> Option<Url> {
    match kind {
        PointKind::Path { template } => {
            let path = substitute_placeholder(template, value);
            base.join(&path).ok()
        }
        PointKind::Param { endpoint, param } => {
            let mut url = base.join(endpoint).ok()?;
            url.set_query(Some(&format!("{param}={value}")));
            Some(url)
        }
    }
}

/// Replace the first `{...}` placeholder in `template` with `value`. If there is no
/// placeholder the template is returned unchanged.
fn substitute_placeholder(template: &str, value: &str) -> String {
    match (template.find('{'), template.find('}')) {
        (Some(open), Some(close)) if close > open => {
            let mut out = String::with_capacity(template.len() + value.len());
            out.push_str(&template[..open]);
            out.push_str(value);
            out.push_str(&template[close + 1..]);
            out
        }
        _ => template.to_string(),
    }
}

/// Generate alternative references of `shape` around `baseline`, never including the
/// baseline itself.
fn neighbours(shape: IdShape, baseline: &str) -> Vec<String> {
    match shape {
        IdShape::Numeric => numeric_neighbours(baseline),
        IdShape::Uuid => fixed_neighbours(SENTINEL_UUIDS, baseline),
        IdShape::Username => fixed_neighbours(COMMON_USERNAMES, baseline),
        IdShape::Email => fixed_neighbours(COMMON_EMAILS, baseline),
    }
}

/// The few integers immediately around `baseline` (`N-1, N+1, N+2, N+3`), filtered
/// to positive values other than the baseline. Empty if the baseline is not an
/// integer.
fn numeric_neighbours(baseline: &str) -> Vec<String> {
    let n: i128 = match baseline.parse() {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for delta in [-1i128, 1, 2, 3] {
        let candidate = n + delta;
        if candidate > 0 && candidate != n {
            let s = candidate.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

/// The fixed alternatives in `pool` other than the baseline.
fn fixed_neighbours(pool: &[&str], baseline: &str) -> Vec<String> {
    pool.iter()
        .filter(|&&candidate| candidate != baseline)
        .map(|&s| s.to_string())
        .collect()
}

/// A probed response reduced to the fields evaluation needs.
#[derive(Debug, Clone)]
struct ProbeResponse {
    status: u16,
    body: Vec<u8>,
    /// Whether the body was capped at [`MAX_BODY_BYTES`].
    truncated: bool,
}

/// Probe one URL through the paced scan context, optionally with the credential
/// stripped, reducing the response to the fields evaluation needs. The body is
/// buffered through a bounded reader (at most [`MAX_BODY_BYTES`]).
async fn probe(ctx: &ScanContext, url: Url, strip_credential: bool) -> Result<ProbeResponse> {
    let mut spec = RequestSpec::get(url);
    if strip_credential {
        spec = spec.without_credential();
    }
    let mut response = ctx.send(spec).await?;
    let status = response.status().as_u16();

    let mut body = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::Http(e.to_string()))?
    {
        let remaining = MAX_BODY_BYTES.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }

    Ok(ProbeResponse {
        status,
        body,
        truncated,
    })
}

/// Whether a status is a 2xx success.
fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Confirm an IDOR: the alternative is a success, is not the baseline reference, is
/// not an error page, and differs materially from the baseline body.
fn confirmed_idor(
    baseline: &ProbeResponse,
    alt: &ProbeResponse,
    baseline_ref: &str,
    alt_ref: &str,
) -> bool {
    is_success(alt.status)
        && alt_ref != baseline_ref
        && !looks_like_error_page(alt)
        && differs_materially(&baseline.body, &alt.body)
}

/// Whether a 2xx body is a recognized not-found / error / access-denied page (a
/// soft error returned with a success status) that should not be reported as an
/// object exposure. The phrase scan is gated on a modest body length.
fn looks_like_error_page(response: &ProbeResponse) -> bool {
    const NEGATIVE_PHRASES: &[&str] = &[
        "not found",
        "no longer exists",
        "does not exist",
        "no such",
        "cannot be found",
        "resource not found",
        "unauthorized",
        "forbidden",
        "access denied",
        "permission denied",
        "not authorized",
        "bad request",
    ];

    if response.truncated || response.body.len() > ERROR_PAGE_MAX_BYTES {
        return false;
    }
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    NEGATIVE_PHRASES.iter().any(|p| lower.contains(p))
}

/// Whether two bodies differ *materially*: their whitespace-normalized lengths
/// differ by more than [`LENGTH_TOLERANCE`], OR (when both parse as JSON) their sets
/// of scalar leaf values differ. A body equal to the baseline counts as no
/// difference.
fn differs_materially(baseline: &[u8], alt: &[u8]) -> bool {
    let base_len = normalized_len(baseline);
    let alt_len = normalized_len(alt);
    let max = base_len.max(alt_len);
    if max > 0 {
        let diff = base_len.abs_diff(alt_len) as f64 / max as f64;
        if diff > LENGTH_TOLERANCE {
            return true;
        }
    }

    match (
        serde_json::from_slice::<Value>(baseline),
        serde_json::from_slice::<Value>(alt),
    ) {
        (Ok(base_json), Ok(alt_json)) => scalar_leaves(&base_json) != scalar_leaves(&alt_json),
        // Not both JSON and lengths within tolerance: treat as the same page (a
        // generic shell or the same object), not a material difference.
        _ => false,
    }
}

/// The whitespace-normalized length of a body: runs of whitespace collapsed to a
/// single space and trimmed, so trivial formatting differences do not register.
fn normalized_len(body: &[u8]) -> usize {
    String::from_utf8_lossy(body)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .len()
}

/// The set of scalar leaf values (strings, numbers, bools, null) in a JSON value,
/// tagged by kind so `1` (number) and `"1"` (string) do not collide.
fn scalar_leaves(value: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    collect_scalar_leaves(value, &mut out);
    out
}

fn collect_scalar_leaves(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Null => {
            out.insert("null".to_string());
        }
        Value::Bool(b) => {
            out.insert(format!("b:{b}"));
        }
        Value::Number(n) => {
            out.insert(format!("n:{n}"));
        }
        Value::String(s) => {
            out.insert(format!("s:{s}"));
        }
        Value::Array(items) => {
            for item in items {
                collect_scalar_leaves(item, out);
            }
        }
        Value::Object(map) => {
            for nested in map.values() {
                collect_scalar_leaves(nested, out);
            }
        }
    }
}

/// Classify the exposed-data class of a confirmed body and list the sensitive fields
/// detected. A body with no sensitive fields that still looks like a structured
/// record reads as user-shaped data (medium); otherwise low.
fn classify_body(response: &ProbeResponse) -> (DataClass, Vec<String>) {
    let mut class = DataClass::None;
    let mut fields: Vec<String> = Vec::new();

    if !response.truncated {
        let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        for (needle, needle_class, label) in SENSITIVE_FIELDS {
            if lower.contains(needle) {
                class = class.max(*needle_class);
                if !fields.iter().any(|f| f == label) {
                    fields.push(label.to_string());
                }
            }
        }
    }

    if class == DataClass::None && looks_like_record(&response.body) {
        class = DataClass::UserData;
    }

    (class, fields)
}

/// Whether a body parses as a JSON object or an array containing an object — a
/// structured record, as opposed to a scalar or empty shell.
fn looks_like_record(body: &[u8]) -> bool {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(map)) => !map.is_empty(),
        Ok(Value::Array(items)) => items.iter().any(|v| v.is_object()),
        _ => false,
    }
}

/// The severity for a confirmed IDOR given its exposed-data class.
fn severity_of(class: DataClass) -> Severity {
    match class {
        DataClass::Credentials => Severity::Critical,
        DataClass::Pii => Severity::High,
        DataClass::UserData => Severity::Medium,
        DataClass::None => Severity::Low,
    }
}

/// Keep at most [`SAMPLE_BYTES`] leading bytes of `body` as a UTF-8 lossy evidence
/// sample, never the whole (possibly large) body.
fn bounded_sample(body: &[u8]) -> String {
    let end = body.len().min(SAMPLE_BYTES);
    String::from_utf8_lossy(&body[..end]).to_string()
}

/// Build the [`Finding`] for a confirmed IDOR, carrying reproduction evidence: the
/// affected endpoint or parameter, the reference tried, the baseline reference, the
/// observed status, a bounded response sample, and the detected sensitive fields.
fn build_finding(
    target: &Target,
    point: &ReferencePoint,
    baseline_ref: &str,
    alt_ref: &str,
    url: &Url,
    response: &ProbeResponse,
) -> Finding {
    let (class, sensitive_fields) = classify_body(response);
    let severity = severity_of(class);

    let mut evidence = serde_json::json!({
        "url": url.as_str(),
        "id_shape": point.shape.label(),
        "reference_tried": alt_ref,
        "baseline_reference": baseline_ref,
        "status": response.status,
        "response_sample": bounded_sample(&response.body),
        "sensitive_fields": sensitive_fields,
        "data_class": class.label(),
        "body_length": response.body.len(),
        "body_truncated": response.truncated,
    });

    let (point_desc, title) = match &point.kind {
        PointKind::Path { template } => {
            evidence["object_reference_point"] = serde_json::json!(template);
            evidence["endpoint"] = serde_json::json!(url.path());
            evidence["template"] = serde_json::json!(template);
            (
                format!("endpoint {template}"),
                format!(
                    "Insecure direct object reference: {template} exposes another object's data"
                ),
            )
        }
        PointKind::Param { endpoint, param } => {
            let label = format!("parameter '{param}' at {endpoint}");
            evidence["object_reference_point"] = serde_json::json!(label);
            evidence["endpoint"] = serde_json::json!(endpoint);
            evidence["parameter"] = serde_json::json!(param);
            (
                label.clone(),
                format!("Insecure direct object reference: {label} exposes another object's data"),
            )
        }
    };

    let data_clause = match class {
        DataClass::Credentials => " and exposes credentials, secrets, or financial data",
        DataClass::Pii => " and exposes personally-identifiable information",
        DataClass::UserData => " and exposes another user's record",
        DataClass::None => "",
    };
    let description = format!(
        "Requesting {} (reference {alt_ref}, baseline {baseline_ref}) without any authorization \
         credential returned HTTP {}; the {point_desc} returns a different object's data than the \
         baseline reference does{data_clause}. An attacker can enumerate object references to read \
         data belonging to other users.",
        url.as_str(),
        response.status,
    );

    Finding::builder(ID, target.clone(), title)
        .status(Status::Vulnerable)
        .severity(severity)
        .description(description)
        .evidence(evidence)
        .recommendations(
            "Enforce object-level authorization server-side: every request for an object must \
             verify that the authenticated caller is permitted to access that specific object, \
             not merely that they are authenticated. Prefer unguessable identifiers and reject \
             references the caller does not own with 403/404.",
        )
        .build()
}

// --- Identifier harvesting --------------------------------------------------

/// Harvest identifiers from a response body into `refs`, JSON-aware with a
/// regex-free textual fallback for non-JSON bodies.
fn harvest_from_body(body: &[u8], refs: &mut References) {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        harvest_json(&value, refs);
    } else {
        harvest_text(&String::from_utf8_lossy(body), refs);
    }
}

/// Walk a JSON value: take scalar values under id-like keys as baselines of their
/// shape, and capture any distinctive (UUID/email) string value regardless of key.
fn harvest_json(value: &Value, refs: &mut References) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if let Some(scalar) = scalar_to_string(nested) {
                    if is_id_like_key(key) {
                        refs.store(&scalar);
                    } else {
                        refs.store_distinctive(&scalar);
                    }
                }
                harvest_json(nested, refs);
            }
        }
        Value::Array(items) => {
            for item in items {
                harvest_json(item, refs);
            }
        }
        _ => {}
    }
}

/// Scan free text for distinctive identifiers (UUIDs and emails). Bare integers and
/// words are too noisy to harvest from arbitrary text, so they are skipped.
fn harvest_text(text: &str, refs: &mut References) {
    for token in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                ',' | ';' | '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ':' | '\\'
            )
    }) {
        if is_uuid(token) || is_email(token) {
            refs.store_distinctive(token);
        }
    }
}

/// A scalar JSON value rendered as a string; `None` for arrays/objects/bool/null.
fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Whether a JSON key names an object identifier worth harvesting its value as a
/// baseline reference.
fn is_id_like_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower == "id"
        || lower.ends_with("_id")
        || lower == "uuid"
        || lower == "guid"
        || lower.contains("uuid")
        || lower == "userid"
        || lower == "username"
        || lower == "user"
        || lower == "login"
        || lower == "email"
        || lower.ends_with("email")
}

/// Classify the shape of an identifier value.
fn id_shape(value: &str) -> Option<IdShape> {
    if value.is_empty() {
        return None;
    }
    if is_uuid(value) {
        return Some(IdShape::Uuid);
    }
    if is_email(value) {
        return Some(IdShape::Email);
    }
    if value.bytes().all(|b| b.is_ascii_digit()) {
        return Some(IdShape::Numeric);
    }
    if is_username(value) {
        return Some(IdShape::Username);
    }
    None
}

/// Whether `value` is a canonical 8-4-4-4-12 hexadecimal UUID.
fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    if groups.len() != 5 {
        return false;
    }
    let expected = [8usize, 4, 4, 4, 12];
    groups
        .iter()
        .zip(expected.iter())
        .all(|(group, &len)| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Whether `value` looks like an email address: a non-empty local part, an `@`, and
/// a domain bearing an interior dot.
fn is_email(value: &str) -> bool {
    let at = match value.find('@') {
        Some(i) => i,
        None => return false,
    };
    let (local, domain) = value.split_at(at);
    let domain = &domain[1..];
    if local.is_empty() || domain.len() < 3 || domain.contains('@') {
        return false;
    }
    match domain.find('.') {
        Some(dot) => dot > 0 && dot < domain.len() - 1,
        None => false,
    }
}

/// Whether `value` is a plausible username: 1..=64 characters of alphanumerics,
/// `_`, `-`, or `.`, not purely numeric (that is the numeric shape).
fn is_username(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let ok = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    ok && !value.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    /// `content_type` is accepted for call-site readability (it labels what the
    /// body represents) but the IDOR comparator/classifier work off the body alone.
    fn resp(status: u16, _content_type: Option<&str>, body: &str) -> ProbeResponse {
        ProbeResponse {
            status,
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    // --- Metadata (tasks 1.1, 1.2) ---------------------------------------------

    #[test]
    fn metadata_is_stable() {
        let scanner = IdorScanner::new();
        assert_eq!(scanner.id(), "idor");
        assert_eq!(IdorScanner::ID, "idor");
        assert!(!scanner.name().is_empty());
        assert!(!scanner.description().is_empty());
    }

    // --- Shape detection -------------------------------------------------------

    #[test]
    fn id_shape_classifies_each_shape() {
        assert_eq!(id_shape("42"), Some(IdShape::Numeric));
        assert_eq!(
            id_shape("550e8400-e29b-41d4-a716-446655440000"),
            Some(IdShape::Uuid)
        );
        assert_eq!(id_shape("alice@example.com"), Some(IdShape::Email));
        assert_eq!(id_shape("alice"), Some(IdShape::Username));
        assert_eq!(id_shape("alice_99"), Some(IdShape::Username));
        assert_eq!(id_shape(""), None);
        // A space-bearing value is not a plausible single identifier.
        assert_eq!(id_shape("not an id"), None);
    }

    #[test]
    fn uuid_and_email_recognizers_are_strict() {
        assert!(is_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(!is_uuid("00000000-0000-0000-0000-00000000000")); // last group too short
        assert!(!is_uuid("zzzzzzzz-0000-0000-0000-000000000000")); // non-hex
        assert!(is_email("a@b.io"));
        assert!(!is_email("@b.io"));
        assert!(!is_email("a@bio"));
        assert!(!is_email("plain"));
    }

    // --- Neighbour generation per shape (task 5.1) -----------------------------

    #[test]
    fn numeric_neighbours_surround_the_baseline_excluding_it() {
        assert_eq!(numeric_neighbours("1"), vec!["2", "3", "4"]);
        assert_eq!(numeric_neighbours("42"), vec!["41", "43", "44", "45"]);
        // Non-numeric baseline yields nothing.
        assert!(numeric_neighbours("abc").is_empty());
    }

    #[test]
    fn fixed_neighbours_exclude_the_baseline() {
        let uuid_baseline = SENTINEL_UUIDS[0];
        let alts = neighbours(IdShape::Uuid, uuid_baseline);
        assert!(!alts.contains(&uuid_baseline.to_string()));
        assert_eq!(alts.len(), SENTINEL_UUIDS.len() - 1);

        let user_alts = neighbours(IdShape::Username, "admin");
        assert!(!user_alts.contains(&"admin".to_string()));
        assert!(user_alts.contains(&"root".to_string()));

        let email_alts = neighbours(IdShape::Email, "admin@example.com");
        assert!(!email_alts.contains(&"admin@example.com".to_string()));
        assert!(email_alts.contains(&"test@example.com".to_string()));
    }

    // --- Error / not-found classifier (task 4.1) -------------------------------

    #[test]
    fn error_classifier_flags_soft_errors_only() {
        assert!(looks_like_error_page(&resp(
            200,
            Some("application/json"),
            r#"{"error":"resource not found"}"#
        )));
        assert!(looks_like_error_page(&resp(
            200,
            Some("text/plain"),
            "Access denied"
        )));
        // A real record is not an error page.
        assert!(!looks_like_error_page(&resp(
            200,
            Some("application/json"),
            r#"{"id":2,"username":"bob","email":"bob@x.io"}"#
        )));
    }

    // --- Baseline-difference comparator (task 4.2) -----------------------------

    #[test]
    fn comparator_identical_bodies_do_not_differ() {
        let body = r#"{"id":1,"username":"alice","email":"alice@x.io"}"#;
        assert!(!differs_materially(body.as_bytes(), body.as_bytes()));
    }

    #[test]
    fn comparator_distinct_objects_differ_via_json_scalars() {
        // Same structure and near-identical length, but different scalar leaves.
        let baseline = r#"{"id":1,"username":"alice","email":"alice@x.io"}"#;
        let other = r#"{"id":2,"username":"bobby","email":"bobby@x.io"}"#;
        assert!(differs_materially(baseline.as_bytes(), other.as_bytes()));
    }

    #[test]
    fn comparator_large_length_gap_differs() {
        let baseline = r#"{"id":1}"#;
        let big = format!(r#"{{"id":2,"blob":"{}"}}"#, "x".repeat(200));
        assert!(differs_materially(baseline.as_bytes(), big.as_bytes()));
    }

    #[test]
    fn comparator_non_json_within_tolerance_does_not_differ() {
        // Two similar-length non-JSON bodies are treated as the same shell page.
        let a = "AAAAAAAAAAAAAAAAAAAA";
        let b = "AAAAAAAAAAAAAAAAAAAB";
        assert!(!differs_materially(a.as_bytes(), b.as_bytes()));
    }

    // --- Confirmation rules (task 4.3) -----------------------------------------

    #[test]
    fn confirmed_requires_success_difference_and_not_error() {
        let baseline = resp(200, Some("application/json"), r#"{"id":1,"name":"alice"}"#);
        let other = resp(200, Some("application/json"), r#"{"id":2,"name":"bob"}"#);
        assert!(confirmed_idor(&baseline, &other, "1", "2"));

        // Identical to baseline → not confirmed.
        let echo = resp(200, Some("application/json"), r#"{"id":1,"name":"alice"}"#);
        assert!(!confirmed_idor(&baseline, &echo, "1", "2"));

        // Error page → not confirmed.
        let not_found = resp(200, Some("application/json"), r#"{"error":"not found"}"#);
        assert!(!confirmed_idor(&baseline, &not_found, "1", "2"));

        // Non-2xx → not confirmed.
        let unauthorized = resp(401, Some("application/json"), r#"{"id":2,"name":"bob"}"#);
        assert!(!confirmed_idor(&baseline, &unauthorized, "1", "2"));

        // Same reference as baseline → not confirmed.
        assert!(!confirmed_idor(&baseline, &other, "2", "2"));
    }

    // --- Sensitive-field detection + severity (task 4.4) -----------------------

    #[test]
    fn severity_scales_with_exposed_data_class() {
        let creds = resp(
            200,
            Some("application/json"),
            r#"{"id":2,"username":"bob","password":"s3cret"}"#,
        );
        let (class, fields) = classify_body(&creds);
        assert_eq!(class, DataClass::Credentials);
        assert!(fields.iter().any(|f| f == "password"));
        assert_eq!(severity_of(class), Severity::Critical);

        let pii = resp(
            200,
            Some("application/json"),
            r#"{"id":2,"email":"bob@x.io","phone":"555-1234"}"#,
        );
        let (class, fields) = classify_body(&pii);
        assert_eq!(class, DataClass::Pii);
        assert!(fields.iter().any(|f| f == "email"));
        assert_eq!(severity_of(class), Severity::High);

        let user = resp(200, Some("application/json"), r#"{"id":2,"role":"member"}"#);
        let (class, _fields) = classify_body(&user);
        assert_eq!(class, DataClass::UserData);
        assert_eq!(severity_of(class), Severity::Medium);

        let plain = resp(200, Some("text/plain"), "2");
        let (class, _fields) = classify_body(&plain);
        assert_eq!(class, DataClass::None);
        assert_eq!(severity_of(class), Severity::Low);
    }

    // --- Identifier harvesting (task 2.2) --------------------------------------

    #[test]
    fn harvests_identifiers_by_shape_from_json() {
        let body = r#"{
            "id": 42,
            "username": "alice",
            "email": "alice@example.com",
            "account_uuid": "550e8400-e29b-41d4-a716-446655440000",
            "role": "user"
        }"#;
        let mut refs = References::default();
        harvest_from_body(body.as_bytes(), &mut refs);
        assert_eq!(refs.numeric.as_deref(), Some("42"));
        assert_eq!(refs.username.as_deref(), Some("alice"));
        assert_eq!(refs.email.as_deref(), Some("alice@example.com"));
        assert_eq!(
            refs.uuid.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn harvest_text_fallback_takes_distinctive_tokens_only() {
        let mut refs = References::default();
        harvest_from_body(
            b"contact admin@example.com ref 550e8400-e29b-41d4-a716-446655440000 count 999",
            &mut refs,
        );
        assert_eq!(refs.email.as_deref(), Some("admin@example.com"));
        assert_eq!(
            refs.uuid.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        // A bare integer in free text is too noisy to adopt as a numeric baseline.
        assert!(refs.numeric.is_none());
    }

    // --- Reference-point planning + default baseline (tasks 2.1, 2.3, 3.1) -----

    #[test]
    fn default_numeric_baseline_when_nothing_harvested() {
        let mut refs = References::default();
        if refs.numeric.is_none() {
            refs.numeric = Some("1".to_string());
        }
        let shapes = refs.shapes();
        assert_eq!(shapes, vec![(IdShape::Numeric, "1".to_string())]);
    }

    #[test]
    fn reference_points_cover_templates_target_and_params() {
        let scanner = IdorScanner::builder()
            .path_templates(["/api/users/{id}"])
            .param_endpoints(["/api/user"])
            .param_names(["id"])
            .build();
        let target = Target::parse("https://example.com")
            .unwrap()
            .with_id_template("/api/widgets/{id}");
        let refs = References {
            numeric: Some("1".to_string()),
            ..Default::default()
        };

        let points = scanner.reference_points(&target, &refs);
        // The built-in template, the target's own template, and the param point.
        let path_points: Vec<&ReferencePoint> = points
            .iter()
            .filter(|p| matches!(p.kind, PointKind::Path { .. }))
            .collect();
        assert_eq!(path_points.len(), 2);
        assert!(points.iter().any(|p| matches!(
            &p.kind,
            PointKind::Path { template } if template == "/api/widgets/{id}"
        )));
        assert!(points.iter().any(|p| matches!(
            &p.kind,
            PointKind::Param { endpoint, param } if endpoint == "/api/user" && param == "id"
        )));
        // Every point has alternatives that exclude the baseline.
        for point in &points {
            assert!(!point.alternatives.is_empty());
            assert!(!point.alternatives.contains(&point.baseline_ref));
        }
    }

    #[test]
    fn point_url_substitutes_paths_and_sets_query() {
        let base = Url::parse("https://example.com").unwrap();
        let path = point_url(
            &base,
            &PointKind::Path {
                template: "/api/users/{id}".to_string(),
            },
            "7",
        )
        .unwrap();
        assert_eq!(path.as_str(), "https://example.com/api/users/7");

        let param = point_url(
            &base,
            &PointKind::Param {
                endpoint: "/api/user".to_string(),
                param: "id".to_string(),
            },
            "7",
        )
        .unwrap();
        assert_eq!(param.as_str(), "https://example.com/api/user?id=7");
    }

    // --- Finding construction (task 4.5) ---------------------------------------

    #[test]
    fn finding_carries_full_evidence() {
        let point = ReferencePoint {
            kind: PointKind::Path {
                template: "/api/users/{id}".to_string(),
            },
            shape: IdShape::Numeric,
            baseline_ref: "1".to_string(),
            alternatives: vec!["2".to_string()],
        };
        let response = resp(
            200,
            Some("application/json"),
            r#"{"id":2,"username":"bob","password":"s3cret"}"#,
        );
        let url = Url::parse("https://example.com/api/users/2").unwrap();
        let finding = build_finding(&target(), &point, "1", "2", &url, &response);

        assert_eq!(finding.scanner_id, "idor");
        assert_eq!(finding.status, Status::Vulnerable);
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.description.is_some());
        assert!(finding.recommendations.is_some());

        let evidence = finding.evidence.unwrap();
        assert_eq!(evidence["endpoint"], "/api/users/2");
        assert_eq!(evidence["template"], "/api/users/{id}");
        assert_eq!(evidence["reference_tried"], "2");
        assert_eq!(evidence["baseline_reference"], "1");
        assert_eq!(evidence["status"], 200);
        assert_eq!(evidence["id_shape"], "numeric");
        assert_eq!(evidence["data_class"], "credentials");
        assert!(evidence["sensitive_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "password"));
        assert!(evidence["response_sample"]
            .as_str()
            .unwrap()
            .contains("bob"));
    }

    #[test]
    fn param_finding_records_the_parameter() {
        let point = ReferencePoint {
            kind: PointKind::Param {
                endpoint: "/api/user".to_string(),
                param: "id".to_string(),
            },
            shape: IdShape::Numeric,
            baseline_ref: "1".to_string(),
            alternatives: vec!["2".to_string()],
        };
        let response = resp(200, Some("application/json"), r#"{"id":2,"role":"member"}"#);
        let url = Url::parse("https://example.com/api/user?id=2").unwrap();
        let finding = build_finding(&target(), &point, "1", "2", &url, &response);
        let evidence = finding.evidence.unwrap();
        assert_eq!(evidence["parameter"], "id");
        assert_eq!(evidence["endpoint"], "/api/user");
        assert_eq!(evidence["reference_tried"], "2");
    }

    #[test]
    fn bounded_sample_caps_length() {
        let big = "A".repeat(SAMPLE_BYTES * 4);
        assert_eq!(bounded_sample(big.as_bytes()).len(), SAMPLE_BYTES);
        assert_eq!(bounded_sample(b"short"), "short");
    }
}
