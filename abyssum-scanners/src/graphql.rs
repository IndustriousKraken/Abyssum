//! GraphQL scanner.
//!
//! [`GraphqlScanner`] locates a target's GraphQL endpoint among a curated set of
//! common paths, then probes that one endpoint for the GraphQL-specific exposures
//! the v1 scanner covered: an open **introspection** interface (which hands an
//! attacker the full schema), acceptance of an **unbounded-depth** query, **query
//! batching**, and **information disclosure** from sensitive-data queries. Each
//! exposure it confirms is reported as its own [`Finding`].
//!
//! Like every scanner it owns none of the cross-cutting concerns: every request —
//! both the detection probes and the exposure checks — goes through
//! [`ScanContext::send`], so pacing, the rotating User-Agent, cancellation, and
//! progress all apply uniformly and the stealth floor cannot be bypassed. There is
//! no raw HTTP client here.
//!
//! ## The two phases
//!
//! 1. **Detect** — for each candidate path (from the seeded `graphql_paths` list,
//!    or a built-in fallback), probe with a GET, then a POST of `{ __typename }`,
//!    and classify the response shape ([`looks_like_graphql`]). The first path that
//!    looks like GraphQL is the endpoint; detection stops there.
//! 2. **Probe** — against that one endpoint: an introspection query (schema data ⇒
//!    a finding, with the extracted schema attached as evidence), a deeply nested
//!    query (unbounded depth), a batched array of queries (batching), and each
//!    seeded sensitive-data query (information disclosure). If no endpoint is
//!    detected the scan completes with no findings.
//!
//! ## Severity
//!
//! Per-finding, from the canonical [`Severity`] set: introspection enabled → high;
//! disclosure of `password`/`token`/`secret` or an admin query → critical; user
//! data, e-mail values, or token-like values → high; other sensitive data,
//! unbounded depth, and batching → medium. There is no scan-level severity field;
//! the "overall" level a surface shows is the maximum across the findings
//! ([`overall_severity`]).

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::CONTENT_TYPE;
use serde_json::Value;
use url::Url;

use abyssum_core::{
    BaseScanner, Error, Finding, Method, ProgressUpdate, ReferenceStore, RequestSpec, Result,
    ScanContext, ScannerFactory, ScannerRegistry, Severity, Status, Target,
};

/// The stable scanner id. The registry keys on this and a scan selects by it; it
/// must never change.
const ID: &str = "graphql";

/// The seeded wordlist of candidate GraphQL endpoint paths, loaded once per scan
/// run. `add-seed-data` ships `graphql_paths`; an absent list falls back to
/// [`DEFAULT_PATHS`].
const WORDLIST_GRAPHQL_PATHS: &str = "graphql_paths";

/// The seeded, *labeled* list of probe queries: the introspection query plus the
/// sensitive-data queries, each carrying a human label and a query body.
const WORDLIST_GRAPHQL_QUERIES: &str = "graphql_queries";

/// The built-in candidate paths used when the seeded `graphql_paths` list is absent
/// or empty. Mirrors the v1 fallback.
const DEFAULT_PATHS: &[&str] = &[
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graph",
    "/query",
];

/// The detection POST body: the smallest valid query, answered by any GraphQL
/// server. Sent after the GET probe.
const TYPENAME_PROBE: &str = "{ __typename }";

/// A deeply nested query used to test for an unbounded query-depth limit. It nests
/// the recursive `ofType` introspection field several levels deep — a server that
/// imposes no depth limit resolves it and answers with non-empty `data`. (Like the
/// v1 probe, this rides the introspection schema, so it can only confirm depth on a
/// server that also answers introspection; that is a deliberate, documented bound.)
const DEPTH_PROBE_QUERY: &str = "query DepthProbe { __schema { types { ofType { ofType \
     { ofType { ofType { ofType { name } } } } } } } }";

/// The queries sent as a single batched array to test for query batching. A server
/// with batching enabled answers with an array of the same length.
const BATCH_PROBE: &[&str] = &["{ __typename }", "{ __typename }"];

/// A built-in introspection query used when the seeded query list carries none.
const BUILTIN_INTROSPECTION_QUERY: &str = "query IntrospectionQuery { __schema { \
     queryType { name } mutationType { name } types { name kind fields { name } } } }";

/// Upper bound on the response body buffered per probe. A probed endpoint is
/// untrusted and could stream an unbounded body, so the scanner never reads a whole
/// body into memory: bytes beyond this cap are dropped and the response is flagged
/// `truncated`.
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// How many leading bytes of the response body to keep as the bounded evidence
/// sample (UTF-8 lossy). Enough to recognize the exposure, never the whole body.
const SAMPLE_BYTES: usize = 512;

/// Type-name keywords that mark an introspected type as sensitive (case-insensitive
/// substring match). A tunable default; the observable contract is "types whose
/// names suggest sensitive data are flagged".
const SENSITIVE_TYPE_KEYWORDS: &[&str] = &[
    "user", "admin", "password", "token", "secret", "key", "auth",
];

/// Field-name fragments that, when present in disclosed data, mark a credential leak
/// (the most severe class). Matched case-insensitively as substrings of the key.
const CREDENTIAL_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
    "credential",
];

/// Field-name fragments that mark disclosed *user data* (high). Matched
/// case-insensitively as substrings of the key.
const USER_DATA_FIELDS: &[&str] = &[
    "email",
    "username",
    "user",
    "firstname",
    "lastname",
    "fullname",
    "phone",
];

/// Field-name fragments that mark *other* sensitive data (medium). Matched
/// case-insensitively as substrings of the key.
const OTHER_SENSITIVE_FIELDS: &[&str] = &[
    "ssn",
    "social_security",
    "credit_card",
    "creditcard",
    "card_number",
    "date_of_birth",
    "dob",
    "iban",
];

/// The class of data a sensitive-data query disclosed, ordered least to most
/// sensitive so the overall class is the maximum over the signals seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DataClass {
    /// No sensitive content disclosed.
    None,
    /// Other sensitive data (PII fragments without credentials or user records).
    Sensitive,
    /// User records, e-mail values, or token-like values.
    UserData,
    /// Credentials, secrets, or tokens.
    Credentials,
}

impl DataClass {
    fn label(self) -> &'static str {
        match self {
            DataClass::None => "none",
            DataClass::Sensitive => "sensitive",
            DataClass::UserData => "user_data",
            DataClass::Credentials => "credentials",
        }
    }
}

/// The severity for a disclosed-data class (the `None` floor is never built into a
/// finding — a `None` disclosure is simply not reported).
fn severity_of(class: DataClass) -> Severity {
    match class {
        DataClass::Credentials => Severity::Critical,
        DataClass::UserData => Severity::High,
        DataClass::Sensitive => Severity::Medium,
        DataClass::None => Severity::Info,
    }
}

/// The outcome of analyzing a disclosed `data` payload: its overall class plus the
/// human-facing signal labels observed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Disclosure {
    class: DataClass,
    signals: Vec<String>,
}

/// Schema evidence extracted from an introspection response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaEvidence {
    /// Number of types the schema defines.
    types_count: usize,
    /// Field names on the query root type.
    query_fields: Vec<String>,
    /// Field names on the mutation root type.
    mutation_fields: Vec<String>,
    /// Type names whose names suggest sensitive data.
    sensitive_types: Vec<String>,
}

/// A named probe query: a human label plus the query body to send.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedQuery {
    label: String,
    body: String,
}

/// Where a [`GraphqlScanner`] draws its paths and queries.
enum DataSource {
    /// The seeded reference-data store: both lists loaded once per scan run.
    Store(ReferenceStore),
    /// Fixed in-memory lists (constructed directly; primarily for tests).
    Fixed {
        paths: Vec<String>,
        queries: Vec<NamedQuery>,
    },
}

/// Locates a GraphQL endpoint and probes it for introspection, unbounded query
/// depth, query batching, and sensitive-data disclosure.
pub struct GraphqlScanner {
    source: DataSource,
}

impl GraphqlScanner {
    /// The stable scanner id, exposed for registration and selection.
    pub const ID: &'static str = ID;

    /// Build a scanner that loads its path and query lists from the seeded
    /// reference-data store (the production constructor; see [`register`]).
    pub fn new(store: ReferenceStore) -> Self {
        Self {
            source: DataSource::Store(store),
        }
    }

    /// Build a scanner over fixed, in-memory lists — for deterministic tests and
    /// previews. Paths are normalized (one leading slash) and deduped; queries are
    /// `(label, body)` pairs.
    pub fn with_lists<P, S, Q, L, B>(paths: P, queries: Q) -> Self
    where
        P: IntoIterator<Item = S>,
        S: Into<String>,
        Q: IntoIterator<Item = (L, B)>,
        L: Into<String>,
        B: Into<String>,
    {
        Self {
            source: DataSource::Fixed {
                paths: paths.into_iter().map(Into::into).collect(),
                queries: queries
                    .into_iter()
                    .map(|(label, body)| NamedQuery {
                        label: label.into(),
                        body: body.into(),
                    })
                    .collect(),
            },
        }
    }

    /// The deduped, leading-slash-normalized candidate paths for this scan run,
    /// falling back to [`DEFAULT_PATHS`] when no list is seeded. Exposed so a
    /// surface can preview what would be probed.
    pub async fn candidate_paths(&self) -> Result<Vec<String>> {
        let raw = match &self.source {
            DataSource::Fixed { paths, .. } => paths.clone(),
            DataSource::Store(store) => store.wordlist_values(WORDLIST_GRAPHQL_PATHS).await?,
        };
        Ok(normalize_paths(raw))
    }

    /// The probe queries (label + body) for this scan run, in seeded order.
    pub async fn candidate_queries(&self) -> Result<Vec<(String, String)>> {
        Ok(self
            .load_queries()
            .await?
            .into_iter()
            .map(|q| (q.label, q.body))
            .collect())
    }

    /// Load the labeled query list (store or fixed), normalizing each entry to a
    /// [`NamedQuery`]. A store entry with no label keeps an empty label.
    async fn load_queries(&self) -> Result<Vec<NamedQuery>> {
        match &self.source {
            DataSource::Fixed { queries, .. } => Ok(queries.clone()),
            DataSource::Store(store) => {
                let entries = store.wordlist(WORDLIST_GRAPHQL_QUERIES).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| NamedQuery {
                        label: e.label.unwrap_or_default(),
                        body: e.value,
                    })
                    .collect())
            }
        }
    }
}

#[async_trait]
impl BaseScanner for GraphqlScanner {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "GraphQL"
    }

    fn description(&self) -> &str {
        "Locates a GraphQL endpoint among common paths, then checks it for an open \
         introspection interface (extracting the exposed schema), acceptance of \
         unbounded query nesting, query batching, and information disclosure from \
         sensitive-data queries — each reported as its own finding."
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        self.validate_target(target)?;

        // Load both lists once per run (task 2.3). Paths are normalized; the query
        // list keeps its labels so the introspection query can be selected by name.
        let paths = self.candidate_paths().await?;
        let queries = self.load_queries().await?;
        let base = target.base_url().clone();

        let mut findings = Vec::new();

        // --- Phase 1: detect a GraphQL endpoint ---------------------------------
        let total_paths = paths.len();
        let mut endpoint: Option<Url> = None;
        for (index, path) in paths.iter().enumerate() {
            if ctx.is_cancelled() {
                return Ok(findings);
            }
            let url = match base.join(path) {
                Ok(url) => url,
                Err(_) => {
                    ctx.report_progress(detect_progress(index + 1, total_paths, path));
                    continue;
                }
            };

            // GET first, then a POST of `{ __typename }`.
            match self.detect(ctx, &url).await {
                Ok(true) => {
                    endpoint = Some(url);
                    ctx.report_progress(detect_progress(index + 1, total_paths, path));
                    break;
                }
                Ok(false) => {}
                Err(Error::Cancelled) => return Ok(findings),
                Err(err) => {
                    tracing::warn!(
                        scanner = ID,
                        path = %path,
                        error = %err,
                        "detection probe failed; stopping and returning what was found"
                    );
                    return Ok(findings);
                }
            }

            ctx.report_progress(detect_progress(index + 1, total_paths, path));
        }

        let endpoint = match endpoint {
            Some(url) => url,
            // No GraphQL endpoint present (spec scenario): no findings.
            None => return Ok(findings),
        };

        // --- Phase 2: probe the detected endpoint -------------------------------
        let sensitive: Vec<&NamedQuery> = queries
            .iter()
            .filter(|q| !is_introspection_query(q))
            .collect();
        // Three structural checks (introspection, depth, batching) + one per
        // sensitive-data query.
        let total_checks = 3 + sensitive.len();
        let mut done = 0usize;

        // Introspection (tasks 4.x).
        if ctx.is_cancelled() {
            return Ok(findings);
        }
        let intro_query = introspection_query(&queries);
        match self.probe_query(ctx, &endpoint, &intro_query).await {
            Ok(resp) => {
                if resp.status == 200 {
                    if let Some(evidence) = extract_schema(&resp.body) {
                        findings.push(build_introspection_finding(
                            target, &endpoint, &evidence, &resp,
                        ));
                    }
                }
                done += 1;
                ctx.report_progress(check_progress(done, total_checks, "introspection"));
            }
            Err(Error::Cancelled) => return Ok(findings),
            Err(err) => {
                tracing::warn!(scanner = ID, error = %err, "introspection probe failed");
                return Ok(findings);
            }
        }

        // Unbounded query depth (task 5.1).
        if ctx.is_cancelled() {
            return Ok(findings);
        }
        match self.probe_query(ctx, &endpoint, DEPTH_PROBE_QUERY).await {
            Ok(resp) => {
                if resp.status == 200 && has_non_empty_data(&resp.body) {
                    findings.push(build_depth_finding(target, &endpoint, &resp));
                }
                done += 1;
                ctx.report_progress(check_progress(done, total_checks, "query_depth"));
            }
            Err(Error::Cancelled) => return Ok(findings),
            Err(err) => {
                tracing::warn!(scanner = ID, error = %err, "depth probe failed");
                return Ok(findings);
            }
        }

        // Query batching (task 5.2).
        if ctx.is_cancelled() {
            return Ok(findings);
        }
        match self.probe_raw(ctx, &endpoint, batch_body()).await {
            Ok(resp) => {
                if resp.status == 200 {
                    if let Some(len) = batch_response_len(&resp.body) {
                        if len == BATCH_PROBE.len() {
                            findings.push(build_batching_finding(target, &endpoint, len, &resp));
                        }
                    }
                }
                done += 1;
                ctx.report_progress(check_progress(done, total_checks, "batching"));
            }
            Err(Error::Cancelled) => return Ok(findings),
            Err(err) => {
                tracing::warn!(scanner = ID, error = %err, "batching probe failed");
                return Ok(findings);
            }
        }

        // Sensitive-data disclosure (task 5.3): one probe per sensitive query.
        for query in &sensitive {
            if ctx.is_cancelled() {
                return Ok(findings);
            }
            match self.probe_query(ctx, &endpoint, &query.body).await {
                Ok(resp) => {
                    if resp.status == 200 {
                        if let Some(data) = response_data(&resp.body) {
                            let disclosure = analyze_disclosure(&data);
                            if disclosure.class != DataClass::None {
                                findings.push(build_disclosure_finding(
                                    target,
                                    &endpoint,
                                    &query.label,
                                    &disclosure,
                                    &resp,
                                ));
                            }
                        }
                    }
                    done += 1;
                    ctx.report_progress(check_progress(done, total_checks, &query.label));
                }
                Err(Error::Cancelled) => return Ok(findings),
                Err(err) => {
                    tracing::warn!(
                        scanner = ID,
                        query = %query.label,
                        error = %err,
                        "disclosure probe failed; returning findings gathered so far"
                    );
                    return Ok(findings);
                }
            }
        }

        Ok(findings)
    }
}

impl GraphqlScanner {
    /// Probe `url` for GraphQL: a GET, then (if that does not look like GraphQL) a
    /// POST of `{ __typename }`. Returns whether either response looks like GraphQL.
    async fn detect(&self, ctx: &ScanContext, url: &Url) -> Result<bool> {
        let get = self.probe(ctx, RequestSpec::get(url.clone())).await?;
        if looks_like_graphql(get.status, get.content_type.as_deref(), &get.body) {
            return Ok(true);
        }
        if ctx.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let post = self
            .probe(ctx, post_query_spec(url.clone(), TYPENAME_PROBE))
            .await?;
        Ok(looks_like_graphql(
            post.status,
            post.content_type.as_deref(),
            &post.body,
        ))
    }

    /// POST a single `{"query": ...}` body to the endpoint, paced through the
    /// context.
    async fn probe_query(
        &self,
        ctx: &ScanContext,
        url: &Url,
        query: &str,
    ) -> Result<ProbeResponse> {
        self.probe(ctx, post_query_spec(url.clone(), query)).await
    }

    /// POST a raw JSON body (e.g. a batched array) to the endpoint.
    async fn probe_raw(
        &self,
        ctx: &ScanContext,
        url: &Url,
        body: Vec<u8>,
    ) -> Result<ProbeResponse> {
        self.probe(ctx, post_json_spec(url.clone(), body)).await
    }

    /// Send one request through the paced scan context and reduce the response to
    /// the fields the checks need, buffering at most [`MAX_BODY_BYTES`].
    async fn probe(&self, ctx: &ScanContext, spec: RequestSpec) -> Result<ProbeResponse> {
        let mut response = ctx.send(spec).await?;
        let status = response.status().as_u16();
        let content_type = header_str(&response, CONTENT_TYPE);

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
            content_type,
            body,
            truncated,
        })
    }
}

/// Register the GraphQL scanner under its stable id, baking in the seeded store the
/// factory cannot otherwise reach (the registry only hands factories a `Config`).
pub fn register(registry: &mut ScannerRegistry, store: &ReferenceStore) {
    let store = store.clone();
    let factory: ScannerFactory = Arc::new(move |_config| {
        Box::new(GraphqlScanner::new(store.clone())) as Box<dyn BaseScanner>
    });
    registry.register(ID, factory);
}

/// The maximum severity across `findings`, or `None` for an empty set. There is no
/// stored scan-level severity (see the change's design); this is the presentation
/// rollup a surface shows.
pub fn overall_severity(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

// --- Request specs ----------------------------------------------------------

/// A `{"query": ...}` POST spec with a JSON content type.
fn post_query_spec(url: Url, query: &str) -> RequestSpec {
    post_json_spec(url, query_body(query))
}

/// A POST spec carrying a raw JSON `body` with a JSON content type.
fn post_json_spec(url: Url, body: Vec<u8>) -> RequestSpec {
    RequestSpec::new(Method::POST, url)
        .header("content-type", "application/json")
        .body(body)
}

/// Serialize a query string into a `{"query": ...}` request body.
fn query_body(query: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "query": query })).unwrap_or_default()
}

/// The batched request body: the [`BATCH_PROBE`] queries as a JSON array.
fn batch_body() -> Vec<u8> {
    let arr: Vec<Value> = BATCH_PROBE
        .iter()
        .map(|q| serde_json::json!({ "query": q }))
        .collect();
    serde_json::to_vec(&Value::Array(arr)).unwrap_or_default()
}

// --- Progress ---------------------------------------------------------------

/// A detection-phase progress update (`tested / total` candidate paths).
fn detect_progress(completed: usize, total: usize, path: &str) -> ProgressUpdate {
    ProgressUpdate::new(ID, completed, total)
        .current_item(path.to_string())
        .message(format!("detecting GraphQL endpoint {completed}/{total}"))
}

/// An exposure-check progress update (`done / total` checks).
fn check_progress(done: usize, total: usize, check: &str) -> ProgressUpdate {
    ProgressUpdate::new(ID, done, total)
        .current_item(check.to_string())
        .message(format!("checking exposures {done}/{total}"))
}

// --- Path / query selection -------------------------------------------------

/// Merge raw path entries into deduped candidates with exactly one leading slash,
/// falling back to [`DEFAULT_PATHS`] when nothing remains. Order is preserved
/// (first occurrence wins); blank entries are dropped.
fn normalize_paths<I, S>(raw: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in raw {
        let trimmed = entry.as_ref().trim();
        if trimmed.is_empty() {
            continue;
        }
        let path = format!("/{}", trimmed.trim_start_matches('/'));
        if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    if out.is_empty() {
        out = DEFAULT_PATHS.iter().map(|s| s.to_string()).collect();
    }
    out
}

/// Whether a named query is the introspection query (so it is selected for the
/// introspection check and excluded from the disclosure probes).
fn is_introspection_query(query: &NamedQuery) -> bool {
    query.label.to_ascii_lowercase().contains("introspection") || query.body.contains("__schema")
}

/// Select the introspection query body: the entry labeled "introspection", else the
/// first whose body references `__schema`, else the built-in fallback.
fn introspection_query(queries: &[NamedQuery]) -> String {
    queries
        .iter()
        .find(|q| q.label.to_ascii_lowercase().contains("introspection"))
        .or_else(|| queries.iter().find(|q| q.body.contains("__schema")))
        .map(|q| q.body.clone())
        .unwrap_or_else(|| BUILTIN_INTROSPECTION_QUERY.to_string())
}

// --- Detection --------------------------------------------------------------

/// A probed response reduced to the fields the checks need.
#[derive(Debug, Clone)]
struct ProbeResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
    /// Whether the body was capped at [`MAX_BODY_BYTES`].
    truncated: bool,
}

/// Whether a response looks like a GraphQL endpoint. Pure over its inputs, so the
/// whole detector is unit-testable. A response is GraphQL when:
///
/// - its content type names GraphQL; or
/// - it has a recognized status and a JSON body carrying a `data`/`errors` key or a
///   GraphQL-shaped error `message`; or
/// - its body text carries a strong GraphQL signal (`graphql`, `__schema`,
///   `__type`, `__typename`).
///
/// The bare words `query`/`mutation` are intentionally **not** treated as standalone
/// body signals: they are common enough in unrelated content to false-positive, and
/// any real GraphQL response is already caught by the JSON envelope or the strong
/// signals above.
fn looks_like_graphql(status: u16, content_type: Option<&str>, body: &[u8]) -> bool {
    if let Some(ct) = content_type {
        if ct.to_ascii_lowercase().contains("graphql") {
            return true;
        }
    }

    const GRAPHQL_STATUSES: &[u16] = &[200, 400, 401, 403, 405, 501];
    if GRAPHQL_STATUSES.contains(&status) {
        if let Ok(value) = serde_json::from_slice::<Value>(body) {
            if value.get("data").is_some() || value.get("errors").is_some() {
                return true;
            }
            if let Some(message) = value.get("message").and_then(|m| m.as_str()) {
                if mentions_graphql_error(message) {
                    return true;
                }
            }
            if let Some(errors) = value.get("errors").and_then(|e| e.as_array()) {
                if errors.iter().any(|e| {
                    e.get("message")
                        .and_then(|m| m.as_str())
                        .map(mentions_graphql_error)
                        .unwrap_or(false)
                }) {
                    return true;
                }
            }
        }
    }

    const SIGNALS: &[&str] = &["graphql", "__schema", "__type", "__typename"];
    let lower = String::from_utf8_lossy(body).to_ascii_lowercase();
    SIGNALS.iter().any(|s| lower.contains(s))
}

/// Whether a (JSON error) message reads like a GraphQL parse/validation error.
fn mentions_graphql_error(message: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "graphql",
        "query",
        "syntax",
        "field",
        "type",
        "must provide",
    ];
    let lower = message.to_ascii_lowercase();
    KEYWORDS.iter().any(|k| lower.contains(k))
}

// --- Schema extraction ------------------------------------------------------

/// Extract schema evidence from an introspection response body. Returns `None`
/// unless the body carries `data.__schema` as an object (the discriminator for
/// "schema data returned").
fn extract_schema(body: &[u8]) -> Option<SchemaEvidence> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let schema = value.get("data")?.get("__schema")?;
    if !schema.is_object() {
        return None;
    }

    let types = schema.get("types").and_then(|t| t.as_array());
    let types_count = types.map(|t| t.len()).unwrap_or(0);

    let query_type_name = root_type_name(schema, "queryType");
    let mutation_type_name = root_type_name(schema, "mutationType");

    Some(SchemaEvidence {
        types_count,
        query_fields: type_field_names(types, query_type_name.as_deref()),
        mutation_fields: type_field_names(types, mutation_type_name.as_deref()),
        sensitive_types: sensitive_type_names(types),
    })
}

/// The `name` of a root type (`queryType` / `mutationType`) on a `__schema` object.
fn root_type_name(schema: &Value, key: &str) -> Option<String> {
    schema
        .get(key)
        .and_then(|t| t.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from)
}

/// The field names of the type named `type_name` within `types`.
fn type_field_names(types: Option<&Vec<Value>>, type_name: Option<&str>) -> Vec<String> {
    let (types, name) = match (types, type_name) {
        (Some(types), Some(name)) => (types, name),
        _ => return Vec::new(),
    };
    types
        .iter()
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(name))
        .and_then(|t| t.get("fields"))
        .and_then(|f| f.as_array())
        .map(|fields| {
            fields
                .iter()
                .filter_map(|f| f.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// The names of types whose names suggest sensitive data.
fn sensitive_type_names(types: Option<&Vec<Value>>) -> Vec<String> {
    let types = match types {
        Some(types) => types,
        None => return Vec::new(),
    };
    types
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .filter(|name| is_sensitive_type_name(name))
        .map(String::from)
        .collect()
}

/// Whether a type name matches a sensitive keyword (case-insensitive substring).
fn is_sensitive_type_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_TYPE_KEYWORDS.iter().any(|k| lower.contains(k))
}

// --- Data-shape predicates --------------------------------------------------

/// Whether a response body carries a non-empty `data` object/array (at least one
/// non-null field, or a non-empty array).
fn has_non_empty_data(body: &[u8]) -> bool {
    match serde_json::from_slice::<Value>(body) {
        Ok(value) => match value.get("data") {
            Some(Value::Object(map)) => map.values().any(|v| !v.is_null()),
            Some(Value::Array(items)) => !items.is_empty(),
            _ => false,
        },
        Err(_) => false,
    }
}

/// The length of a top-level JSON array response (a batched answer), or `None` if
/// the body is not a JSON array.
fn batch_response_len(body: &[u8]) -> Option<usize> {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Array(items)) => Some(items.len()),
        _ => None,
    }
}

/// The non-null `data` value of a response body, if present.
fn response_data(body: &[u8]) -> Option<Value> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value.get("data").filter(|d| !d.is_null()).cloned()
}

// --- Disclosure analysis ----------------------------------------------------

/// Analyze a disclosed `data` payload for sensitive field names and values,
/// returning the overall class (the maximum over the signals) and the human-facing
/// signal labels. Pure over its input, so it is unit-testable.
fn analyze_disclosure(data: &Value) -> Disclosure {
    let mut class = DataClass::None;
    let mut signals: Vec<String> = Vec::new();
    walk_disclosure(data, &mut class, &mut signals);
    Disclosure { class, signals }
}

/// Recursively classify a JSON value, raising `class` and recording signals for
/// each sensitive key or value seen.
fn walk_disclosure(value: &Value, class: &mut DataClass, signals: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                classify_key(key, class, signals);
                walk_disclosure(nested, class, signals);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_disclosure(item, class, signals);
            }
        }
        Value::String(s) => classify_value(s, class, signals),
        _ => {}
    }
}

/// Raise the class and record a `field:<name>` signal for a sensitive key.
fn classify_key(key: &str, class: &mut DataClass, signals: &mut Vec<String>) {
    let lower = key.to_ascii_lowercase();
    let matched = if CREDENTIAL_FIELDS.iter().any(|f| lower.contains(f)) {
        Some(DataClass::Credentials)
    } else if USER_DATA_FIELDS.iter().any(|f| lower.contains(f)) {
        Some(DataClass::UserData)
    } else if OTHER_SENSITIVE_FIELDS.iter().any(|f| lower.contains(f)) {
        Some(DataClass::Sensitive)
    } else {
        None
    };
    if let Some(matched) = matched {
        *class = (*class).max(matched);
        push_unique(signals, format!("field:{key}"));
    }
}

/// Raise the class and record a signal for a sensitive string value (an e-mail
/// address or a token-like string).
fn classify_value(value: &str, class: &mut DataClass, signals: &mut Vec<String>) {
    if is_email(value) {
        *class = (*class).max(DataClass::UserData);
        push_unique(signals, "email_value".to_string());
    } else if looks_token_like(value) {
        *class = (*class).max(DataClass::UserData);
        push_unique(signals, "token_value".to_string());
    }
}

/// Append `label` to `signals` if not already present.
fn push_unique(signals: &mut Vec<String>, label: String) {
    if !signals.iter().any(|s| s == &label) {
        signals.push(label);
    }
}

/// Whether `value` looks like an e-mail address: a non-empty local part, an `@`, and
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

/// Whether `value` looks like a credential token: a JWT (three base64url segments),
/// or a long opaque alphanumeric string carrying both letters and digits. UUIDs
/// (which carry dashes) are excluded so ordinary object identifiers do not register.
fn looks_token_like(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() == 3
        && parts
            .iter()
            .all(|p| p.len() >= 8 && p.chars().all(is_base64url))
    {
        return true;
    }
    let charset_ok = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    let has_digit = value.bytes().any(|b| b.is_ascii_digit());
    let has_alpha = value.bytes().any(|b| b.is_ascii_alphabetic());
    value.len() >= 32 && charset_ok && has_digit && has_alpha
}

/// Whether `c` is a base64url character.
fn is_base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

// --- Finding construction ---------------------------------------------------

/// Keep at most [`SAMPLE_BYTES`] leading bytes of `body` as a UTF-8 lossy evidence
/// sample.
fn bounded_sample(body: &[u8]) -> String {
    let end = body.len().min(SAMPLE_BYTES);
    String::from_utf8_lossy(&body[..end]).to_string()
}

/// Read a response header as an owned string, if present and valid UTF-8.
fn header_str(response: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

/// Build the finding for an exposed introspection interface, attaching the extracted
/// schema as evidence (task 4.4).
fn build_introspection_finding(
    target: &Target,
    url: &Url,
    evidence: &SchemaEvidence,
    response: &ProbeResponse,
) -> Finding {
    let description = format!(
        "The GraphQL endpoint at {} answered an introspection query with its schema \
         ({} types, {} query fields, {} mutation fields). An exposed introspection \
         interface hands an attacker the full map of every type, query, and mutation, \
         including {} type(s) whose names suggest sensitive data.",
        url.as_str(),
        evidence.types_count,
        evidence.query_fields.len(),
        evidence.mutation_fields.len(),
        evidence.sensitive_types.len(),
    );

    let json = serde_json::json!({
        "endpoint": url.as_str(),
        "status": response.status,
        "check": "introspection",
        "types_count": evidence.types_count,
        "query_fields": evidence.query_fields,
        "mutation_fields": evidence.mutation_fields,
        "sensitive_types": evidence.sensitive_types,
        "response_sample": bounded_sample(&response.body),
        "body_truncated": response.truncated,
    });

    Finding::builder(ID, target.clone(), "GraphQL introspection is exposed")
        .status(Status::Vulnerable)
        .severity(Severity::High)
        .description(description)
        .evidence(json)
        .recommendations(
            "Disable introspection in production, or restrict it to authenticated, \
             authorized operators. Introspection should never be reachable by an \
             anonymous client on a production endpoint.",
        )
        .build()
}

/// Build the finding for an endpoint that accepts an unbounded-depth query.
fn build_depth_finding(target: &Target, url: &Url, response: &ProbeResponse) -> Finding {
    let json = serde_json::json!({
        "endpoint": url.as_str(),
        "status": response.status,
        "check": "query_depth",
        "response_sample": bounded_sample(&response.body),
        "body_truncated": response.truncated,
    });

    Finding::builder(
        ID,
        target.clone(),
        "GraphQL endpoint accepts unbounded query nesting",
    )
    .status(Status::Vulnerable)
    .severity(Severity::Medium)
    .description(format!(
        "The GraphQL endpoint at {} resolved a deeply nested query without rejecting \
             it for depth. Unbounded query nesting lets an attacker craft expensive \
             recursive queries that exhaust server resources (a denial-of-service vector).",
        url.as_str(),
    ))
    .evidence(json)
    .recommendations(
        "Enforce a maximum query depth and a query-complexity/cost limit so \
             deeply nested or expensive queries are rejected before execution.",
    )
    .build()
}

/// Build the finding for an endpoint with query batching enabled.
fn build_batching_finding(
    target: &Target,
    url: &Url,
    batch_len: usize,
    response: &ProbeResponse,
) -> Finding {
    let json = serde_json::json!({
        "endpoint": url.as_str(),
        "status": response.status,
        "check": "batching",
        "batch_length": batch_len,
        "response_sample": bounded_sample(&response.body),
        "body_truncated": response.truncated,
    });

    Finding::builder(ID, target.clone(), "GraphQL query batching is enabled")
        .status(Status::Vulnerable)
        .severity(Severity::Medium)
        .description(format!(
            "The GraphQL endpoint at {} answered a batch of {batch_len} queries sent as a \
             single array with an array of {batch_len} results. Query batching amplifies \
             abuse — for example brute-forcing many credential guesses or object references \
             in one request, sidestepping per-request rate limits.",
            url.as_str(),
        ))
        .evidence(json)
        .recommendations(
            "Disable array-based query batching, or apply rate limiting and cost \
             accounting across the whole batch rather than per HTTP request.",
        )
        .build()
}

/// Build the finding for a sensitive-data disclosure from a probe query.
fn build_disclosure_finding(
    target: &Target,
    url: &Url,
    query_label: &str,
    disclosure: &Disclosure,
    response: &ProbeResponse,
) -> Finding {
    // An admin-scoped query that returns data is at least critical (per design).
    let mut severity = severity_of(disclosure.class);
    if query_label.to_ascii_lowercase().contains("admin") {
        severity = severity.max(Severity::Critical);
    }

    let json = serde_json::json!({
        "endpoint": url.as_str(),
        "status": response.status,
        "check": "information_disclosure",
        "query": query_label,
        "data_class": disclosure.class.label(),
        "signals": disclosure.signals,
        "response_sample": bounded_sample(&response.body),
        "body_truncated": response.truncated,
    });

    let label = if query_label.is_empty() {
        "a sensitive-data query".to_string()
    } else {
        format!("the '{query_label}' query")
    };

    Finding::builder(
        ID,
        target.clone(),
        format!("GraphQL endpoint discloses sensitive data via {label}"),
    )
    .status(Status::Vulnerable)
    .severity(severity)
    .description(format!(
        "The GraphQL endpoint at {} answered {label} with data containing sensitive \
         field names or values ({}). Returning sensitive data to an unauthorized query \
         is an information-disclosure vulnerability.",
        url.as_str(),
        disclosure.signals.join(", "),
    ))
    .evidence(json)
    .recommendations(
        "Apply field-level authorization so sensitive fields and types are only \
         resolvable for callers permitted to see them, and never return credentials \
         or secrets through the schema.",
    )
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    fn resp(status: u16, content_type: Option<&str>, body: &str) -> ProbeResponse {
        ProbeResponse {
            status,
            content_type: content_type.map(|s| s.to_string()),
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    // --- Metadata (tasks 1.1, 1.2) ---------------------------------------------

    #[test]
    fn metadata_is_stable() {
        let scanner = GraphqlScanner::with_lists(["/graphql"], Vec::<(String, String)>::new());
        assert_eq!(scanner.id(), "graphql");
        assert_eq!(GraphqlScanner::ID, "graphql");
        assert!(!scanner.name().is_empty());
        assert!(!scanner.description().is_empty());
    }

    // --- Detector (task 6.1) ---------------------------------------------------

    #[test]
    fn detector_recognizes_graphql_json() {
        // A GraphQL JSON envelope with a `data` key.
        assert!(looks_like_graphql(
            200,
            Some("application/json"),
            br#"{"data":{"__typename":"Query"}}"#
        ));
        // An `errors` envelope.
        assert!(looks_like_graphql(
            200,
            Some("application/json"),
            br#"{"errors":[{"message":"x"}]}"#
        ));
    }

    #[test]
    fn detector_recognizes_graphql_error_message() {
        // A 400 with a GraphQL-shaped parse/validation error message.
        assert!(looks_like_graphql(
            400,
            Some("application/json"),
            br#"{"message":"Must provide query string"}"#
        ));
        assert!(looks_like_graphql(
            400,
            Some("application/json"),
            br#"{"errors":[{"message":"Cannot query field \"x\" on type \"Query\""}]}"#
        ));
    }

    #[test]
    fn detector_recognizes_schema_body() {
        // A body that carries `__schema` text is GraphQL even without the envelope.
        assert!(looks_like_graphql(
            200,
            Some("text/html"),
            b"<html>GraphiQL playground with __schema</html>"
        ));
        // A GraphQL content type alone is conclusive.
        assert!(looks_like_graphql(
            200,
            Some("application/graphql-response+json"),
            b"{}"
        ));
    }

    #[test]
    fn detector_rejects_non_graphql_404() {
        assert!(!looks_like_graphql(404, Some("text/plain"), b"Not Found"));
        assert!(!looks_like_graphql(
            404,
            Some("text/html"),
            b"<html><body>404 Not Found</body></html>"
        ));
        // A 200 page with no GraphQL signal is not GraphQL.
        assert!(!looks_like_graphql(
            200,
            Some("text/html"),
            b"<html><body>Welcome</body></html>"
        ));
    }

    // --- Schema extraction (task 6.2) ------------------------------------------

    fn introspection_payload() -> &'static str {
        r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": { "name": "Mutation" },
                    "types": [
                        { "name": "Query", "kind": "OBJECT",
                          "fields": [ { "name": "users" }, { "name": "me" } ] },
                        { "name": "Mutation", "kind": "OBJECT",
                          "fields": [ { "name": "createUser" }, { "name": "login" } ] },
                        { "name": "User", "kind": "OBJECT", "fields": [ { "name": "id" } ] },
                        { "name": "Password", "kind": "OBJECT", "fields": [] },
                        { "name": "AuthToken", "kind": "OBJECT", "fields": [] },
                        { "name": "String", "kind": "SCALAR" }
                    ]
                }
            }
        }"#
    }

    #[test]
    fn extracts_schema_evidence() {
        let evidence = extract_schema(introspection_payload().as_bytes()).unwrap();
        assert_eq!(evidence.types_count, 6);
        assert_eq!(evidence.query_fields, vec!["users", "me"]);
        assert_eq!(evidence.mutation_fields, vec!["createUser", "login"]);
        // User, Password, AuthToken all match a sensitive keyword; String does not.
        assert!(evidence.sensitive_types.contains(&"User".to_string()));
        assert!(evidence.sensitive_types.contains(&"Password".to_string()));
        assert!(evidence.sensitive_types.contains(&"AuthToken".to_string()));
        assert!(!evidence.sensitive_types.contains(&"String".to_string()));
    }

    #[test]
    fn extract_schema_is_none_without_schema() {
        // No `__schema` (introspection disabled): not extractable.
        assert!(extract_schema(br#"{"data":{"__typename":"Query"}}"#).is_none());
        assert!(extract_schema(br#"{"errors":[{"message":"introspection disabled"}]}"#).is_none());
        assert!(extract_schema(b"not json").is_none());
    }

    // --- Disclosure analyzer (task 6.3) ----------------------------------------

    #[test]
    fn disclosure_flags_credential_field_names() {
        let data = serde_json::json!({
            "me": { "id": 1, "username": "alice", "password": "hunter2" }
        });
        let disclosure = analyze_disclosure(&data);
        assert_eq!(disclosure.class, DataClass::Credentials);
        assert!(disclosure.signals.iter().any(|s| s == "field:password"));
        assert_eq!(severity_of(disclosure.class), Severity::Critical);
    }

    #[test]
    fn disclosure_flags_email_values() {
        let data = serde_json::json!({
            "users": [ { "id": 1, "contact": "alice@example.com" } ]
        });
        let disclosure = analyze_disclosure(&data);
        assert_eq!(disclosure.class, DataClass::UserData);
        assert!(disclosure.signals.iter().any(|s| s == "email_value"));
        assert_eq!(severity_of(disclosure.class), Severity::High);
    }

    #[test]
    fn disclosure_flags_token_like_values() {
        // A JWT-shaped value.
        let jwt = serde_json::json!({
            "session": "eyJhbGciOi.eyJzdWIiOiAxMjM0.SflKxwRJSMeKKF2QT4"
        });
        let disclosure = analyze_disclosure(&jwt);
        assert_eq!(disclosure.class, DataClass::UserData);
        assert!(disclosure.signals.iter().any(|s| s == "token_value"));

        // A long opaque API-key-shaped value.
        let key = serde_json::json!({ "result": "AKIA1234567890ABCDEFghijklmnopqrstuvwx" });
        let disclosure = analyze_disclosure(&key);
        assert!(disclosure.signals.iter().any(|s| s == "token_value"));
    }

    #[test]
    fn disclosure_is_none_for_benign_data() {
        let data = serde_json::json!({ "__typename": "Query", "count": 3 });
        assert_eq!(analyze_disclosure(&data).class, DataClass::None);
    }

    #[test]
    fn token_recognizer_excludes_uuids_and_short_ids() {
        // A UUID carries dashes and must not register as a token.
        assert!(!looks_token_like("550e8400-e29b-41d4-a716-446655440000"));
        // Short alphanumerics are not tokens.
        assert!(!looks_token_like("abc123"));
        // A 40-char hex string is token-like.
        assert!(looks_token_like("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"));
    }

    #[test]
    fn email_recognizer_is_strict() {
        assert!(is_email("alice@example.com"));
        assert!(!is_email("@example.com"));
        assert!(!is_email("alice@localhost"));
        assert!(!is_email("plain-string"));
    }

    // --- Severity rollup (task 5.4) --------------------------------------------

    #[test]
    fn overall_severity_is_the_highest_finding() {
        let medium = Finding::builder(ID, target(), "batching")
            .severity(Severity::Medium)
            .build();
        let high = Finding::builder(ID, target(), "introspection")
            .severity(Severity::High)
            .build();
        let critical = Finding::builder(ID, target(), "creds")
            .severity(Severity::Critical)
            .build();

        assert_eq!(overall_severity(&[]), None);
        assert_eq!(
            overall_severity(&[medium.clone(), high.clone()]),
            Some(Severity::High)
        );
        assert_eq!(
            overall_severity(&[medium, high, critical]),
            Some(Severity::Critical)
        );
    }

    // --- Data-shape predicates -------------------------------------------------

    #[test]
    fn non_empty_data_predicate() {
        assert!(has_non_empty_data(br#"{"data":{"__typename":"Query"}}"#));
        assert!(has_non_empty_data(br#"{"data":{"__schema":{"types":[]}}}"#));
        // Null/empty/absent data is not "non-empty".
        assert!(!has_non_empty_data(br#"{"data":null}"#));
        assert!(!has_non_empty_data(br#"{"data":{}}"#));
        assert!(!has_non_empty_data(br#"{"errors":[{"message":"x"}]}"#));
    }

    #[test]
    fn batch_response_len_reads_array_length() {
        assert_eq!(batch_response_len(br#"[{"data":{}},{"data":{}}]"#), Some(2));
        assert_eq!(batch_response_len(br#"{"data":{}}"#), None);
    }

    // --- Path / query selection (tasks 2.1, 2.3) -------------------------------

    #[test]
    fn normalize_paths_dedupes_normalizes_and_defaults() {
        let got = normalize_paths(["graphql", "/graphql", " /api/graphql ", "//graph"]);
        assert_eq!(
            got,
            vec![
                "/graphql".to_string(),
                "/api/graphql".to_string(),
                "/graph".to_string(),
            ]
        );
        // An empty list falls back to the built-in defaults.
        let defaults = normalize_paths(Vec::<String>::new());
        assert_eq!(
            defaults,
            DEFAULT_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn introspection_query_selection() {
        let queries = vec![
            NamedQuery {
                label: "Users Query".to_string(),
                body: "query { users { id } }".to_string(),
            },
            NamedQuery {
                label: "Introspection Query".to_string(),
                body: "query { __schema { types { name } } }".to_string(),
            },
        ];
        assert!(introspection_query(&queries).contains("__schema"));
        // The introspection query is identified and excluded from disclosure probes.
        let sensitive: Vec<&NamedQuery> = queries
            .iter()
            .filter(|q| !is_introspection_query(q))
            .collect();
        assert_eq!(sensitive.len(), 1);
        assert_eq!(sensitive[0].label, "Users Query");
        // With no introspection entry, the built-in fallback is used.
        let empty: Vec<NamedQuery> = Vec::new();
        assert_eq!(introspection_query(&empty), BUILTIN_INTROSPECTION_QUERY);
    }

    // --- Finding construction --------------------------------------------------

    #[test]
    fn introspection_finding_carries_schema_evidence() {
        let evidence = extract_schema(introspection_payload().as_bytes()).unwrap();
        let url = Url::parse("https://example.com/graphql").unwrap();
        let response = resp(200, Some("application/json"), introspection_payload());
        let finding = build_introspection_finding(&target(), &url, &evidence, &response);

        assert_eq!(finding.scanner_id, "graphql");
        assert_eq!(finding.status, Status::Vulnerable);
        assert_eq!(finding.severity, Severity::High);
        let json = finding.evidence.unwrap();
        assert_eq!(json["check"], "introspection");
        assert_eq!(json["types_count"], 6);
        assert!(json["query_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "users"));
        assert!(json["sensitive_types"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "Password"));
    }

    #[test]
    fn admin_disclosure_is_critical() {
        let data = serde_json::json!({ "admin": { "id": 1, "name": "root" } });
        let disclosure = analyze_disclosure(&data);
        let url = Url::parse("https://example.com/graphql").unwrap();
        let response = resp(200, Some("application/json"), r#"{"data":{}}"#);
        // The label names an admin query → critical even though the body alone is
        // only user-data class.
        let finding =
            build_disclosure_finding(&target(), &url, "Admin Query", &disclosure, &response);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.evidence.unwrap()["query"], "Admin Query");
    }

    #[test]
    fn bounded_sample_caps_length() {
        let big = "A".repeat(SAMPLE_BYTES * 4);
        assert_eq!(bounded_sample(big.as_bytes()).len(), SAMPLE_BYTES);
        assert_eq!(bounded_sample(b"short"), "short");
    }
}
