//! OpenAPI / Swagger spec-document discovery.
//!
//! [`OpenApiDiscoveryScanner`] probes a target's origin against a curated set of
//! common OpenAPI/Swagger document locations (the seeded `openapi-discovery-paths`
//! list) and, when a candidate location serves a genuine spec document, reports a
//! finding carrying the location, the detected spec type, and the documented
//! endpoints as evidence. A publicly reachable spec hands an operator the entire
//! documented API surface in one request — a high-value reconnaissance win and,
//! often, an exposure worth reporting.
//!
//! Like every scanner it owns none of the cross-cutting concerns: each request
//! goes through [`ScanContext::send`], so pacing, the rotating User-Agent,
//! cancellation, and progress all apply uniformly and the stealth floor cannot be
//! bypassed. The probing shape mirrors [`rest_discovery`](crate::rest_discovery);
//! the difference is the per-response decision ("is this an API spec?") and the
//! evidence (the documented endpoint set), not the engine plumbing.
//!
//! ## What counts as a spec
//!
//! A candidate response is treated as a spec only when it is a successful (2xx)
//! response whose body parses (as JSON or YAML) into an object bearing an
//! OpenAPI/Swagger marker: a top-level `openapi` string, a top-level `swagger`
//! string, or a top-level `paths` object. An unrelated 2xx response — arbitrary
//! JSON, an HTML landing page, an unparseable body — bears no marker and is never
//! reported. This is the observable contract that separates "found a spec" from
//! "got some 2xx".

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::CONTENT_TYPE;
use serde_json::Value;
use url::Url;

use abyssum_core::{
    BaseScanner, Error, Finding, ProgressUpdate, ReferenceStore, RequestSpec, Result, ScanContext,
    ScannerFactory, ScannerRegistry, Severity, Status, Target,
};

/// The stable scanner id. The registry keys on this and a scan selects by it; it
/// must never change.
const ID: &str = "openapi_discovery";

/// The seeded wordlist this scanner draws its candidate spec locations from. The
/// name follows the `openapi-discovery` spec; the reference-data store seeds the
/// curated list under it (see `add-seed-data`).
const WORDLIST_OPENAPI_PATHS: &str = "openapi-discovery-paths";

/// Upper bound on the response body buffered per probe. A probed location is
/// untrusted and could stream an unbounded (or maliciously large) response, so the
/// scanner never reads a whole body into memory: bytes beyond this cap are dropped
/// and the response is flagged `truncated`. The cap is generous (a spec must be
/// parsed whole to validate and extract endpoints, and real specs can run to a few
/// MiB) but still bounded; a body capped mid-document almost always fails to parse
/// and so is simply not reported.
const MAX_SPEC_BODY_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

/// Where an [`OpenApiDiscoveryScanner`] draws its candidate spec locations.
enum CandidateSource {
    /// The seeded reference-data store: loaded once per scan run by list name.
    Store(ReferenceStore),
    /// A fixed in-memory list (constructed directly; primarily for tests and
    /// callers that supply their own candidates).
    Fixed(Vec<String>),
}

/// Discovers published OpenAPI/Swagger spec documents by probing a curated set of
/// common locations against a target.
pub struct OpenApiDiscoveryScanner {
    source: CandidateSource,
}

impl OpenApiDiscoveryScanner {
    /// The stable scanner id, exposed for registration and selection.
    pub const ID: &'static str = ID;

    /// Build a scanner that loads its spec-location wordlist from the seeded
    /// reference-data store (the production constructor; see [`register`]).
    pub fn new(store: ReferenceStore) -> Self {
        Self {
            source: CandidateSource::Store(store),
        }
    }

    /// Build a scanner over a fixed, in-memory candidate list. Entries are
    /// normalized (leading slash) and deduped just like the seeded list.
    pub fn with_paths<I, S>(paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            source: CandidateSource::Fixed(paths.into_iter().map(Into::into).collect()),
        }
    }

    /// The deduped, leading-slash-normalized candidate spec locations for this scan
    /// run.
    ///
    /// For a store-backed scanner this loads the `openapi-discovery-paths` list
    /// once; a missing (unseeded) list contributes nothing rather than erroring, so
    /// the scanner simply issues zero probes. Exposed so a surface can preview what
    /// would be probed.
    pub async fn candidate_paths(&self) -> Result<Vec<String>> {
        let raw = match &self.source {
            CandidateSource::Fixed(paths) => paths.clone(),
            CandidateSource::Store(store) => store.wordlist_values(WORDLIST_OPENAPI_PATHS).await?,
        };
        Ok(normalize_candidates(raw))
    }
}

#[async_trait]
impl BaseScanner for OpenApiDiscoveryScanner {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "OpenAPI/Swagger Discovery"
    }

    fn description(&self) -> &str {
        "Probes a target against a curated set of common OpenAPI/Swagger document \
         locations and reports any publicly reachable API specification, surfacing \
         the documented endpoints as evidence."
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        self.validate_target(target)?;

        let candidates = self.candidate_paths().await?;
        let total = candidates.len();
        let mut findings = Vec::new();
        if total == 0 {
            // No seeded list (or an empty fixed list): nothing to probe, and no
            // request is issued.
            return Ok(findings);
        }

        // Endpoints attributed to a finding's evidence so far, across every spec
        // discovered on this target. A documented path is listed in the evidence of
        // at most one finding — the first spec that documents it.
        let mut attributed: HashSet<String> = HashSet::new();

        for (index, path) in candidates.iter().enumerate() {
            // Stop promptly on cancellation, returning the findings gathered so far
            // rather than erroring.
            if ctx.is_cancelled() {
                break;
            }

            let url = match target.base_url().join(path) {
                Ok(url) => url,
                Err(_) => {
                    // An unparseable candidate is skipped, never fatal.
                    ctx.report_progress(progress(index + 1, total, path));
                    continue;
                }
            };

            match probe(ctx, url).await {
                Ok(response) => {
                    if let Some((marker, value)) = evaluate_spec(&response, path) {
                        let documented = extract_endpoints(target, &value);
                        // Attribute only the endpoints not already carried by an
                        // earlier finding's evidence (first spec wins).
                        let fresh = fresh_endpoints(documented, &mut attributed);
                        findings.push(finding_for(
                            target,
                            path,
                            &marker,
                            &fresh,
                            response.truncated,
                        ));
                    }
                }
                // Cancellation is not a transport failure: surface it to the
                // orchestrator rather than masking it as a partial success.
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(err) => {
                    // A transport failure or a pacing halt (sustained target
                    // distress). Respect it: stop probing this host and return the
                    // findings gathered so far rather than hammering a struggling
                    // target — but log the halt so it is not silent.
                    tracing::warn!(
                        scanner = ID,
                        path = %path,
                        error = %err,
                        "stopping OpenAPI discovery after a request failure; \
                         returning partial findings"
                    );
                    break;
                }
            }

            ctx.report_progress(progress(index + 1, total, path));
        }

        Ok(findings)
    }
}

/// Register the OpenAPI discovery scanner under its stable id, baking in the seeded
/// store the factory cannot otherwise reach (the registry only hands factories a
/// `Config`). Each created instance shares the cheaply-cloneable store.
pub fn register(registry: &mut ScannerRegistry, store: &ReferenceStore) {
    let store = store.clone();
    let factory: ScannerFactory = Arc::new(move |_config| {
        Box::new(OpenApiDiscoveryScanner::new(store.clone())) as Box<dyn BaseScanner>
    });
    registry.register(ID, factory);
}

/// Build a scanner-internal progress update for the candidate at `completed` of
/// `total`, naming the location currently being probed.
fn progress(completed: usize, total: usize, path: &str) -> ProgressUpdate {
    ProgressUpdate::new(ID, completed, total)
        .current_item(path.to_string())
        .message(format!("probing {completed}/{total}"))
}

/// Merge raw wordlist entries into deduped candidate paths, each carrying exactly
/// one leading slash. Order is preserved (first occurrence wins); blank entries are
/// dropped.
fn normalize_candidates<I, S>(raw: I) -> Vec<String>
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
        let path = normalize_leading_slash(trimmed);
        if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

/// Normalize a path to exactly one leading slash: `openapi.json` ->
/// `/openapi.json`, `//api-docs` -> `/api-docs`, `/docs/` -> `/docs/`.
fn normalize_leading_slash(s: &str) -> String {
    format!("/{}", s.trim_start_matches('/'))
}

/// A probed response reduced to the fields validation needs.
#[derive(Debug, Clone)]
struct ProbeResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
    /// Whether the body was capped at [`MAX_SPEC_BODY_BYTES`] (more bytes were
    /// available but dropped).
    truncated: bool,
}

/// The OpenAPI/Swagger marker a body bears, from which the spec type is derived.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SpecMarker {
    /// A top-level `openapi` string field (OpenAPI 3.x); carries the version.
    OpenApi(String),
    /// A top-level `swagger` string field (Swagger 2.0); carries the version.
    Swagger(String),
    /// Only a top-level `paths` object — a documented surface with no version
    /// marker.
    PathsOnly,
}

impl SpecMarker {
    /// Detect the marker borne by a parsed body, or `None` when the body is not an
    /// object or bears no OpenAPI/Swagger marker.
    fn detect(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        if let Some(version) = object.get("openapi").and_then(Value::as_str) {
            return Some(SpecMarker::OpenApi(version.to_string()));
        }
        if let Some(version) = object.get("swagger").and_then(Value::as_str) {
            return Some(SpecMarker::Swagger(version.to_string()));
        }
        if object.get("paths").is_some_and(Value::is_object) {
            return Some(SpecMarker::PathsOnly);
        }
        None
    }

    /// The human-readable spec type recorded in the finding (e.g. `OpenAPI 3.0.1`).
    fn spec_type(&self) -> String {
        match self {
            SpecMarker::OpenApi(version) => format!("OpenAPI {version}"),
            SpecMarker::Swagger(version) => format!("Swagger {version}"),
            SpecMarker::PathsOnly => "OpenAPI/Swagger (unversioned)".to_string(),
        }
    }

    /// The short marker label for the finding evidence.
    fn label(&self) -> &'static str {
        match self {
            SpecMarker::OpenApi(_) => "openapi",
            SpecMarker::Swagger(_) => "swagger",
            SpecMarker::PathsOnly => "paths",
        }
    }
}

/// The two body formats a spec may be served in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Yaml,
}

/// Validate a probed response: a successful response whose body parses (as JSON or
/// YAML) into an object bearing an OpenAPI/Swagger marker is a spec. Returns the
/// detected marker and the parsed value, or `None` for any response that is not a
/// genuine spec (a non-2xx status, an unparseable body, or a 2xx body lacking every
/// marker — unrelated JSON or HTML).
fn evaluate_spec(response: &ProbeResponse, path: &str) -> Option<(SpecMarker, Value)> {
    if !(200..300).contains(&response.status) {
        return None;
    }
    let value = parse_spec_body(response, path)?;
    let marker = SpecMarker::detect(&value)?;
    Some((marker, value))
}

/// Parse a response body into a generic JSON value, trying the format the response
/// advertises first and the other as a fallback. The preferred format is chosen
/// from the `content-type` and then the path extension (JSON when neither decides);
/// the other format is always attempted if the first fails, so a mislabeled spec is
/// still parsed.
fn parse_spec_body(response: &ProbeResponse, path: &str) -> Option<Value> {
    let (first, second) = if prefers_yaml(response.content_type.as_deref(), path) {
        (Format::Yaml, Format::Json)
    } else {
        (Format::Json, Format::Yaml)
    };
    parse_as(&response.body, first).or_else(|| parse_as(&response.body, second))
}

/// Parse `body` in a single format into a generic JSON value, or `None` if it does
/// not parse in that format.
fn parse_as(body: &[u8], format: Format) -> Option<Value> {
    match format {
        Format::Json => serde_json::from_slice::<Value>(body).ok(),
        // YAML decodes into the same generic value, so validation and extraction
        // stay format-agnostic. (JSON is a YAML subset, but the JSON parser is
        // tried first for JSON-advertised bodies for speed and precision.)
        Format::Yaml => serde_yaml::from_slice::<Value>(body).ok(),
    }
}

/// Whether a response should be parsed as YAML first, decided by `content-type`
/// (authoritative when present) then the path extension. Defaults to JSON-first.
fn prefers_yaml(content_type: Option<&str>, path: &str) -> bool {
    if let Some(content_type) = content_type {
        let content_type = content_type.to_ascii_lowercase();
        if content_type.contains("yaml") || content_type.contains("yml") {
            return true;
        }
        if content_type.contains("json") {
            return false;
        }
    }
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".yaml") || lower.ends_with(".yml")
}

/// Extract the documented endpoints from a spec's `paths` object, each joined to
/// the target's origin and de-duplicated within the spec. Path templates (e.g.
/// `/users/{id}`) are preserved verbatim. A spec with no `paths` object yields no
/// endpoints (it was accepted on an `openapi`/`swagger` marker alone).
fn extract_endpoints(target: &Target, value: &Value) -> Vec<String> {
    let Some(paths) = value.get("paths").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for key in paths.keys() {
        let endpoint = join_endpoint(target, key);
        if seen.insert(endpoint.clone()) {
            out.push(endpoint);
        }
    }
    out
}

/// Express a documented path relative to the target base URL by anchoring it to the
/// target's origin (scheme + host + optional port). Path templates are kept literal
/// (a `Url::join` would percent-encode `{`/`}`), so `/users/{id}` stays readable.
fn join_endpoint(target: &Target, path: &str) -> String {
    let origin = target.base_url().origin().ascii_serialization();
    let path = normalize_leading_slash(path);
    format!("{origin}{path}")
}

/// Keep only the endpoints not already attributed to an earlier finding, recording
/// the survivors as attributed so a later spec documenting the same path does not
/// list it again. This realizes "an overlapping endpoint appears in the evidence of
/// at most one finding".
fn fresh_endpoints(endpoints: Vec<String>, attributed: &mut HashSet<String>) -> Vec<String> {
    endpoints
        .into_iter()
        .filter(|endpoint| attributed.insert(endpoint.clone()))
        .collect()
}

/// Build the [`Finding`] for a discovered spec. A published spec is an observation,
/// not by itself a weakness, so it maps to `status: info` / `severity: info` (per
/// the design's canonical finding mapping). The evidence carries the location, the
/// detected spec type, and the documented endpoints attributed to this finding.
fn finding_for(
    target: &Target,
    path: &str,
    marker: &SpecMarker,
    endpoints: &[String],
    truncated: bool,
) -> Finding {
    let spec_type = marker.spec_type();
    let title = format!("Discovered {spec_type} document at {path}");
    let description = format!(
        "A published API specification ({spec_type}) is reachable at {path}; it \
         documents {count} endpoint(s) attributed to this finding. A publicly \
         reachable spec hands an operator the documented API surface in one request.",
        count = endpoints.len(),
    );

    let evidence = serde_json::json!({
        "location": path,
        "spec_type": spec_type,
        "marker": marker.label(),
        "endpoint_count": endpoints.len(),
        "endpoints": endpoints,
        "body_truncated": truncated,
    });

    Finding::builder(ID, target.clone(), title)
        .status(Status::Info)
        .severity(Severity::Info)
        .description(description)
        .evidence(evidence)
        .recommendations(
            "If this specification was not intended to be public, restrict access to \
             it; otherwise confirm that every documented endpoint enforces its own \
             authorization.",
        )
        .build()
}

/// Probe one URL through the paced scan context and reduce the response to the
/// fields validation needs. The body is streamed through a bounded reader that
/// buffers at most [`MAX_SPEC_BODY_BYTES`]: a probed location is untrusted and could
/// return an unbounded body, so an oversized body is capped and flagged
/// (`truncated`) rather than read whole into memory.
async fn probe(ctx: &ScanContext, url: Url) -> Result<ProbeResponse> {
    let mut response = ctx.send(RequestSpec::get(url)).await?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());

    let mut body = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::Http(e.to_string()))?
    {
        let remaining = MAX_SPEC_BODY_BYTES.saturating_sub(body.len());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, content_type: Option<&str>, body: &str) -> ProbeResponse {
        ProbeResponse {
            status,
            content_type: content_type.map(|s| s.to_string()),
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    // --- Metadata (task 1.2) ---------------------------------------------------

    #[test]
    fn metadata_is_stable() {
        let scanner = OpenApiDiscoveryScanner::with_paths(["/openapi.json"]);
        assert_eq!(scanner.id(), "openapi_discovery");
        assert_eq!(OpenApiDiscoveryScanner::ID, "openapi_discovery");
        assert!(!scanner.name().is_empty());
        assert!(!scanner.description().is_empty());
    }

    // --- Wordlist normalization + dedup (task 2.2) -----------------------------

    #[test]
    fn normalizes_leading_slashes_and_dedupes_preserving_order() {
        let raw = vec![
            "openapi.json",   // -> /openapi.json
            "/openapi.json",  // dup
            "/swagger.yaml",  // kept
            "api-docs",       // -> /api-docs
            "  /docs/  ",     // trimmed -> /docs/ (trailing slash preserved)
            "//swagger-spec", // -> /swagger-spec
            "",               // dropped
            "   ",            // dropped
        ];
        let got = normalize_candidates(raw);
        assert_eq!(
            got,
            vec![
                "/openapi.json".to_string(),
                "/swagger.yaml".to_string(),
                "/api-docs".to_string(),
                "/docs/".to_string(),
                "/swagger-spec".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn fixed_source_candidate_paths_are_normalized() {
        let scanner =
            OpenApiDiscoveryScanner::with_paths(["openapi.json", "/openapi.json", "swagger.json"]);
        let paths = scanner.candidate_paths().await.unwrap();
        assert_eq!(
            paths,
            vec!["/openapi.json".to_string(), "/swagger.json".to_string()]
        );
    }

    // --- Validator matrix (task 4.2 / 4.3 / test 6.1) --------------------------

    #[test]
    fn validator_accepts_openapi_json() {
        let body = r#"{"openapi":"3.0.1","info":{"title":"X"},"paths":{"/a":{}}}"#;
        let (marker, _) =
            evaluate_spec(&resp(200, Some("application/json"), body), "/openapi.json")
                .expect("an OpenAPI 3.x JSON doc is a spec");
        assert_eq!(marker, SpecMarker::OpenApi("3.0.1".to_string()));
        assert_eq!(marker.spec_type(), "OpenAPI 3.0.1");
        assert_eq!(marker.label(), "openapi");
    }

    #[test]
    fn validator_accepts_swagger_json() {
        let body = r#"{"swagger":"2.0","info":{"title":"X"},"paths":{"/a":{}}}"#;
        let (marker, _) =
            evaluate_spec(&resp(200, Some("application/json"), body), "/swagger.json")
                .expect("a Swagger 2.0 JSON doc is a spec");
        assert_eq!(marker, SpecMarker::Swagger("2.0".to_string()));
        assert_eq!(marker.spec_type(), "Swagger 2.0");
    }

    #[test]
    fn validator_accepts_yaml_spec() {
        let body = "openapi: 3.0.0\npaths:\n  /users:\n    get: {}\n";
        let (marker, value) =
            evaluate_spec(&resp(200, Some("application/yaml"), body), "/openapi.yaml")
                .expect("a YAML OpenAPI doc is a spec");
        assert_eq!(marker, SpecMarker::OpenApi("3.0.0".to_string()));
        // The YAML decoded into the same generic value used for extraction.
        assert!(value.get("paths").and_then(Value::as_object).is_some());
    }

    #[test]
    fn validator_accepts_paths_only_document() {
        // No openapi/swagger marker, but a top-level `paths` object is enough.
        let body = r#"{"paths":{"/health":{"get":{}}}}"#;
        let (marker, _) = evaluate_spec(&resp(200, Some("application/json"), body), "/spec.json")
            .expect("a paths-only document is a spec");
        assert_eq!(marker, SpecMarker::PathsOnly);
        assert_eq!(marker.label(), "paths");
    }

    #[test]
    fn validator_rejects_unrelated_json() {
        // A 2xx JSON payload with none of the markers is not a spec.
        let body = r#"{"data":[1,2,3],"page":1}"#;
        assert!(evaluate_spec(&resp(200, Some("application/json"), body), "/data.json").is_none());
    }

    #[test]
    fn validator_rejects_html() {
        let body = "<!DOCTYPE html><html><body>API documentation</body></html>";
        assert!(evaluate_spec(&resp(200, Some("text/html"), body), "/docs").is_none());
    }

    #[test]
    fn validator_rejects_unparseable_body() {
        // Not valid JSON and not a YAML mapping/scalar that yields an object.
        let body = "\u{0000}\u{0001}not a document: [unbalanced";
        assert!(evaluate_spec(&resp(200, Some("application/json"), body), "/x").is_none());
    }

    #[test]
    fn validator_rejects_non_2xx_even_with_spec_body() {
        // A 404 (or any non-success) is ignored regardless of body content.
        let body = r#"{"openapi":"3.0.0","paths":{"/a":{}}}"#;
        assert!(
            evaluate_spec(&resp(404, Some("application/json"), body), "/openapi.json").is_none()
        );
        assert!(
            evaluate_spec(&resp(500, Some("application/json"), body), "/openapi.json").is_none()
        );
    }

    #[test]
    fn validator_rejects_json_scalar_and_array() {
        // Parseable JSON that is not an object cannot bear a top-level marker.
        assert!(evaluate_spec(&resp(200, Some("application/json"), "[1,2,3]"), "/x").is_none());
        assert!(evaluate_spec(&resp(200, Some("application/json"), "\"hi\""), "/x").is_none());
    }

    // --- Format selection ------------------------------------------------------

    #[test]
    fn format_preference_follows_content_type_then_extension() {
        assert!(prefers_yaml(Some("application/yaml"), "/openapi.json"));
        assert!(prefers_yaml(Some("text/x-yaml; charset=utf-8"), "/x"));
        assert!(!prefers_yaml(Some("application/json"), "/openapi.yaml"));
        // No decisive content-type: fall back to the extension.
        assert!(prefers_yaml(Some("text/plain"), "/openapi.yaml"));
        assert!(prefers_yaml(None, "/openapi.yml"));
        assert!(!prefers_yaml(None, "/openapi.json"));
        // Unknown everything defaults to JSON-first.
        assert!(!prefers_yaml(None, "/api-docs"));
    }

    #[test]
    fn yaml_spec_parsed_even_when_mislabeled_json() {
        // content-type lies (says JSON) but the body is YAML: the JSON parse fails
        // and the YAML fallback recovers it.
        let body = "swagger: '2.0'\npaths:\n  /a: {}\n";
        let (marker, _) =
            evaluate_spec(&resp(200, Some("application/json"), body), "/swagger.json")
                .expect("YAML fallback parses a mislabeled spec");
        assert_eq!(marker, SpecMarker::Swagger("2.0".to_string()));
    }

    // --- Endpoint extraction (task 5.1 / 5.2 / test 6.2) -----------------------

    #[test]
    fn extracts_documented_paths_joined_to_origin() {
        let value = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/users": {},
                "/users/{id}": {},
                "/health": {}
            }
        });
        let endpoints = extract_endpoints(&target(), &value);
        // Path templates are preserved and anchored to the target origin.
        assert!(endpoints.contains(&"https://example.com/users".to_string()));
        assert!(endpoints.contains(&"https://example.com/users/{id}".to_string()));
        assert!(endpoints.contains(&"https://example.com/health".to_string()));
        assert_eq!(endpoints.len(), 3);
    }

    #[test]
    fn extraction_dedupes_within_a_spec() {
        // Two keys that collapse to the same origin-joined endpoint appear once.
        let value = serde_json::json!({
            "paths": { "/dup": {}, "dup": {} }
        });
        let endpoints = extract_endpoints(&target(), &value);
        assert_eq!(endpoints, vec!["https://example.com/dup".to_string()]);
    }

    #[test]
    fn extraction_is_empty_without_paths_object() {
        let value = serde_json::json!({ "openapi": "3.0.0", "info": {} });
        assert!(extract_endpoints(&target(), &value).is_empty());
        // A non-object `paths` is ignored too.
        let value = serde_json::json!({ "paths": "not an object" });
        assert!(extract_endpoints(&target(), &value).is_empty());
    }

    #[test]
    fn endpoints_anchor_to_origin_with_explicit_port() {
        let target = Target::parse("http://127.0.0.1:8080").unwrap();
        let value = serde_json::json!({ "paths": { "/v1/items": {} } });
        let endpoints = extract_endpoints(&target, &value);
        assert_eq!(
            endpoints,
            vec!["http://127.0.0.1:8080/v1/items".to_string()]
        );
    }

    // --- Cross-spec de-duplication (spec scenario) -----------------------------

    #[test]
    fn fresh_endpoints_attribute_an_overlap_to_the_first_finding_only() {
        let mut attributed = HashSet::new();
        let first = fresh_endpoints(
            vec![
                "https://example.com/users".to_string(),
                "https://example.com/orders".to_string(),
            ],
            &mut attributed,
        );
        assert_eq!(first.len(), 2);
        // A second spec re-documenting /users plus a new /carts: only /carts is fresh.
        let second = fresh_endpoints(
            vec![
                "https://example.com/users".to_string(),
                "https://example.com/carts".to_string(),
            ],
            &mut attributed,
        );
        assert_eq!(second, vec!["https://example.com/carts".to_string()]);
    }

    // --- Finding construction (task 5.3) ---------------------------------------

    #[test]
    fn finding_maps_to_info_info_with_location_type_and_endpoints() {
        let marker = SpecMarker::OpenApi("3.0.1".to_string());
        let endpoints = vec![
            "https://example.com/users".to_string(),
            "https://example.com/users/{id}".to_string(),
        ];
        let finding = finding_for(&target(), "/openapi.json", &marker, &endpoints, false);

        assert_eq!(finding.scanner_id, "openapi_discovery");
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.severity, Severity::Info);
        // The location and the detected spec type both surface in the title.
        assert!(finding.title.contains("/openapi.json"));
        assert!(finding.title.contains("OpenAPI 3.0.1"));

        let evidence = finding.evidence.expect("evidence present");
        assert_eq!(evidence["location"], "/openapi.json");
        assert_eq!(evidence["spec_type"], "OpenAPI 3.0.1");
        assert_eq!(evidence["marker"], "openapi");
        assert_eq!(evidence["endpoint_count"], 2);
        let listed = evidence["endpoints"].as_array().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|e| e == "https://example.com/users/{id}"));
        assert_eq!(evidence["body_truncated"], false);
    }
}
