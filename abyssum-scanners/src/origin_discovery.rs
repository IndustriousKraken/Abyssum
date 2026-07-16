//! Origin-IP discovery for a target fronted by a CDN/WAF.
//!
//! [`OriginDiscoveryScanner`] finds the true origin IP of a host that hides behind
//! a CDN/WAF (Cloudflare, CloudFront, Akamai, …). If the origin answers directly,
//! the perimeter's protections can be bypassed by testing it straight — but only
//! once you know where it is. This scanner discovers and **confirms** that address;
//! exploiting it is the job of the other scanners.
//!
//! The flow is three steps, all through the paced request path so pacing, the
//! rotating User-Agent, cancellation, and progress apply and the stealth floor
//! cannot be bypassed:
//!
//! 1. **Detect fronting.** Fetch the target once and recognize a CDN/WAF from its
//!    response headers (`CF-Ray`, `X-Amz-Cf-Id`, `Server: cloudflare`, …). This
//!    request also captures the **perimeter baseline** content. When no CDN/WAF is
//!    detected, origin discovery does not apply and nothing is reported.
//! 2. **Gather candidates passively.** Historical / passive-DNS A records for the
//!    host, fetched over HTTP from a third-party source — never by probing the
//!    target's own perimeter. Private/loopback/link-local addresses are dropped so
//!    no internal range is ever probed.
//! 3. **Confirm.** For each candidate IP, issue a direct request *to the IP* while
//!    presenting the target's `Host` header, and compare the response to the
//!    perimeter baseline. A body that matches the baseline **with the CDN markers
//!    absent** means we reached the real origin behind the perimeter. Only a
//!    confirmed origin is reported (naming the host and IP); an unconfirmed
//!    candidate — a shared-host IP serving unrelated content, or another CDN edge —
//!    is never reported as the origin. Each candidate IP is a distinct pacing host,
//!    so probing spreads across them rather than hammering one.
//!
//! The body comparison mirrors the whitespace-normalized / JSON-scalar comparison
//! the BAC/IDOR scanners use to tell "the same page" from "a materially different
//! one".

use std::collections::{BTreeSet, HashSet};
use std::net::Ipv4Addr;
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
const ID: &str = "origin_discovery";

/// The default passive candidate source: a historical/passive-DNS aggregator that,
/// queried as `{base}?q=<host>`, returns the `hostname,ip` records it has observed
/// for the host — a third-party lookup, not a query against the target's own
/// infrastructure. Any address token in the body is harvested, so the exact
/// response format is not depended on.
const HOSTSEARCH_BASE: &str = "https://api.hackertarget.com/hostsearch/";

/// Upper bound on candidate IPs confirmed in one run. Passive sources return few
/// addresses for a host, but the set is capped and the truncation logged rather
/// than silently dropped.
const MAX_CANDIDATES: usize = 64;

/// Upper bound on the response body buffered per request. A probed IP (or a
/// third-party source) is untrusted and could stream an unbounded body; the
/// comparison only needs a bounded prefix, so bytes beyond this cap are dropped.
const MAX_BODY_BYTES: usize = 512 * 1024;

/// The whitespace-normalized length tolerance below which two bodies are *not*
/// considered to differ on length alone (5%) — the same tolerance BAC/IDOR use.
const LENGTH_TOLERANCE: f64 = 0.05;

/// Known CDN/WAF fingerprints: `(name, lowercase header, lowercase value
/// substring)`. A response carries the fingerprint when it has the header and —
/// when the substring is non-empty — the header value contains it (an empty
/// substring matches on the header's mere presence). This is a tunable default;
/// the observable contract is "a fronted target is recognized", not the exact set.
const CDN_MARKERS: &[(&str, &str, &str)] = &[
    ("Cloudflare", "cf-ray", ""),
    ("Cloudflare", "cf-cache-status", ""),
    ("Cloudflare", "server", "cloudflare"),
    ("Amazon CloudFront", "x-amz-cf-id", ""),
    ("Amazon CloudFront", "x-amz-cf-pop", ""),
    ("Amazon CloudFront", "via", "cloudfront"),
    ("Amazon CloudFront", "server", "cloudfront"),
    ("Akamai", "x-akamai-transformed", ""),
    ("Akamai", "server", "akamaighost"),
    ("Fastly", "x-fastly-request-id", ""),
    ("Fastly", "x-served-by", "cache-"),
    ("Fastly", "server", "fastly"),
    ("Sucuri", "x-sucuri-id", ""),
    ("Sucuri", "server", "sucuri"),
    ("Imperva Incapsula", "x-iinfo", ""),
    ("Imperva Incapsula", "x-cdn", "incapsula"),
    ("StackPath", "server", "stackpath"),
];

/// Where an [`OriginDiscoveryScanner`] draws its candidate origin IPs.
enum Candidates {
    /// Query the passive source live, through the paced request path (production).
    /// Holds the source base URL so tests can point it at a local mock.
    Passive { source_base: Url },
    /// A fixed, in-memory candidate list — bypasses the network. Used by tests
    /// that stub the passive source and by callers supplying their own candidates.
    Fixed(Vec<String>),
}

/// Discovers and confirms the origin IP of a CDN/WAF-fronted target.
pub struct OriginDiscoveryScanner {
    candidates: Candidates,
}

impl OriginDiscoveryScanner {
    /// The stable scanner id, exposed for registration and selection.
    pub const ID: &'static str = ID;

    /// Build the production scanner: candidates gathered from the default passive
    /// historical-DNS source.
    pub fn new() -> Self {
        Self {
            candidates: Candidates::Passive {
                // The default base is a valid absolute URL, so this never fails.
                source_base: Url::parse(HOSTSEARCH_BASE).expect("HOSTSEARCH_BASE is a valid URL"),
            },
        }
    }

    /// Build a scanner whose passive source is the hostsearch-style endpoint at
    /// `base` (for tests pointing candidate gathering at a local mock).
    pub fn with_source_base(base: Url) -> Self {
        Self {
            candidates: Candidates::Passive { source_base: base },
        }
    }

    /// Build a scanner over a fixed, in-memory candidate list — the passive source
    /// stubbed out (no source query is issued). Entries are parsed as IPv4
    /// addresses just like passively-discovered ones.
    pub fn with_candidates<I, S>(candidates: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            candidates: Candidates::Fixed(candidates.into_iter().map(Into::into).collect()),
        }
    }

    /// Gather the raw candidate strings from the configured source. Every passive
    /// query goes through [`ScanContext::send`], so it is paced and carries a
    /// rotating User-Agent.
    async fn gather(&self, host: &str, ctx: &ScanContext) -> Result<Vec<String>> {
        match &self.candidates {
            Candidates::Fixed(list) => Ok(list.clone()),
            Candidates::Passive { source_base } => passive_dns_query(source_base, host, ctx).await,
        }
    }
}

impl Default for OriginDiscoveryScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BaseScanner for OriginDiscoveryScanner {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "Origin IP Discovery"
    }

    fn description(&self) -> &str {
        "Detects that a target is fronted by a CDN/WAF, gathers candidate origin IPs \
         from passive historical-DNS sources (never attacking the perimeter), and \
         confirms an origin by requesting the target host directly against a candidate \
         IP and matching the response to the perimeter-served baseline. Only a \
         confirmed origin is reported, naming the host and IP."
    }

    /// Requires a target with a host (the host whose origin is sought). Any path is
    /// accepted: the baseline and each origin probe use it so the comparison is of a
    /// meaningful page.
    fn validate_target(&self, target: &Target) -> Result<()> {
        if target.host().is_none() {
            return Err(Error::Target(format!(
                "origin discovery target has no host: {}",
                target.base_url()
            )));
        }
        Ok(())
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        self.validate_target(target)?;
        // `validate_target` guarantees a host.
        let host = target.host().unwrap_or_default().to_ascii_lowercase();

        // Step 1: fetch the perimeter baseline. This both reveals the fronting
        // CDN/WAF (from its headers) and captures the content each candidate is
        // compared against.
        let baseline = match probe(ctx, RequestSpec::get(target.full_url())).await {
            Ok(response) => response,
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(err) => {
                tracing::warn!(
                    scanner = ID,
                    host = %host,
                    error = %err,
                    "could not fetch the perimeter baseline; skipping origin discovery"
                );
                return Ok(Vec::new());
            }
        };

        let Some(cdn) = detect_cdn(&baseline.headers) else {
            // Not fronted by a recognized CDN/WAF: origin discovery does not apply.
            tracing::debug!(
                scanner = ID,
                host = %host,
                "target is not fronted by a recognized CDN/WAF; not attempting origin discovery"
            );
            return Ok(Vec::new());
        };

        // Step 2: gather candidate origin IPs from passive sources.
        let raw = self.gather(&host, ctx).await?;
        let (candidates, dropped) = cap_candidates(parse_candidate_ips(&raw), MAX_CANDIDATES);
        if dropped > 0 {
            tracing::warn!(
                scanner = ID,
                host = %host,
                cap = MAX_CANDIDATES,
                dropped,
                "passive source returned more candidate IPs than the probe cap; \
                 probing the first {MAX_CANDIDATES} and dropping {dropped}"
            );
        }

        // Step 3: confirm each candidate by a direct request to the IP carrying the
        // target's Host header, comparing against the baseline.
        let baseline_url = target.full_url();
        let total = candidates.len();
        let mut findings = Vec::new();

        for (index, ip) in candidates.iter().enumerate() {
            if ctx.is_cancelled() {
                break;
            }

            match confirm_probe(ctx, ip, &baseline_url, &host).await {
                Ok(Some(response)) if is_confirmed_origin(&baseline, &response) => {
                    findings.push(finding_for(target, &host, ip, cdn, &baseline, &response));
                }
                Ok(_) => {}
                // Cancellation is not a per-candidate failure: surface it.
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(err) => {
                    // A candidate that will not form a URL or does not answer is
                    // simply not the origin — routine, never fatal.
                    tracing::debug!(
                        scanner = ID,
                        ip = %ip,
                        error = %err,
                        "candidate IP did not confirm; skipping"
                    );
                }
            }

            ctx.report_progress(progress(index + 1, total, ip));
        }

        Ok(findings)
    }
}

/// Register the origin-discovery scanner under its stable id. Its passive sources
/// and CDN fingerprints are inline, so it reads no seeded store.
pub fn register(registry: &mut ScannerRegistry) {
    let factory: ScannerFactory =
        Arc::new(|_config| Box::new(OriginDiscoveryScanner::new()) as Box<dyn BaseScanner>);
    registry.register(ID, factory);
}

/// A probed response reduced to the fields discovery needs: status, the response
/// headers (lowercase names) for CDN detection, and the body for comparison.
#[derive(Debug, Clone)]
struct ProbeResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// The fronting CDN/WAF whose markers appear in `headers`, or `None` if none do.
/// Case-insensitive: header names are already lowercased and values are compared
/// case-insensitively.
fn detect_cdn(headers: &[(String, String)]) -> Option<&'static str> {
    for (name, needle_value, cdn) in CDN_MARKERS
        .iter()
        .map(|(cdn, header, needle)| (*header, *needle, *cdn))
    {
        if let Some((_, value)) = headers.iter().find(|(n, _)| n == name)
            && (needle_value.is_empty() || value.to_ascii_lowercase().contains(needle_value))
        {
            return Some(cdn);
        }
    }
    None
}

/// Whether a candidate is the confirmed origin: it serves the perimeter's content
/// directly (its body matches the baseline) **and** does not itself carry a CDN/WAF
/// marker — i.e. we reached the host behind the perimeter, not another edge or an
/// unrelated shared host.
fn is_confirmed_origin(baseline: &ProbeResponse, candidate: &ProbeResponse) -> bool {
    detect_cdn(&candidate.headers).is_none() && content_matches(&baseline.body, &candidate.body)
}

/// Whether two bodies are the same page. The inverse of the BAC/IDOR material-
/// difference test: bodies whose whitespace-normalized lengths are within
/// [`LENGTH_TOLERANCE`] and (when both are JSON) whose scalar leaves are equal are
/// treated as the same content.
fn content_matches(baseline: &[u8], candidate: &[u8]) -> bool {
    !differs_materially(baseline, candidate)
}

/// Whether two bodies differ *materially*: their whitespace-normalized lengths
/// differ by more than [`LENGTH_TOLERANCE`], OR (when both parse as JSON) their sets
/// of scalar leaf values differ. Mirrors the BAC/IDOR comparator.
//
// ponytail: replicates idor.rs's private `differs_materially`; lift to a core util
// only if a third scanner needs the same comparison.
fn differs_materially(baseline: &[u8], candidate: &[u8]) -> bool {
    let base_len = normalized_len(baseline);
    let alt_len = normalized_len(candidate);
    let max = base_len.max(alt_len);
    if max > 0 {
        let diff = base_len.abs_diff(alt_len) as f64 / max as f64;
        if diff > LENGTH_TOLERANCE {
            return true;
        }
    }

    match (
        serde_json::from_slice::<Value>(baseline),
        serde_json::from_slice::<Value>(candidate),
    ) {
        (Ok(base_json), Ok(alt_json)) => scalar_leaves(&base_json) != scalar_leaves(&alt_json),
        // Not both JSON and lengths within tolerance: treat as the same page.
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

/// The set of scalar leaf values in a JSON value, each tagged by its key path and
/// kind so that structurally different objects produce different sets.
fn scalar_leaves(value: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    collect_scalar_leaves(value, "", &mut out);
    out
}

fn collect_scalar_leaves(value: &Value, path: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Null => {
            out.insert(format!("{path}=null"));
        }
        Value::Bool(b) => {
            out.insert(format!("{path}=b:{b}"));
        }
        Value::Number(n) => {
            out.insert(format!("{path}=n:{n}"));
        }
        Value::String(s) => {
            out.insert(format!("{path}=s:{s}"));
        }
        Value::Array(items) => {
            let child = format!("{path}[]");
            for item in items {
                collect_scalar_leaves(item, &child, out);
            }
        }
        Value::Object(map) => {
            for (key, nested) in map {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                collect_scalar_leaves(nested, &child, out);
            }
        }
    }
}

/// Extract candidate origin IPv4 addresses from raw passive-source strings. Each
/// string is scanned for `A.B.C.D` tokens (so CSV, JSON, and plaintext responses
/// all work), parsed as IPv4, deduplicated preserving order, and filtered to
/// globally-routable unicast — private, loopback, link-local, unspecified, and
/// broadcast addresses are dropped so no internal range is ever probed.
fn parse_candidate_ips<I, S>(raw: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in raw {
        for token in entry
            .as_ref()
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        {
            let Ok(ip) = token.parse::<Ipv4Addr>() else {
                continue;
            };
            if !is_probeable(&ip) {
                continue;
            }
            let text = ip.to_string();
            if seen.insert(text.clone()) {
                out.push(text);
            }
        }
    }
    out
}

/// Whether an address is a public unicast address worth probing (not private,
/// loopback, link-local, unspecified, or broadcast).
fn is_probeable(ip: &Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation())
}

/// Truncate `candidates` to at most `cap`, returning the kept prefix and how many
/// were dropped.
fn cap_candidates(mut candidates: Vec<String>, cap: usize) -> (Vec<String>, usize) {
    let dropped = candidates.len().saturating_sub(cap);
    candidates.truncate(cap);
    (candidates, dropped)
}

/// Query the passive historical-DNS source at `base` for `host`, through the paced
/// request path, returning its raw body as a single-element list for the IP
/// extractor. A non-2xx, a transport failure, or an empty body yields no
/// candidates (logged) rather than failing the scan — gathering is best-effort.
async fn passive_dns_query(base: &Url, host: &str, ctx: &ScanContext) -> Result<Vec<String>> {
    let mut url = base.clone();
    url.query_pairs_mut().clear().append_pair("q", host);

    let response = match probe(ctx, RequestSpec::get(url)).await {
        Ok(response) => response,
        Err(Error::Cancelled) => return Err(Error::Cancelled),
        Err(err) => {
            tracing::warn!(
                scanner = ID,
                host = %host,
                error = %err,
                "passive source query failed; continuing with no candidates"
            );
            return Ok(Vec::new());
        }
    };

    if !(200..300).contains(&response.status) {
        tracing::warn!(
            scanner = ID,
            host = %host,
            status = response.status,
            "passive source returned a non-success status; no candidates"
        );
        return Ok(Vec::new());
    }

    Ok(vec![String::from_utf8_lossy(&response.body).into_owned()])
}

/// Issue a direct request to `ip` at the baseline URL's scheme/path while
/// presenting `host` as the `Host` header, through the paced request path — so the
/// probe is paced per-IP and carries a rotating User-Agent. `None` if the candidate
/// URL cannot be formed.
async fn confirm_probe(
    ctx: &ScanContext,
    ip: &str,
    baseline_url: &Url,
    host: &str,
) -> Result<Option<ProbeResponse>> {
    // Address the IP directly but keep the baseline's scheme/path/query, so we
    // compare the same page the perimeter served.
    let mut url = baseline_url.clone();
    if url.set_host(Some(ip)).is_err() {
        return Ok(None);
    }
    // ponytail: HTTPS-to-IP validates the cert against the IP, which an origin cert
    // rarely covers, so an HTTPS origin may not confirm here; a reqwest `.resolve()`
    // client (SNI = host, connect = IP) would lift that — deferred until needed.
    let spec = RequestSpec::get(url).header("Host", host);
    probe(ctx, spec).await.map(Some)
}

/// Send one request through the paced scan context, reducing the response to the
/// status, its headers (lowercase names), and a length-capped body.
async fn probe(ctx: &ScanContext, spec: RequestSpec) -> Result<ProbeResponse> {
    let mut response = ctx.send(spec).await?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_ascii_lowercase(), v.to_string()))
        })
        .collect();

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::Http(e.to_string()))?
    {
        let remaining = MAX_BODY_BYTES.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            break;
        }
        body.extend_from_slice(&chunk);
    }

    Ok(ProbeResponse {
        status,
        headers,
        body,
    })
}

/// Build the finding for a confirmed origin, naming the host and IP and recording
/// the fronting CDN, the reproduction detail, and the observed statuses.
fn finding_for(
    target: &Target,
    host: &str,
    ip: &str,
    cdn: &str,
    baseline: &ProbeResponse,
    origin: &ProbeResponse,
) -> Finding {
    Finding::builder(
        ID,
        target.clone(),
        format!("Origin IP for {host} discovered behind {cdn}: {ip}"),
    )
    .status(Status::Vulnerable)
    .severity(Severity::Medium)
    .description(format!(
        "The host {host} is fronted by {cdn}, but its origin answers directly at {ip}: a \
         request to {ip} carrying `Host: {host}` returned the same content the perimeter \
         serves (HTTP {origin_status} vs baseline {baseline_status}), with no {cdn} markers \
         present. An attacker who knows the origin address can bypass the CDN/WAF and test \
         the origin directly.",
        origin_status = origin.status,
        baseline_status = baseline.status,
    ))
    .evidence(serde_json::json!({
        "host": host,
        "origin_ip": ip,
        "fronting_cdn": cdn,
        "baseline_status": baseline.status,
        "origin_status": origin.status,
        "confirmed": true,
    }))
    .recommendations(format!(
        "Restrict the origin at {ip} to accept traffic only from {cdn} (firewall to the \
         CDN's published IP ranges, or use authenticated origin pull / mutual TLS), so the \
         origin cannot be reached directly and the perimeter cannot be bypassed. Rotating \
         the origin IP after locking it down prevents reuse of the exposed address."
    ))
    .build()
}

/// Build a scanner-internal progress update for candidate `completed` of `total`,
/// naming the IP currently being confirmed.
fn progress(completed: usize, total: usize, ip: &str) -> ProgressUpdate {
    ProgressUpdate::new(ID, completed, total)
        .current_item(ip.to_string())
        .message(format!("confirming candidate {completed}/{total}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
            .collect()
    }

    fn resp(status: u16, hdrs: &[(&str, &str)], body: &str) -> ProbeResponse {
        ProbeResponse {
            status,
            headers: headers(hdrs),
            body: body.as_bytes().to_vec(),
        }
    }

    // --- Metadata --------------------------------------------------------------

    #[test]
    fn metadata_is_stable() {
        let scanner = OriginDiscoveryScanner::new();
        assert_eq!(scanner.id(), "origin_discovery");
        assert_eq!(OriginDiscoveryScanner::ID, "origin_discovery");
        assert!(!scanner.name().is_empty());
        assert!(!scanner.description().is_empty());
    }

    #[test]
    fn validate_target_requires_a_host() {
        let scanner = OriginDiscoveryScanner::new();
        assert!(scanner.validate_target(&target()).is_ok());
        // A path is allowed (the comparison uses it).
        let with_path = Target::parse("https://example.com/app").unwrap();
        assert!(scanner.validate_target(&with_path).is_ok());
        // No host at all is rejected.
        let hostless = Target::new(Url::parse("file:///tmp/x").unwrap(), None, None);
        assert!(matches!(
            scanner.validate_target(&hostless),
            Err(Error::Target(_))
        ));
    }

    // --- CDN/WAF detection (task 1) --------------------------------------------

    #[test]
    fn detects_fronting_from_headers() {
        assert_eq!(
            detect_cdn(&headers(&[
                ("CF-Ray", "7d1b-EWR"),
                ("Server", "cloudflare")
            ])),
            Some("Cloudflare")
        );
        assert_eq!(
            detect_cdn(&headers(&[
                ("X-Amz-Cf-Id", "abc"),
                ("Via", "1.1 x.cloudfront.net")
            ])),
            Some("Amazon CloudFront")
        );
        assert_eq!(
            detect_cdn(&headers(&[("Server", "AkamaiGHost")])),
            Some("Akamai")
        );
        assert_eq!(
            detect_cdn(&headers(&[
                ("X-Sucuri-ID", "12"),
                ("Server", "Sucuri/Cloudproxy")
            ])),
            Some("Sucuri")
        );
        // A plain origin (no CDN markers) is not fronted.
        assert_eq!(
            detect_cdn(&headers(&[
                ("Server", "nginx/1.24.0"),
                ("Content-Type", "text/html")
            ])),
            None
        );
        assert_eq!(detect_cdn(&[]), None);
    }

    // --- Candidate IP extraction + filtering (task 2) --------------------------

    #[test]
    fn parses_ips_from_mixed_bodies_dedup_and_drops_internal() {
        // A hostsearch CSV plus a JSON blob; private/loopback/link-local dropped.
        let raw = vec![
            "www.example.com,203.0.113.7\napi.example.com,198.51.100.9",
            r#"{"ip":"203.0.113.7","other":"192.168.1.10"}"#, // dup public + private
            "127.0.0.1 169.254.1.1 10.0.0.5 0.0.0.0",         // all internal/bogus
        ];
        let got = parse_candidate_ips(raw);
        // 203.0.113.x and 198.51.100.x are TEST-NET documentation ranges — dropped
        // too, confirming documentation addresses never get probed.
        assert!(
            got.is_empty(),
            "documentation/internal addresses are dropped: {got:?}"
        );

        // Public, routable addresses survive and dedupe in first-seen order.
        let public = vec!["8.8.8.8, 1.1.1.1", "text 8.8.8.8 again", "9.9.9.9"];
        let got = parse_candidate_ips(public);
        assert_eq!(got, vec!["8.8.8.8", "1.1.1.1", "9.9.9.9"]);
    }

    #[test]
    fn cap_truncates_and_reports_dropped() {
        let big: Vec<String> = (0..(MAX_CANDIDATES + 3))
            .map(|i| format!("1.2.3.{i}"))
            .collect();
        let (kept, dropped) = cap_candidates(big, MAX_CANDIDATES);
        assert_eq!(kept.len(), MAX_CANDIDATES);
        assert_eq!(dropped, 3);
    }

    // --- Content comparison (task 3) -------------------------------------------

    #[test]
    fn content_matches_same_page_and_rejects_different() {
        let page = "<html><head><title>Acme</title></head><body>Welcome to Acme</body></html>";
        // Byte-identical → match.
        assert!(content_matches(page.as_bytes(), page.as_bytes()));
        // Trivial whitespace reformatting → still a match.
        let reflowed =
            "<html><head><title>Acme</title></head>\n  <body>Welcome to Acme</body></html>";
        assert!(content_matches(page.as_bytes(), reflowed.as_bytes()));
        // A materially different (much longer) page → not a match.
        let other = format!("<html><body>{}</body></html>", "unrelated ".repeat(50));
        assert!(!content_matches(page.as_bytes(), other.as_bytes()));
    }

    // --- Confirmation rules (tasks 3, 4, and the task-6 scenario) --------------

    #[test]
    fn confirms_matching_candidate_without_cdn_markers() {
        let page = "<html><body>the real origin site, served identically</body></html>";
        // Perimeter baseline: the site, fronted by Cloudflare.
        let baseline = resp(200, &[("cf-ray", "7d1b"), ("server", "cloudflare")], page);

        // A candidate IP that serves the SAME content with NO CDN markers → origin.
        let origin = resp(200, &[("server", "nginx")], page);
        assert!(is_confirmed_origin(&baseline, &origin));
    }

    #[test]
    fn does_not_confirm_different_content() {
        let baseline = resp(
            200,
            &[("cf-ray", "7d1b"), ("server", "cloudflare")],
            "<html><body>the real origin site</body></html>",
        );
        // A shared-host IP serving an unrelated (materially different) page → not
        // the origin, so it is not reported.
        let unrelated = resp(
            200,
            &[("server", "nginx")],
            &format!("<html><body>{}</body></html>", "parked domain ".repeat(40)),
        );
        assert!(!is_confirmed_origin(&baseline, &unrelated));
    }

    #[test]
    fn does_not_confirm_when_candidate_still_shows_cdn_markers() {
        let page = "<html><body>identical content</body></html>";
        let baseline = resp(200, &[("cf-ray", "7d1b"), ("server", "cloudflare")], page);
        // Same content, but the candidate still carries CDN markers → it is another
        // edge, not the origin behind the perimeter.
        let another_edge = resp(200, &[("cf-ray", "9a2c"), ("server", "cloudflare")], page);
        assert!(!is_confirmed_origin(&baseline, &another_edge));
    }

    // --- Finding construction (task 4) -----------------------------------------

    #[test]
    fn finding_names_host_and_origin_ip() {
        let page = "<html><body>site</body></html>";
        let baseline = resp(200, &[("cf-ray", "7d1b"), ("server", "cloudflare")], page);
        let origin = resp(200, &[("server", "nginx")], page);
        let finding = finding_for(
            &target(),
            "example.com",
            "203.0.113.7",
            "Cloudflare",
            &baseline,
            &origin,
        );

        assert_eq!(finding.scanner_id, "origin_discovery");
        assert_eq!(finding.status, Status::Vulnerable);
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.title.contains("example.com"));
        assert!(finding.title.contains("203.0.113.7"));
        assert!(finding.recommendations.is_some());
        let evidence = finding.evidence.unwrap();
        assert_eq!(evidence["host"], "example.com");
        assert_eq!(evidence["origin_ip"], "203.0.113.7");
        assert_eq!(evidence["fronting_cdn"], "Cloudflare");
        assert_eq!(evidence["confirmed"], true);
    }
}
