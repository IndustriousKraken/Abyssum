//! Subdomain reconnaissance — passive surface mapping, first slice.
//!
//! [`SubdomainReconScanner`] takes an apex domain, discovers candidate subdomains
//! from **passive** certificate-transparency / passive-DNS sources (a CT-log
//! aggregator such as crt.sh — querying a third party, never brute-forcing the
//! target's own DNS), probes each candidate for liveness, and flags subdomain
//! takeover from the probe response.
//!
//! Like every scanner it owns none of the cross-cutting concerns: every source
//! query and every probe goes through [`ScanContext::send`], so the pacing floor,
//! the rotating User-Agent, cancellation, and progress all apply and the stealth
//! floor cannot be bypassed. The per-domain rate limiter gives each distinct host
//! its first request free, so probing many discovered hosts spreads across them
//! rather than hammering one — consistent with the stealth posture.
//!
//! ## What is reported
//!
//! - A **live** subdomain (any HTTP response received) → an informational finding
//!   recording the host. A candidate that fails to connect is dead and is not
//!   reported.
//! - A live subdomain whose response body matches a known **unclaimed-service
//!   fingerprint** (the classic "can-I-take-over-X" signatures — an S3
//!   `NoSuchBucket` body, a GitHub Pages 404, a Heroku "no such app" page, …) →
//!   a high-severity vulnerable finding naming the subdomain and the suspected
//!   service, *instead of* the plain info finding (one finding per host).
//!
//! Takeover detection here is HTTP-fingerprint based and needs no DNS-resolver
//! dependency; CNAME-chain confirmation and active DNS brute-force are follow-on
//! slices (see `roadmap/deep-surface-mapping.md`).

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use url::Url;

use abyssum_core::{
    BaseScanner, Error, Finding, ProgressUpdate, RequestSpec, Result, ScanContext, ScannerFactory,
    ScannerRegistry, Severity, Status, Target,
};

/// The stable scanner id. The registry keys on this and a scan selects by it; it
/// must never change.
const ID: &str = "subdomain_recon";

/// The default passive source: a certificate-transparency log aggregator. Queried
/// as `{base}/?q=%.<apex>&output=json`, returning the certificate names observed
/// for the apex — a passive, third-party lookup, not a query against the target's
/// own DNS.
const CRTSH_BASE: &str = "https://crt.sh";

/// Upper bound on how many deduplicated candidates are probed in one run. Passive
/// sources can return thousands of historical names for a busy apex; probing all
/// of them would be neither stealthy nor timely, so the set is capped and the
/// truncation is logged rather than silently dropped.
const MAX_CANDIDATES: usize = 512;

/// Upper bound on the response body buffered per probe. A discovered subdomain is
/// untrusted and could stream an unbounded (or maliciously large) response; the
/// takeover fingerprints all appear near the top of a short error page, so a
/// capped prefix is sufficient and the rest is never read into memory.
const MAX_BODY_BYTES: usize = 512 * 1024;

/// Known unclaimed-service takeover fingerprints: `(service, lowercase body
/// marker)`. A live subdomain whose response body contains a marker is pointing
/// at a third-party service that no longer claims it — an attacker who registers
/// that resource then controls the subdomain. Markers are stored lowercase and
/// matched against a lowercased response body (case-insensitive substring).
///
/// This is the HTTP-fingerprint slice; each entry is the distinctive text the
/// unclaimed service serves. Sourced from the public "can-i-take-over-xyz"
/// corpus; extend it as new services are catalogued.
const TAKEOVER_SIGNATURES: &[(&str, &str)] = &[
    ("Amazon S3", "the specified bucket does not exist"),
    ("GitHub Pages", "there isn't a github pages site here"),
    ("Heroku", "no-such-app.html"),
    ("Fastly", "fastly error: unknown domain"),
    ("Shopify", "sorry, this shop is currently unavailable"),
    ("Surge.sh", "project not found"),
    ("Bitbucket", "repository not found"),
    (
        "Tumblr",
        "whatever you were looking for doesn't currently exist at this address",
    ),
    ("Zendesk", "help center closed"),
    (
        "Pantheon",
        "the gods are wise, but do not know of the site which you seek",
    ),
    ("Ghost", "the thing you were looking for is no longer here"),
    ("Read the Docs", "unknown to read the docs"),
];

/// Where a [`SubdomainReconScanner`] draws its candidate subdomains.
enum Discovery {
    /// Query a passive certificate-transparency source live, through the paced
    /// request path (production). Holds the source base URL so tests can point it
    /// at a local mock.
    Passive { crtsh_base: Url },
    /// A fixed, in-memory candidate list. Bypasses the network entirely — used by
    /// tests that stub the passive source, and by callers that supply their own
    /// candidate hosts.
    Fixed(Vec<String>),
}

/// Discovers subdomains from passive sources, probes them for liveness, and flags
/// subdomain takeover.
pub struct SubdomainReconScanner {
    discovery: Discovery,
}

impl SubdomainReconScanner {
    /// The stable scanner id, exposed for registration and selection.
    pub const ID: &'static str = ID;

    /// Build the production scanner: passive discovery via the default crt.sh
    /// certificate-transparency aggregator.
    pub fn new() -> Self {
        Self {
            discovery: Discovery::Passive {
                // The default base is a valid absolute URL, so this never fails.
                crtsh_base: Url::parse(CRTSH_BASE).expect("CRTSH_BASE is a valid URL"),
            },
        }
    }

    /// Build a scanner whose passive source is the crt.sh-style endpoint at
    /// `base` (for tests that point discovery at a local mock).
    pub fn with_source_base(base: Url) -> Self {
        Self {
            discovery: Discovery::Passive { crtsh_base: base },
        }
    }

    /// Build a scanner over a fixed, in-memory candidate list — the passive source
    /// stubbed out (no source query is issued). Entries are normalized and
    /// deduplicated just like passively-discovered names.
    pub fn with_candidates<I, S>(candidates: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            discovery: Discovery::Fixed(candidates.into_iter().map(Into::into).collect()),
        }
    }

    /// Gather the raw candidate names for `apex` from the configured source. Every
    /// passive query goes through [`ScanContext::send`], so it is paced and carries
    /// a rotating User-Agent.
    async fn discover(&self, apex: &str, ctx: &ScanContext) -> Result<Vec<String>> {
        match &self.discovery {
            Discovery::Fixed(list) => Ok(list.clone()),
            Discovery::Passive { crtsh_base } => crtsh_query(crtsh_base, apex, ctx).await,
        }
    }
}

impl Default for SubdomainReconScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BaseScanner for SubdomainReconScanner {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "Subdomain Reconnaissance"
    }

    fn description(&self) -> &str {
        "Discovers subdomains of an apex domain from passive certificate-transparency \
         sources (no DNS brute-force), probes each for liveness, reports live hosts as \
         the discovered attack surface, and flags subdomain takeover when a probe \
         response matches a known unclaimed-service fingerprint."
    }

    /// Requires a bare host with no path: the target is an apex domain, not an
    /// endpoint. (`https://example.com` is accepted; `https://example.com/api` is
    /// rejected.)
    fn validate_target(&self, target: &Target) -> Result<()> {
        if target.host().is_none() {
            return Err(Error::Target(format!(
                "subdomain recon target has no host: {}",
                target.base_url()
            )));
        }
        let bare = target.path().is_none() && matches!(target.base_url().path(), "" | "/");
        if !bare {
            return Err(Error::Target(format!(
                "subdomain recon target must be a bare host with no path: {}",
                target.full_url()
            )));
        }
        Ok(())
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        self.validate_target(target)?;
        // `validate_target` guarantees a host.
        let apex = target.host().unwrap_or_default().to_ascii_lowercase();
        let scheme = target.base_url().scheme();

        let raw = self.discover(&apex, ctx).await?;
        let candidates = normalize_candidates(raw, &apex);

        // Cap the probe set to a sane bound, logging the truncation rather than
        // silently dropping the tail.
        let (candidates, dropped) = cap_candidates(candidates, MAX_CANDIDATES);
        if dropped > 0 {
            tracing::warn!(
                scanner = ID,
                apex = %apex,
                cap = MAX_CANDIDATES,
                dropped,
                "passive source returned more candidates than the probe cap; \
                 probing the first {MAX_CANDIDATES} and dropping {dropped}"
            );
        }

        let total = candidates.len();
        let mut findings = Vec::new();

        for (index, host) in candidates.iter().enumerate() {
            // Stop promptly on cancellation, returning the findings gathered so far.
            if ctx.is_cancelled() {
                break;
            }

            let url = match Url::parse(&format!("{scheme}://{host}/")) {
                Ok(url) => url,
                Err(_) => {
                    // A candidate that will not form a URL is skipped, never fatal.
                    ctx.report_progress(progress(index + 1, total, host));
                    continue;
                }
            };

            match probe(ctx, url.clone()).await {
                Ok(response) => {
                    findings.push(finding_for(target, host, &url, &response));
                }
                // Cancellation is not a per-host failure: surface it rather than
                // masking it as a dead candidate.
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(err) => {
                    // Unlike single-host scanners, a probe failure here means *this
                    // candidate* is unreachable (dead subdomain) — an expected,
                    // routine outcome in recon. Skip it and keep probing the rest
                    // rather than aborting the whole surface map.
                    tracing::debug!(
                        scanner = ID,
                        host = %host,
                        error = %err,
                        "candidate did not respond; treating as dead"
                    );
                }
            }

            ctx.report_progress(progress(index + 1, total, host));
        }

        Ok(findings)
    }
}

/// Register the subdomain-recon scanner under its stable id. It carries no seeded
/// store (its passive sources and takeover fingerprints are inline), so the
/// factory ignores the config it is handed.
pub fn register(registry: &mut ScannerRegistry) {
    let factory: ScannerFactory =
        Arc::new(|_config| Box::new(SubdomainReconScanner::new()) as Box<dyn BaseScanner>);
    registry.register(ID, factory);
}

/// A probed candidate reduced to the fields liveness + takeover classification
/// need. Its mere existence means the host is **live** (an HTTP response arrived);
/// a candidate that fails to connect never produces one.
#[derive(Debug, Clone)]
struct ProbeResponse {
    status: u16,
    body: Vec<u8>,
}

/// Build the finding for a live candidate: a takeover finding when the response
/// matches an unclaimed-service fingerprint, otherwise an informational
/// live-subdomain finding.
fn finding_for(target: &Target, host: &str, url: &Url, response: &ProbeResponse) -> Finding {
    match match_takeover(&response.body) {
        Some(service) => Finding::builder(
            ID,
            target.clone(),
            format!("Potential subdomain takeover: {host} ({service})"),
        )
        .status(Status::Vulnerable)
        .severity(Severity::High)
        .description(format!(
            "The discovered subdomain {host} resolves to an unclaimed {service} \
             endpoint: its response ({}) matches a known {service} \
             \"no such resource\" fingerprint. A dangling DNS record like this lets an \
             attacker register the resource and serve content from the subdomain.",
            response.status
        ))
        .evidence(serde_json::json!({
            "host": host,
            "probed_url": url.as_str(),
            "status": response.status,
            "suspected_service": service,
            "takeover": true,
        }))
        .recommendations(format!(
            "Remove the dangling DNS record pointing {host} at the unclaimed {service} \
             resource, or re-claim that resource before an attacker does."
        ))
        .build(),
        None => Finding::builder(
            ID,
            target.clone(),
            format!("Discovered live subdomain {host}"),
        )
        .status(Status::Info)
        .severity(Severity::Info)
        .description(format!(
            "The subdomain {host} was discovered from a passive source and responded \
             when probed (HTTP {}); it is part of the reachable attack surface.",
            response.status
        ))
        .evidence(serde_json::json!({
            "host": host,
            "probed_url": url.as_str(),
            "status": response.status,
            "body_length": response.body.len(),
            "takeover": false,
        }))
        .build(),
    }
}

/// The suspected service if `body` matches a known unclaimed-service takeover
/// fingerprint, else `None`. Case-insensitive substring match.
fn match_takeover(body: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    TAKEOVER_SIGNATURES
        .iter()
        .find(|(_, marker)| text.contains(marker))
        .map(|(service, _)| *service)
}

/// Normalize and deduplicate raw candidate names against `apex` (already
/// lowercased). Each entry is trimmed, lowercased, stripped of a leading `*.`
/// wildcard label and any trailing dot; blanks, the apex itself, and duplicates
/// are dropped. Order is preserved (first occurrence wins) so truncation at the
/// cap is deterministic for a given source ordering.
fn normalize_candidates<I, S>(raw: I, apex: &str) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in raw {
        let name = entry
            .as_ref()
            .trim()
            .trim_end_matches('.')
            .trim_start_matches("*.")
            .trim()
            .to_ascii_lowercase();
        if name.is_empty() || name == apex {
            continue;
        }
        if seen.insert(name.clone()) {
            out.push(name);
        }
    }
    out
}

/// Truncate `candidates` to at most `cap`, returning the kept prefix and how many
/// were dropped. Splitting this out of `scan` keeps the cap-and-log decision
/// unit-testable without issuing any requests.
fn cap_candidates(mut candidates: Vec<String>, cap: usize) -> (Vec<String>, usize) {
    let dropped = candidates.len().saturating_sub(cap);
    candidates.truncate(cap);
    (candidates, dropped)
}

/// Query the crt.sh-style passive source at `base` for `apex`, through the paced
/// request path, and extract the certificate names it observed. A non-2xx
/// response, a transport failure, or an unparseable body yields no candidates
/// (logged) rather than failing the scan — discovery is best-effort.
async fn crtsh_query(base: &Url, apex: &str, ctx: &ScanContext) -> Result<Vec<String>> {
    let mut url = base.clone();
    // `?q=%.<apex>&output=json` — `query_pairs_mut` percent-encodes the SQL-LIKE
    // wildcard `%` for us, so the emitted query is `q=%25.<apex>`.
    url.query_pairs_mut()
        .clear()
        .append_pair("q", &format!("%.{apex}"))
        .append_pair("output", "json");

    let response = match probe(ctx, url).await {
        Ok(response) => response,
        Err(err) => {
            tracing::warn!(
                scanner = ID,
                apex = %apex,
                error = %err,
                "passive source query failed; continuing with no candidates"
            );
            return Ok(Vec::new());
        }
    };

    if !(200..300).contains(&response.status) {
        tracing::warn!(
            scanner = ID,
            apex = %apex,
            status = response.status,
            "passive source returned a non-success status; no candidates"
        );
        return Ok(Vec::new());
    }

    Ok(parse_crtsh(&response.body))
}

/// Parse a crt.sh JSON response body into the certificate names it lists. crt.sh
/// returns an array of objects each carrying `name_value` (newline-separated
/// names) and `common_name`; both are harvested. A body that does not parse as
/// the expected shape yields an empty list.
fn parse_crtsh(body: &[u8]) -> Vec<String> {
    let Ok(entries) = serde_json::from_slice::<Vec<serde_json::Value>>(body) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in &entries {
        if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
            for line in name_value.split('\n') {
                names.push(line.to_string());
            }
        }
        if let Some(common_name) = entry.get("common_name").and_then(|v| v.as_str()) {
            names.push(common_name.to_string());
        }
    }
    names
}

/// Probe one URL through the paced scan context, reducing the response to the
/// status and a length-capped body. The body is streamed through a bounded reader
/// that buffers at most [`MAX_BODY_BYTES`]: a probed host is untrusted and could
/// return an unbounded body, and the takeover fingerprints all sit near the top of
/// a short error page, so an oversized body is capped rather than read whole.
async fn probe(ctx: &ScanContext, url: Url) -> Result<ProbeResponse> {
    let mut response = ctx.send(RequestSpec::get(url)).await?;
    let status = response.status().as_u16();

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

    Ok(ProbeResponse { status, body })
}

/// Build a scanner-internal progress update for the candidate at `completed` of
/// `total`, naming the host currently being probed.
fn progress(completed: usize, total: usize, host: &str) -> ProgressUpdate {
    ProgressUpdate::new(ID, completed, total)
        .current_item(host.to_string())
        .message(format!("probing {completed}/{total}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    fn resp(status: u16, body: &str) -> ProbeResponse {
        ProbeResponse {
            status,
            body: body.as_bytes().to_vec(),
        }
    }

    // --- Metadata --------------------------------------------------------------

    #[test]
    fn metadata_is_stable() {
        let scanner = SubdomainReconScanner::new();
        assert_eq!(scanner.id(), "subdomain_recon");
        assert_eq!(SubdomainReconScanner::ID, "subdomain_recon");
        assert!(!scanner.name().is_empty());
        assert!(!scanner.description().is_empty());
    }

    // --- validate_target: bare host, no path -----------------------------------

    #[test]
    fn validate_target_requires_bare_host_no_path() {
        let scanner = SubdomainReconScanner::new();
        assert!(scanner.validate_target(&target()).is_ok());
        // A path beneath the origin is rejected.
        let with_path = Target::parse("https://example.com/api").unwrap();
        assert!(matches!(
            scanner.validate_target(&with_path),
            Err(Error::Target(_))
        ));
        // A separately-attached path is also rejected.
        let attached = Target::parse("https://example.com")
            .unwrap()
            .with_path("/admin");
        assert!(matches!(
            scanner.validate_target(&attached),
            Err(Error::Target(_))
        ));
        // No host at all is rejected.
        let hostless = Target::new(Url::parse("file:///tmp/x").unwrap(), None, None);
        assert!(matches!(
            scanner.validate_target(&hostless),
            Err(Error::Target(_))
        ));
    }

    // --- Candidate normalization + dedup ---------------------------------------

    #[test]
    fn normalize_dedupes_strips_wildcards_and_drops_apex() {
        let raw = vec![
            "API.example.com",      // -> api.example.com (lowercased)
            "api.example.com",      // dup
            "*.example.com",        // wildcard label stripped -> example.com == apex, dropped
            "www.example.com.",     // trailing dot stripped
            "example.com",          // apex itself, dropped
            "  mail.example.com  ", // trimmed
            "",                     // dropped
            "   ",                  // dropped
        ];
        let got = normalize_candidates(raw, "example.com");
        assert_eq!(
            got,
            vec![
                "api.example.com".to_string(),
                "www.example.com".to_string(),
                "mail.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn cap_truncates_and_reports_dropped_count() {
        // Under the cap: nothing dropped, list unchanged.
        let small: Vec<String> = (0..3).map(|i| format!("h{i}.example.com")).collect();
        let (kept, dropped) = cap_candidates(small.clone(), MAX_CANDIDATES);
        assert_eq!(kept, small);
        assert_eq!(dropped, 0);

        // Over the cap: truncated to the cap, dropped count reported (not silent).
        let big: Vec<String> = (0..(MAX_CANDIDATES + 5))
            .map(|i| format!("h{i}.example.com"))
            .collect();
        let (kept, dropped) = cap_candidates(big, MAX_CANDIDATES);
        assert_eq!(kept.len(), MAX_CANDIDATES);
        assert_eq!(dropped, 5);
    }

    // --- Takeover fingerprint matching -----------------------------------------

    #[test]
    fn matches_known_takeover_fingerprints_case_insensitively() {
        assert_eq!(
            match_takeover(b"<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"),
            Some("Amazon S3")
        );
        // Case-insensitive.
        assert_eq!(
            match_takeover(b"THERE ISN'T A GITHUB PAGES SITE HERE."),
            Some("GitHub Pages")
        );
        // A plain page matches nothing.
        assert_eq!(match_takeover(b"<html><body>welcome</body></html>"), None);
        assert_eq!(match_takeover(b""), None);
    }

    // --- Finding construction --------------------------------------------------

    #[test]
    fn takeover_response_yields_high_vulnerable_finding() {
        let url = Url::parse("https://api.example.com/").unwrap();
        let response = resp(404, "The specified bucket does not exist");
        let finding = finding_for(&target(), "api.example.com", &url, &response);
        assert_eq!(finding.scanner_id, "subdomain_recon");
        assert_eq!(finding.status, Status::Vulnerable);
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.title.contains("api.example.com"));
        assert!(finding.title.contains("Amazon S3"));
        assert!(finding.recommendations.is_some());
        let evidence = finding.evidence.unwrap();
        assert_eq!(evidence["host"], "api.example.com");
        assert_eq!(evidence["suspected_service"], "Amazon S3");
        assert_eq!(evidence["takeover"], true);
        assert_eq!(evidence["status"], 404);
    }

    #[test]
    fn plain_live_response_yields_info_finding() {
        let url = Url::parse("https://blog.example.com/").unwrap();
        let response = resp(200, "<html>hello</html>");
        let finding = finding_for(&target(), "blog.example.com", &url, &response);
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.title.contains("blog.example.com"));
        let evidence = finding.evidence.unwrap();
        assert_eq!(evidence["takeover"], false);
        assert_eq!(evidence["status"], 200);
    }

    // --- crt.sh JSON parsing ---------------------------------------------------

    #[test]
    fn parses_crtsh_names_including_multiline_and_common_name() {
        let body = br#"[
            {"name_value":"a.example.com\n*.b.example.com","common_name":"c.example.com"},
            {"name_value":"a.example.com","common_name":"d.example.com"}
        ]"#;
        let names = parse_crtsh(body);
        assert!(names.contains(&"a.example.com".to_string()));
        assert!(names.contains(&"*.b.example.com".to_string()));
        assert!(names.contains(&"c.example.com".to_string()));
        assert!(names.contains(&"d.example.com".to_string()));

        // A dedup+normalize pass collapses the wildcard and the duplicate.
        let candidates = normalize_candidates(names, "example.com");
        assert_eq!(
            candidates,
            vec![
                "a.example.com".to_string(),
                "b.example.com".to_string(),
                "c.example.com".to_string(),
                "d.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn parse_crtsh_tolerates_garbage() {
        assert!(parse_crtsh(b"not json").is_empty());
        assert!(parse_crtsh(b"{}").is_empty());
        assert!(parse_crtsh(b"[]").is_empty());
    }
}
