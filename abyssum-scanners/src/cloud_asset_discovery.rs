//! Forgotten cloud-asset discovery — surfacing the object-storage buckets an
//! organization left exposed and forgot about.
//!
//! Exposed object-storage (a world-listable S3/GCS/Azure bucket) is among the
//! highest-impact forgotten assets: a public bucket leaks its contents outright.
//! [`CloudAssetDiscoveryScanner`] takes a target's domain, guesses likely
//! bucket/asset names by permuting the domain and organization identifier with a
//! built-in affix list, and probes the known cloud-provider storage endpoints for
//! each guess.
//!
//! Each probe is classified from its response:
//!
//! - **does not exist** — the candidate resolves to no asset (`404`, or a transport
//!   failure). Not reported.
//! - **exists but access-denied** — the asset is there but not readable (`401`/`403`,
//!   or a provider redirect). Reported as an informational footprint finding.
//! - **exists and publicly readable/listable** — the list endpoint returns `2xx`.
//!   Reported at **high** severity as a data-exposure finding.
//!
//! Like every scanner it owns none of the cross-cutting concerns: every probe goes
//! through [`ScanContext::send`], so pacing, the rotating User-Agent, cancellation,
//! and progress all apply and the stealth floor cannot be bypassed. Guessing many
//! names could balloon into a lot of traffic, so the candidate set is capped and the
//! truncation logged rather than probing an unbounded list silently.
//!
//! **Scope line — existence and exposure only.** A probe is a single GET to the
//! bucket/list endpoint; the *status* is the proof (a `2xx` list response confirms
//! public readability). The scanner never reads the returned listing body, follows
//! into object keys, or downloads object contents — it confirms the exposure and
//! stops there.

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
const ID: &str = "cloud_asset_discovery";

/// Built-in affixes permuted against the target's domain/organization identifier to
/// form candidate bucket/asset names (as `base-<affix>` and `<affix>-base`). A small
/// curated set of the environment/purpose tokens real buckets are named with; the
/// wordlist mechanism can supply more later (see `roadmap/`).
const AFFIXES: &[&str] = &[
    "dev", "prod", "staging", "stage", "test", "qa", "assets", "static", "media", "backup",
    "backups", "data", "files", "uploads", "public", "private", "internal", "cdn", "images",
    "logs", "archive", "db",
];

/// Second-level labels that are effectively public suffixes (e.g. `co` in
/// `example.co.uk`), so the organization identifier is the label to their *left*.
/// A heuristic, not the full Public Suffix List — enough to not mistake `co`/`com`
/// for the org name on the common multi-part ccTLDs.
///
/// ponytail: heuristic 2LD list; swap in a real PSL crate if org-name accuracy on
/// exotic ccTLDs ever matters.
const SECOND_LEVEL_PUBLIC: &[&str] = &[
    "co", "com", "org", "net", "gov", "edu", "ac", "gob", "or", "ne",
];

/// Upper bound on how many candidate names are probed in one run. Each candidate is
/// probed against every provider, so the total request count is this times the
/// provider count; beyond the cap the candidate set is truncated and the drop is
/// logged, never silent.
const MAX_CANDIDATES: usize = 256;

/// A cloud object-storage provider: a display name and a URL template whose `{name}`
/// placeholders are replaced with the candidate to form the probe URL.
#[derive(Debug, Clone)]
struct Provider {
    /// Human-readable provider name for findings (e.g. `"Amazon S3"`).
    name: String,
    /// Probe-URL template. `{name}` is substituted with the candidate; the endpoint
    /// is the bucket root / container-list so a `2xx` confirms public listability.
    template: String,
}

impl Provider {
    fn new(name: impl Into<String>, template: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            template: template.into(),
        }
    }

    /// The probe URL for `candidate`, or `None` when substitution does not yield a
    /// valid absolute URL (skipped, never fatal).
    fn url_for(&self, candidate: &str) -> Option<Url> {
        Url::parse(&self.template.replace("{name}", candidate)).ok()
    }
}

/// The production providers. The endpoints are the bucket root (S3 virtual-host,
/// GCS path style) or the container-list query (Azure Blob), so a `2xx` response is
/// itself the proof of public readability/listability — no object read is needed.
fn default_providers() -> Vec<Provider> {
    vec![
        Provider::new("Amazon S3", "https://{name}.s3.amazonaws.com/"),
        Provider::new(
            "Google Cloud Storage",
            "https://storage.googleapis.com/{name}",
        ),
        Provider::new(
            "Azure Blob Storage",
            "https://{name}.blob.core.windows.net/{name}?restype=container&comp=list",
        ),
    ]
}

/// How a [`CloudAssetDiscoveryScanner`] obtains the candidate names to probe.
enum Candidates {
    /// Permute the target's own domain/organization identifier (production).
    Generate,
    /// A fixed, pre-formed candidate list — bypasses generation. Used by tests and
    /// by callers supplying their own names.
    Fixed(Vec<String>),
}

/// Discovers forgotten/exposed cloud-storage assets for a target by guessing likely
/// names and probing the cloud providers.
pub struct CloudAssetDiscoveryScanner {
    candidates: Candidates,
    providers: Vec<Provider>,
}

impl CloudAssetDiscoveryScanner {
    /// The stable scanner id, exposed for registration and selection.
    pub const ID: &'static str = ID;

    /// Build the production scanner: candidates generated from the target's domain,
    /// probed against the built-in cloud providers.
    pub fn new() -> Self {
        Self {
            candidates: Candidates::Generate,
            providers: default_providers(),
        }
    }

    /// Use a fixed candidate list instead of generating from the domain (for tests
    /// and callers supplying their own names). Entries are sanitized/deduplicated
    /// like generated ones.
    pub fn with_candidates<I, S>(mut self, candidates: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.candidates = Candidates::Fixed(candidates.into_iter().map(Into::into).collect());
        self
    }

    /// Replace the probed providers with `(name, template)` pairs (for tests that
    /// point probing at a local mock). Each template's `{name}` placeholder is the
    /// candidate.
    pub fn with_providers<I, N, T>(mut self, providers: I) -> Self
    where
        I: IntoIterator<Item = (N, T)>,
        N: Into<String>,
        T: Into<String>,
    {
        self.providers = providers
            .into_iter()
            .map(|(name, template)| Provider::new(name, template))
            .collect();
        self
    }

    /// The sanitized, deduplicated candidate names for `host`.
    fn candidate_names(&self, host: &str) -> Vec<String> {
        match &self.candidates {
            Candidates::Fixed(list) => sanitize(list.iter()),
            Candidates::Generate => generate_candidates(host),
        }
    }
}

impl Default for CloudAssetDiscoveryScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BaseScanner for CloudAssetDiscoveryScanner {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "Cloud Asset Discovery"
    }

    fn description(&self) -> &str {
        "Discovers forgotten/exposed cloud-storage assets for a target by permuting its \
         domain and organization identifier into likely bucket names and probing the known \
         cloud-provider storage endpoints (S3/GCS/Azure). Assets that exist are reported; \
         those that are publicly readable or listable are reported at high severity as a \
         data-exposure finding. Non-existent candidates are not reported. Existence and \
         exposure only: it confirms the exposure from the response status and never \
         downloads or enumerates object contents."
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        self.validate_target(target)?;
        // `validate_target` guarantees a host.
        let host = target.host().unwrap_or_default().to_ascii_lowercase();

        let (candidates, dropped) = cap_candidates(self.candidate_names(&host), MAX_CANDIDATES);
        if dropped > 0 {
            tracing::warn!(
                scanner = ID,
                host = %host,
                cap = MAX_CANDIDATES,
                dropped,
                "candidate set exceeded the probe cap; \
                 probing the first {MAX_CANDIDATES} and dropping {dropped}"
            );
        }

        let total = candidates.len();
        let mut findings = Vec::new();

        for (index, name) in candidates.iter().enumerate() {
            // Stop promptly on cancellation, returning what has been found so far.
            if ctx.is_cancelled() {
                break;
            }
            for provider in &self.providers {
                if ctx.is_cancelled() {
                    break;
                }
                let Some(url) = provider.url_for(name) else {
                    // A candidate that will not form a URL for this provider is
                    // skipped, never fatal.
                    continue;
                };
                match probe_status(ctx, url.clone()).await {
                    Ok(status) => match classify(status) {
                        // Publicly readable/listable — the high-value data exposure.
                        Classification::Public => {
                            findings.push(public_finding(target, name, provider, &url, status));
                        }
                        // Exists but not readable — the informational footprint.
                        Classification::Exists => {
                            findings.push(footprint_finding(target, name, provider, &url, status));
                        }
                        // Does not exist — not reported.
                        Classification::Absent => {}
                    },
                    // Cancellation is not a per-probe failure: surface it.
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(err) => {
                        // A transport failure means this candidate is unreachable at
                        // this provider (treated as does-not-exist) — routine when
                        // guessing names; skip it and keep probing the rest.
                        tracing::debug!(
                            scanner = ID,
                            candidate = %name,
                            provider = %provider.name,
                            error = %err,
                            "cloud-asset probe failed; treating candidate as non-existent"
                        );
                    }
                }
            }
            ctx.report_progress(progress(index + 1, total, name));
        }

        Ok(findings)
    }
}

/// Register the cloud-asset-discovery scanner under its stable id. Its affix list
/// and provider endpoints are inline defaults, so it reads no seeded store.
pub fn register(registry: &mut ScannerRegistry) {
    let factory: ScannerFactory =
        Arc::new(|_config| Box::new(CloudAssetDiscoveryScanner::new()) as Box<dyn BaseScanner>);
    registry.register(ID, factory);
}

/// How a probe response is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Classification {
    /// `2xx` on the list endpoint — the asset exists and is publicly readable/listable.
    Public,
    /// Exists but is not readable: access-denied (`401`/`403`) or a provider redirect
    /// (a `3xx` region/endpoint redirect still means the asset is there).
    Exists,
    /// No asset (a `404`, or any other status) — not reported.
    Absent,
}

/// Classify a probe from its HTTP status alone. The list endpoints return `2xx` when
/// public, `401`/`403` when the asset exists but is locked down, a redirect when the
/// asset exists at another endpoint/region, and `404` when there is no such asset.
fn classify(status: u16) -> Classification {
    match status {
        200..=299 => Classification::Public,
        301 | 302 | 307 | 308 | 401 | 403 => Classification::Exists,
        _ => Classification::Absent,
    }
}

/// Send one GET through the paced scan context and return only the response status.
/// The status is all classification needs — a `2xx` list response is itself the
/// proof of public readability — so the response body (the object listing) is
/// **never read**: its contents are neither downloaded nor enumerated, and no object
/// key can surface in a finding. This is what keeps the scanner to existence/exposure
/// confirmation only. The unread body is dropped with the response.
///
/// The probe is sent **without** the target's credential: probes go to third-party
/// cloud-provider hosts (and, since the scanner guesses bucket names, potentially to
/// an attacker-squatted bucket), so attaching the target's bearer token / cookie
/// would leak it. Mirrors the BAC scanner's `probe`.
async fn probe_status(ctx: &ScanContext, url: Url) -> Result<u16> {
    let response = ctx.send(RequestSpec::get(url).without_credential()).await?;
    Ok(response.status().as_u16())
}

/// Build the high-severity finding for a publicly readable/listable asset.
fn public_finding(
    target: &Target,
    name: &str,
    provider: &Provider,
    url: &Url,
    status: u16,
) -> Finding {
    Finding::builder(
        ID,
        target.clone(),
        format!(
            "Publicly readable cloud storage asset: {name} ({provider})",
            provider = provider.name
        ),
    )
    .status(Status::Vulnerable)
    .severity(Severity::High)
    .description(format!(
        "The {provider} storage asset '{name}' exists and is publicly readable/listable: its \
         list endpoint returned HTTP {status}, so its contents are exposed to anyone. This is a \
         forgotten/misconfigured asset leaking data. Existence and exposure were confirmed from \
         the response status only — the asset's contents were not downloaded or enumerated.",
        provider = provider.name,
    ))
    .evidence(serde_json::json!({
        "candidate": name,
        "provider": provider.name,
        "probed_url": url.as_str(),
        "status": status,
        "public": true,
    }))
    .recommendations(format!(
        "Remove public read/list access from the {provider} asset '{name}' (tighten its ACL / \
         bucket policy), or delete it if it is no longer needed.",
        provider = provider.name,
    ))
    .build()
}

/// Build the informational footprint finding for an asset that exists but is not
/// publicly readable.
fn footprint_finding(
    target: &Target,
    name: &str,
    provider: &Provider,
    url: &Url,
    status: u16,
) -> Finding {
    Finding::builder(
        ID,
        target.clone(),
        format!(
            "Cloud storage asset exists: {name} ({provider})",
            provider = provider.name
        ),
    )
    .status(Status::Info)
    .severity(Severity::Info)
    .description(format!(
        "The {provider} storage asset '{name}' exists but is not publicly readable (its list \
         endpoint returned HTTP {status}). It is recorded as part of the target's cloud \
         footprint — a real asset an attacker could target, even though its contents are not \
         currently exposed.",
        provider = provider.name,
    ))
    .evidence(serde_json::json!({
        "candidate": name,
        "provider": provider.name,
        "probed_url": url.as_str(),
        "status": status,
        "public": false,
    }))
    .build()
}

/// The base tokens for `host`: its organization/domain identifier plus the dashed
/// and concatenated full-domain forms. `www.example.com` and `api.example.com` both
/// yield `example`, `example-com`, `examplecom`; a bare single-label host yields
/// itself.
fn base_tokens(host: &str) -> Vec<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    // Drop a leading `www.` so it does not become the organization identifier.
    let labels: &[&str] = match labels.split_first() {
        Some((&"www", rest)) if !rest.is_empty() => rest,
        _ => &labels,
    };

    let mut tokens = Vec::new();
    match labels {
        [] => {}
        [single] => tokens.push((*single).to_string()),
        [.., sld, tld] => {
            tokens.push((*sld).to_string()); // example
            tokens.push(format!("{sld}-{tld}")); // example-com
            tokens.push(format!("{sld}{tld}")); // examplecom
            // On a multi-part public suffix (example.co.uk), the label left of the
            // 2LD-public is the real organization identifier.
            if labels.len() >= 3 && SECOND_LEVEL_PUBLIC.contains(sld) {
                tokens.push(labels[labels.len() - 3].to_string());
            }
        }
    }
    tokens
}

/// Permute `host`'s base tokens with the built-in affix list into candidate asset
/// names, then sanitize and deduplicate. Pure (no network) so it is unit-testable.
fn generate_candidates(host: &str) -> Vec<String> {
    let mut raw = Vec::new();
    for base in base_tokens(host) {
        raw.push(base.clone());
        for affix in AFFIXES {
            raw.push(format!("{base}-{affix}"));
            raw.push(format!("{affix}-{base}"));
        }
    }
    sanitize(raw.iter())
}

/// Normalize, validate, and deduplicate candidate names (first occurrence wins, so
/// truncation at the cap is deterministic). Names that are not valid object-storage
/// bucket names are dropped so no malformed probe is issued.
fn sanitize<I, S>(raw: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in raw {
        let name = entry.as_ref().trim().to_ascii_lowercase();
        if !is_valid_bucket_name(&name) {
            continue;
        }
        if seen.insert(name.clone()) {
            out.push(name);
        }
    }
    out
}

/// Whether `name` is a valid object-storage bucket name: 3–63 chars, lowercase
/// letters / digits / hyphens, not starting or ending with a hyphen. This is the
/// common intersection of the S3/GCS/Azure naming rules — enough to skip candidates
/// that would only ever produce a malformed request.
fn is_valid_bucket_name(name: &str) -> bool {
    (3..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// Truncate `candidates` to at most `cap`, returning the kept prefix and how many
/// were dropped. Split out of `scan` so the cap-and-log decision is unit-testable
/// without issuing any requests.
fn cap_candidates(mut candidates: Vec<String>, cap: usize) -> (Vec<String>, usize) {
    let dropped = candidates.len().saturating_sub(cap);
    candidates.truncate(cap);
    (candidates, dropped)
}

/// Build a scanner-internal progress update for the candidate at `completed` of
/// `total`, naming the candidate currently being probed.
fn progress(completed: usize, total: usize, name: &str) -> ProgressUpdate {
    ProgressUpdate::new(ID, completed, total)
        .current_item(name.to_string())
        .message(format!("probing {completed}/{total}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    fn provider() -> Provider {
        Provider::new("Amazon S3", "https://{name}.s3.amazonaws.com/")
    }

    // --- Metadata --------------------------------------------------------------

    #[test]
    fn metadata_is_stable() {
        let scanner = CloudAssetDiscoveryScanner::new();
        assert_eq!(scanner.id(), "cloud_asset_discovery");
        assert_eq!(CloudAssetDiscoveryScanner::ID, "cloud_asset_discovery");
        assert!(!scanner.name().is_empty());
        assert!(!scanner.description().is_empty());
    }

    // --- Candidate generation (task 1) -----------------------------------------

    #[test]
    fn base_tokens_derive_org_identifier() {
        assert_eq!(
            base_tokens("example.com"),
            vec![
                "example".to_string(),
                "example-com".to_string(),
                "examplecom".to_string(),
            ]
        );
        // A subdomain and a leading www both reduce to the same org identifier.
        assert_eq!(base_tokens("api.example.com")[0], "example");
        assert_eq!(base_tokens("www.example.com")[0], "example");
        // A multi-part public suffix: the label left of `co` is the org identifier.
        assert!(base_tokens("example.co.uk").contains(&"example".to_string()));
        // A bare single label yields itself.
        assert_eq!(base_tokens("localhost"), vec!["localhost".to_string()]);
    }

    #[test]
    fn generate_permutes_with_affixes_and_dedupes() {
        let got = generate_candidates("example.com");
        // The bare org identifier and its permutations are present.
        assert!(got.contains(&"example".to_string()));
        assert!(got.contains(&"example-dev".to_string()));
        assert!(got.contains(&"dev-example".to_string()));
        assert!(got.contains(&"example-backup".to_string()));
        // No duplicates.
        let mut deduped = got.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), got.len(), "candidates are unique");
    }

    #[test]
    fn sanitize_drops_invalid_bucket_names_and_dedupes() {
        let raw = [
            "Example",     // -> example (lowercased)
            "example",     // dup
            "ab",          // too short (<3), dropped
            "-example",    // leading hyphen, dropped
            "example-",    // trailing hyphen, dropped
            "under_score", // illegal char, dropped
            "  spaced  ",  // trimmed -> spaced
        ];
        assert_eq!(
            sanitize(raw.iter()),
            vec!["example".to_string(), "spaced".to_string()]
        );
    }

    #[test]
    fn is_valid_bucket_name_enforces_the_common_rules() {
        assert!(is_valid_bucket_name("my-bucket-1"));
        assert!(!is_valid_bucket_name("ab")); // too short
        assert!(!is_valid_bucket_name(&"a".repeat(64))); // too long
        assert!(!is_valid_bucket_name("-lead"));
        assert!(!is_valid_bucket_name("trail-"));
        assert!(!is_valid_bucket_name("Upper"));
        assert!(!is_valid_bucket_name("has_underscore"));
    }

    // --- Classification (task 3) -----------------------------------------------

    #[test]
    fn classify_maps_status_to_the_three_outcomes() {
        assert_eq!(classify(200), Classification::Public);
        assert_eq!(classify(206), Classification::Public);
        assert_eq!(classify(403), Classification::Exists);
        assert_eq!(classify(401), Classification::Exists);
        assert_eq!(classify(301), Classification::Exists);
        assert_eq!(classify(404), Classification::Absent);
        assert_eq!(classify(500), Classification::Absent);
    }

    // --- Cap + truncation logging (task 6) -------------------------------------

    #[test]
    fn cap_truncates_and_reports_dropped() {
        let small: Vec<String> = (0..3).map(|i| format!("b{i}-bucket")).collect();
        let (kept, dropped) = cap_candidates(small.clone(), MAX_CANDIDATES);
        assert_eq!(kept, small);
        assert_eq!(dropped, 0);

        let big: Vec<String> = (0..(MAX_CANDIDATES + 4))
            .map(|i| format!("b{i}-bucket"))
            .collect();
        let (kept, dropped) = cap_candidates(big, MAX_CANDIDATES);
        assert_eq!(kept.len(), MAX_CANDIDATES);
        assert_eq!(dropped, 4);
    }

    // --- Finding construction (task 4) -----------------------------------------

    #[test]
    fn public_finding_is_high_severity_data_exposure() {
        let url = Url::parse("https://example-assets.s3.amazonaws.com/").unwrap();
        let finding = public_finding(&target(), "example-assets", &provider(), &url, 200);
        assert_eq!(finding.scanner_id, "cloud_asset_discovery");
        assert_eq!(finding.status, Status::Vulnerable);
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.title.contains("example-assets"));
        assert!(finding.title.contains("Amazon S3"));
        assert!(finding.recommendations.is_some());
        let ev = finding.evidence.unwrap();
        assert_eq!(ev["candidate"], "example-assets");
        assert_eq!(ev["provider"], "Amazon S3");
        assert_eq!(ev["public"], true);
        assert_eq!(ev["status"], 200);
    }

    #[test]
    fn footprint_finding_is_info() {
        let url = Url::parse("https://example-backup.s3.amazonaws.com/").unwrap();
        let finding = footprint_finding(&target(), "example-backup", &provider(), &url, 403);
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.title.contains("example-backup"));
        let ev = finding.evidence.unwrap();
        assert_eq!(ev["public"], false);
        assert_eq!(ev["status"], 403);
    }

    // --- Provider URL templating -----------------------------------------------

    #[test]
    fn provider_substitutes_candidate_into_template() {
        let azure = Provider::new(
            "Azure Blob Storage",
            "https://{name}.blob.core.windows.net/{name}?restype=container&comp=list",
        );
        let url = azure.url_for("acme").unwrap();
        assert_eq!(
            url.as_str(),
            "https://acme.blob.core.windows.net/acme?restype=container&comp=list"
        );
    }
}
