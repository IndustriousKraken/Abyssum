//! ASN / netblock enumeration — mapping a target to the IP footprint its owner
//! actually controls.
//!
//! Bug-bounty and assessment scope is usually an *organization*, not a single
//! host. [`AsnEnumerationScanner`] expands from one domain or IP to the autonomous
//! system (ASN) and the IP netblocks the owning organization has registered, so the
//! full external footprint is visible rather than the sliver a single-host view
//! shows.
//!
//! The flow is three steps, all through the paced request path so pacing, the
//! rotating User-Agent, cancellation, and progress apply and the stealth floor
//! cannot be bypassed:
//!
//! 1. **Resolve to an IP.** A target given as a domain is resolved to an IPv4
//!    address over DNS-over-HTTPS — the *same* paced DoH path the active
//!    subdomain brute-force uses, so no DNS-resolver dependency is added. A target
//!    already given as an IP literal skips this step.
//! 2. **Look up the owning ASN.** Query a registration-data source (RDAP/WHOIS +
//!    routing data, aggregated as HTTP/JSON so it reuses the paced request path with
//!    no new dependency) for the IP → the owning organization, its ASN, and the
//!    prefix covering the IP.
//! 3. **Enumerate the ASN's netblocks.** Query the same source for the prefixes the
//!    ASN announces → the organization's registered netblocks.
//!
//! The ASN and each discovered netblock are reported as findings naming the owning
//! organization (the enumerated footprint). A large organization can announce many
//! prefixes, so the netblock set is capped and the truncation logged rather than
//! emitting thousands of rows silently.
//!
//! **Scope line — enumeration only.** This is asset *enumeration*: it queries
//! registration-data sources about the target and never touches BGP. It does **not**
//! manipulate routing or perform any BGP action, and it does **not** scan the
//! enumerated ranges — probing a discovered netblock is the operator's separate,
//! scoped decision, made with the other scanners.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use abyssum_core::{
    BaseScanner, Error, Finding, ProgressUpdate, RequestSpec, Result, ScanContext, ScannerFactory,
    ScannerRegistry, Severity, Status, Target,
};

use crate::source_availability::{self, SourceIssue};

/// The stable scanner id. The registry keys on this and a scan selects by it; it
/// must never change.
const ID: &str = "asn_enumeration";

/// Names for the external sources this scanner relies on, used when reporting that
/// one was unavailable so an empty result is never mistaken for "nothing to enumerate".
const REGDATA_SOURCE: &str = "registration data (RIPEstat)";
const DOH_SOURCE: &str = "DNS-over-HTTPS resolver";

/// Default registration-data source: RIPEstat, RIPE NCC's maintained, official data
/// API aggregating registration (RDAP/WHOIS) and routing data as HTTP/JSON, so it
/// reuses the engine's paced request path with no new dependency.
/// `{base}prefix-overview/data.json?resource=<ip>` returns the announcing ASN, its
/// holder (owning org), and the covering prefix for an address;
/// `{base}announced-prefixes/data.json?resource=AS<asn>` returns the ASN's announced
/// netblocks. The trailing slash matters: source URLs are built with [`Url::join`].
///
/// (Was `api.bgpview.io`, a third-party aggregator that has since gone dead —
/// NXDOMAIN — silently turning every scan into "no findings"; RIPEstat is a durable
/// first-party replacement covering both lookups the scanner needs.)
const SOURCE_BASE: &str = "https://stat.ripe.net/data/";

/// Default DNS-over-HTTPS resolver (JSON API), shared with the subdomain
/// brute-force path. A domain target is resolved with `{base}?name=<host>&type=A`
/// and `Accept: application/dns-json`, through the paced request path — so
/// resolution adds no DNS-resolver dependency and is paced/User-Agent-rotated.
const DOH_BASE: &str = "https://cloudflare-dns.com/dns-query";

/// Upper bound on how many netblocks are reported for one ASN. A large
/// organization can announce thousands of prefixes; beyond this the set is
/// truncated and the drop is logged, never silent.
const MAX_NETBLOCKS: usize = 256;

/// Upper bound on the response body buffered per source query. A third-party
/// source is untrusted and could stream an unbounded body; the fields we read all
/// sit in a bounded JSON document, so bytes beyond this cap are dropped.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// How an [`AsnEnumerationScanner`] obtains the IP to look up. A domain target is
/// resolved over DoH; an IP-literal target is used directly.
enum Resolver {
    /// Resolve domains over the DoH JSON API at this base (production / mockable).
    Doh { doh_base: Url },
    /// A fixed, pre-resolved IP — bypasses the network. Used by tests and by
    /// callers that already hold the target's address.
    Fixed(String),
}

/// Enumerates the ASN and registered netblocks of a target's owning organization.
pub struct AsnEnumerationScanner {
    /// Registration-data source base (RDAP/WHOIS + routing data, HTTP/JSON).
    source_base: Url,
    /// How a domain target is resolved to an IP before the source lookup.
    resolver: Resolver,
}

impl AsnEnumerationScanner {
    /// The stable scanner id, exposed for registration and selection.
    pub const ID: &'static str = ID;

    /// Build the production scanner: the default registration-data source, with
    /// domain targets resolved over the default DoH resolver.
    pub fn new() -> Self {
        Self {
            // The default bases are valid absolute URLs, so these never fail.
            source_base: Url::parse(SOURCE_BASE).expect("SOURCE_BASE is a valid URL"),
            resolver: Resolver::Doh {
                doh_base: Url::parse(DOH_BASE).expect("DOH_BASE is a valid URL"),
            },
        }
    }

    /// Point the registration-data source at `base` (for tests using a local mock).
    /// `base` should end in `/`: source URLs are built with [`Url::join`].
    pub fn with_source_base(mut self, base: Url) -> Self {
        self.source_base = base;
        self
    }

    /// Point domain resolution at the DoH-style resolver at `base` (for tests that
    /// stub the resolver with a local mock).
    pub fn with_doh_base(mut self, base: Url) -> Self {
        self.resolver = Resolver::Doh { doh_base: base };
        self
    }

    /// Use a fixed, pre-resolved IP for the target, bypassing DoH entirely (for
    /// tests and callers that already hold the address).
    pub fn with_resolved_ip(mut self, ip: impl Into<String>) -> Self {
        self.resolver = Resolver::Fixed(ip.into());
        self
    }

    /// The IP to look up for `host`: the host itself when it is already an IP
    /// literal, a fixed override, or the first A record resolved over the paced DoH
    /// path. `None` when a domain does not resolve. Records an entry in `issues` if
    /// the resolver could not be consulted.
    async fn resolve_ip(
        &self,
        host: &str,
        ctx: &ScanContext,
        issues: &mut Vec<SourceIssue>,
    ) -> Result<Option<String>> {
        // A target already given as an IP is looked up directly — no DNS needed.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Some(ip.to_string()));
        }
        match &self.resolver {
            Resolver::Fixed(ip) => Ok(Some(ip.clone())),
            Resolver::Doh { doh_base } => doh_resolve_ipv4(doh_base, host, ctx, issues).await,
        }
    }
}

impl Default for AsnEnumerationScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BaseScanner for AsnEnumerationScanner {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "ASN / Netblock Enumeration"
    }

    fn description(&self) -> &str {
        "Given a target domain or IP, enumerates the autonomous system (ASN) and the IP \
         netblocks the owning organization has registered, using registration-data sources \
         (RDAP/WHOIS + routing data). A domain is resolved to an IP over the paced DoH path; \
         the IP's ASN and owning organization are looked up, then the ASN's announced \
         netblocks are enumerated. The ASN and each netblock are reported as findings naming \
         the owning organization. Enumeration only: it never manipulates routing, performs \
         any BGP action, or scans the enumerated ranges."
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        self.validate_target(target)?;
        // `validate_target` guarantees a host.
        let host = target.host().unwrap_or_default().to_ascii_lowercase();

        // External sources that could not be consulted this run — reported as
        // informational findings so an empty result is never mistaken for "this
        // organization has no footprint" when a source was simply unavailable.
        let mut source_issues: Vec<SourceIssue> = Vec::new();

        // Step 1: resolve the target to an IP (skipped for an IP-literal target).
        let Some(ip) = self.resolve_ip(&host, ctx, &mut source_issues).await? else {
            tracing::warn!(
                scanner = ID,
                host = %host,
                "target did not resolve to an IP; nothing to enumerate"
            );
            return Ok(source_availability::to_findings(source_issues, ID, target));
        };

        // Step 2: look up the owning ASN + organization for the IP.
        let Some(info) = self.lookup_asn(&ip, ctx, &mut source_issues).await? else {
            tracing::warn!(
                scanner = ID,
                host = %host,
                ip = %ip,
                "registration-data source returned no ASN for the IP; nothing to enumerate"
            );
            return Ok(source_availability::to_findings(source_issues, ID, target));
        };

        ctx.report_progress(progress(1, 2, &format!("AS{}", info.asn)));

        // Step 3: enumerate the ASN's announced netblocks.
        let announced = self
            .lookup_netblocks(info.asn, ctx, &mut source_issues)
            .await?;
        let (netblocks, dropped) = cap_netblocks(announced, MAX_NETBLOCKS);
        if dropped > 0 {
            tracing::warn!(
                scanner = ID,
                host = %host,
                asn = info.asn,
                cap = MAX_NETBLOCKS,
                dropped,
                "ASN announces more netblocks than the report cap; \
                 reporting the first {MAX_NETBLOCKS} and dropping {dropped}"
            );
        }

        // Report the ASN itself, then each enumerated netblock — the footprint.
        let mut findings = Vec::with_capacity(netblocks.len() + 1);
        findings.push(asn_finding(target, &host, &ip, &info));
        for netblock in &netblocks {
            findings.push(netblock_finding(target, &host, netblock, &info));
        }
        // Report any source that could not be consulted (e.g. the ASN prefix
        // enumeration failed after the IP lookup succeeded), so a partial footprint
        // is distinguishable from a complete one.
        findings.extend(source_availability::to_findings(source_issues, ID, target));

        ctx.report_progress(progress(2, 2, &format!("AS{}", info.asn)));
        Ok(findings)
    }
}

impl AsnEnumerationScanner {
    /// Query the registration-data source for the ASN + owning organization of
    /// `ip`, through the paced request path. A non-2xx or transport failure yields
    /// `None` (logged, and recorded in `issues` so an unavailable source is
    /// reported) rather than failing the scan — enumeration is best-effort;
    /// cancellation propagates. A healthy 2xx that simply carries no ASN (an
    /// unannounced IP) records no issue.
    async fn lookup_asn(
        &self,
        ip: &str,
        ctx: &ScanContext,
        issues: &mut Vec<SourceIssue>,
    ) -> Result<Option<IpAsnInfo>> {
        let Some(url) = source_url(&self.source_base, "prefix-overview/data.json", ip) else {
            return Ok(None);
        };
        // A registration-data source queried to map the target: support-lane pacing.
        match probe(ctx, RequestSpec::get(url).support_lookup()).await {
            Ok(response) if (200..300).contains(&response.status) => {
                Ok(parse_ip_lookup(&response.body))
            }
            Ok(response) => {
                tracing::warn!(
                    scanner = ID,
                    ip = %ip,
                    status = response.status,
                    "registration-data source returned a non-success status for the IP lookup"
                );
                issues.push(SourceIssue::non_success(REGDATA_SOURCE, response.status));
                Ok(None)
            }
            Err(Error::Cancelled) => Err(Error::Cancelled),
            Err(err) => {
                tracing::warn!(
                    scanner = ID,
                    ip = %ip,
                    error = %err,
                    "IP-to-ASN lookup failed; nothing to enumerate"
                );
                issues.push(SourceIssue::errored(REGDATA_SOURCE));
                Ok(None)
            }
        }
    }

    /// Query the registration-data source for the netblocks `asn` announces,
    /// through the paced request path. A non-2xx or transport failure yields no
    /// netblocks (logged, and recorded in `issues`); cancellation propagates. A
    /// healthy 2xx that lists no prefixes records no issue.
    async fn lookup_netblocks(
        &self,
        asn: u64,
        ctx: &ScanContext,
        issues: &mut Vec<SourceIssue>,
    ) -> Result<Vec<String>> {
        let Some(url) = source_url(
            &self.source_base,
            "announced-prefixes/data.json",
            &format!("AS{asn}"),
        ) else {
            return Ok(Vec::new());
        };
        // A registration-data source queried to map the target: support-lane pacing.
        match probe(ctx, RequestSpec::get(url).support_lookup()).await {
            Ok(response) if (200..300).contains(&response.status) => {
                Ok(parse_asn_prefixes(&response.body))
            }
            Ok(response) => {
                tracing::warn!(
                    scanner = ID,
                    asn,
                    status = response.status,
                    "registration-data source returned a non-success status for the ASN prefixes"
                );
                issues.push(SourceIssue::non_success(REGDATA_SOURCE, response.status));
                Ok(Vec::new())
            }
            Err(Error::Cancelled) => Err(Error::Cancelled),
            Err(err) => {
                tracing::warn!(
                    scanner = ID,
                    asn,
                    error = %err,
                    "ASN prefix enumeration failed; reporting the ASN with no netblocks"
                );
                issues.push(SourceIssue::errored(REGDATA_SOURCE));
                Ok(Vec::new())
            }
        }
    }
}

/// Register the ASN-enumeration scanner under its stable id. Its registration-data
/// source and DoH resolver are inline defaults, so it reads no seeded store.
pub fn register(registry: &mut ScannerRegistry) {
    let factory: ScannerFactory =
        Arc::new(|_config| Box::new(AsnEnumerationScanner::new()) as Box<dyn BaseScanner>);
    registry.register(ID, factory);
}

/// The ASN + owning organization for a looked-up IP, plus the prefix covering it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IpAsnInfo {
    asn: u64,
    organization: String,
    /// The registered prefix covering the looked-up IP, when the source reports it.
    covering_prefix: Option<String>,
}

/// A source/DoH response reduced to the status and a length-capped body.
#[derive(Debug, Clone)]
struct ProbeResponse {
    status: u16,
    body: Vec<u8>,
}

/// Build a RIPEstat data-call URL: `{base}{path}?resource=<resource>`. `base` ends
/// in `/`, so `path` (e.g. `prefix-overview/data.json`) joins relative to it. `None`
/// only if a misconfigured base makes the join fail.
fn source_url(base: &Url, path: &str, resource: &str) -> Option<Url> {
    let mut url = base.join(path).ok()?;
    url.query_pairs_mut().append_pair("resource", resource);
    Some(url)
}

/// An ASN from RIPEstat, which reports it as a JSON number on some data calls and a
/// numeric string on others; accept either.
fn json_asn(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Parse a RIPEstat `prefix-overview` response into the owning ASN + organization.
/// The data call returns `data.asns[]` (each `{ asn, holder }`) for the address's
/// covering prefix, reported as `data.resource`; the first entry carrying an ASN
/// wins, and its `holder` is the owning organization (a placeholder when absent).
/// `None` when no entry carries an ASN (unparseable, or the IP is unannounced).
fn parse_ip_lookup(body: &[u8]) -> Option<IpAsnInfo> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let data = value.get("data")?;
    let asns = data.get("asns")?.as_array()?;
    for entry in asns {
        let Some(asn) = entry.get("asn").and_then(json_asn) else {
            continue;
        };
        let organization = entry
            .get("holder")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| "unknown organization".to_string());
        let covering_prefix = data
            .get("resource")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        return Some(IpAsnInfo {
            asn,
            organization,
            covering_prefix,
        });
    }
    None
}

/// Parse a RIPEstat `announced-prefixes` response into the announced netblocks. The
/// data call returns `data.prefixes[]`, each entry carrying a `prefix` (CIDR); both
/// IPv4 and IPv6 prefixes share the one array. They are collected, deduplicated in
/// first-seen order. An unparseable body yields an empty list.
fn parse_asn_prefixes(body: &[u8]) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let Some(entries) = value
        .get("data")
        .and_then(|d| d.get("prefixes"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in entries {
        if let Some(prefix) = entry.get("prefix").and_then(Value::as_str) {
            let prefix = prefix.trim();
            if !prefix.is_empty() && seen.insert(prefix.to_string()) {
                out.push(prefix.to_string());
            }
        }
    }
    out
}

/// Resolve `host` to its first A record over the paced DoH path. Queries the DoH
/// JSON API for an `A` record and returns the first address in the answer.
/// Best-effort: a non-success resolver status or a transport failure yields `None`
/// and records an entry in `issues` (so an unavailable resolver is reported); a
/// healthy 2xx NXDOMAIN also yields `None` but records no issue; cancellation
/// propagates.
async fn doh_resolve_ipv4(
    doh_base: &Url,
    host: &str,
    ctx: &ScanContext,
    issues: &mut Vec<SourceIssue>,
) -> Result<Option<String>> {
    let mut url = doh_base.clone();
    url.query_pairs_mut()
        .clear()
        .append_pair("name", host)
        .append_pair("type", "A");
    // The DoH JSON API is selected by the `application/dns-json` Accept header. This
    // is a public-resolver query to map the target, so it uses the support lane.
    let spec = RequestSpec::get(url)
        .header("Accept", "application/dns-json")
        .support_lookup();

    match probe(ctx, spec).await {
        Ok(response) if (200..300).contains(&response.status) => {
            Ok(doh_first_a_record(&response.body))
        }
        Ok(response) => {
            issues.push(SourceIssue::non_success(DOH_SOURCE, response.status));
            Ok(None)
        }
        Err(Error::Cancelled) => Err(Error::Cancelled),
        Err(err) => {
            tracing::warn!(
                scanner = ID,
                host = %host,
                error = %err,
                "DoH resolution failed; nothing to enumerate"
            );
            issues.push(SourceIssue::errored(DOH_SOURCE));
            Ok(None)
        }
    }
}

/// The first IPv4 A-record address in a DoH JSON body, or `None`. Requires DNS
/// status `0` (NOERROR); an `Answer` entry of `type` 1 (A) whose `data` parses as
/// an IPv4 address is returned. NXDOMAIN, an empty answer, or a body that does not
/// parse all read as "no address".
fn doh_first_a_record(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    if value.get("Status").and_then(Value::as_i64) != Some(0) {
        return None;
    }
    value
        .get("Answer")
        .and_then(Value::as_array)?
        .iter()
        .filter(|answer| answer.get("type").and_then(Value::as_i64) == Some(1))
        .find_map(|answer| {
            answer
                .get("data")
                .and_then(Value::as_str)
                .filter(|data| data.parse::<std::net::Ipv4Addr>().is_ok())
                .map(str::to_string)
        })
}

/// Truncate `netblocks` to at most `cap`, returning the kept prefix and how many
/// were dropped. Split out of `scan` so the cap-and-log decision is unit-testable
/// without issuing any requests.
fn cap_netblocks(mut netblocks: Vec<String>, cap: usize) -> (Vec<String>, usize) {
    let dropped = netblocks.len().saturating_sub(cap);
    netblocks.truncate(cap);
    (netblocks, dropped)
}

/// Send one request through the paced scan context, reducing the response to the
/// status and a length-capped body. A third-party source is untrusted and could
/// return an unbounded body, so bytes beyond [`MAX_BODY_BYTES`] are dropped.
async fn probe(ctx: &ScanContext, spec: RequestSpec) -> Result<ProbeResponse> {
    let mut response = ctx.send(spec).await?;
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

/// Build the finding for the enumerated ASN, naming the owning organization.
fn asn_finding(target: &Target, host: &str, ip: &str, info: &IpAsnInfo) -> Finding {
    let covering = info
        .covering_prefix
        .as_deref()
        .map(|p| format!(" (covering prefix {p})"))
        .unwrap_or_default();
    Finding::builder(
        ID,
        target.clone(),
        format!(
            "{host} belongs to AS{asn} ({org})",
            asn = info.asn,
            org = info.organization
        ),
    )
    .status(Status::Info)
    .severity(Severity::Info)
    .description(format!(
        "{host} resolves to {ip}, which is announced by autonomous system AS{asn}, \
         registered to {org}{covering}. The organization's registered netblocks are \
         enumerated as separate findings — the external IP footprint beyond this single \
         host. This is registration-data enumeration only; no routing is touched and the \
         enumerated ranges are not scanned.",
        asn = info.asn,
        org = info.organization,
    ))
    .evidence(serde_json::json!({
        "host": host,
        "resolved_ip": ip,
        "asn": info.asn,
        "organization": info.organization,
        "covering_prefix": info.covering_prefix,
    }))
    .recommendations(
        "Confirm which of the enumerated netblocks are in scope for your engagement before \
         probing any of them — enumeration reveals the footprint, but authorization is \
         per-range.",
    )
    .build()
}

/// Build the finding for one enumerated netblock, naming the ASN and organization.
fn netblock_finding(target: &Target, host: &str, netblock: &str, info: &IpAsnInfo) -> Finding {
    Finding::builder(
        ID,
        target.clone(),
        format!(
            "Netblock {netblock} announced by AS{asn} ({org})",
            asn = info.asn,
            org = info.organization
        ),
    )
    .status(Status::Info)
    .severity(Severity::Info)
    .description(format!(
        "The netblock {netblock} is announced by AS{asn} ({org}), the autonomous system \
         owning {host}. It is part of the organization's registered IP footprint discovered \
         from registration-data sources. The range is reported, not scanned.",
        asn = info.asn,
        org = info.organization,
    ))
    .evidence(serde_json::json!({
        "host": host,
        "asn": info.asn,
        "organization": info.organization,
        "netblock": netblock,
    }))
    .build()
}

/// Build a scanner-internal progress update for `completed` of `total`, naming the
/// ASN currently being enumerated.
fn progress(completed: usize, total: usize, asn: &str) -> ProgressUpdate {
    ProgressUpdate::new(ID, completed, total)
        .current_item(asn.to_string())
        .message(format!("enumerating {completed}/{total}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    fn info() -> IpAsnInfo {
        IpAsnInfo {
            asn: 15169,
            organization: "Google LLC".to_string(),
            covering_prefix: Some("8.8.8.0/24".to_string()),
        }
    }

    // --- Metadata --------------------------------------------------------------

    #[test]
    fn metadata_is_stable() {
        let scanner = AsnEnumerationScanner::new();
        assert_eq!(scanner.id(), "asn_enumeration");
        assert_eq!(AsnEnumerationScanner::ID, "asn_enumeration");
        assert!(!scanner.name().is_empty());
        assert!(!scanner.description().is_empty());
    }

    #[test]
    fn validate_target_requires_a_host() {
        let scanner = AsnEnumerationScanner::new();
        assert!(scanner.validate_target(&target()).is_ok());
        // An IP-literal target is fine (it is looked up directly).
        let ip = Target::parse("http://8.8.8.8").unwrap();
        assert!(scanner.validate_target(&ip).is_ok());
        // No host at all is rejected.
        let hostless = Target::new(Url::parse("file:///tmp/x").unwrap(), None, None);
        assert!(matches!(
            scanner.validate_target(&hostless),
            Err(Error::Target(_))
        ));
    }

    // --- Source URL construction against the real default base -----------------

    #[test]
    fn source_urls_target_ripestat_data_calls() {
        let base = Url::parse(SOURCE_BASE).unwrap();
        let ip = source_url(&base, "prefix-overview/data.json", "8.8.8.8").unwrap();
        assert_eq!(
            ip.as_str(),
            "https://stat.ripe.net/data/prefix-overview/data.json?resource=8.8.8.8"
        );
        let asn = source_url(&base, "announced-prefixes/data.json", "AS15169").unwrap();
        assert_eq!(
            asn.as_str(),
            "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169"
        );
    }

    // --- IP-to-ASN parsing (task 1) --------------------------------------------

    #[test]
    fn parses_asn_and_org_from_ip_lookup() {
        // A captured RIPEstat `prefix-overview` response for 8.8.8.8 (trimmed).
        let body = br#"{
            "status": "ok",
            "data": {
                "announced": true,
                "asns": [ {"asn": 15169, "holder": "GOOGLE, US"} ],
                "resource": "8.8.8.0/24",
                "type": "prefix"
            }
        }"#;
        let got = parse_ip_lookup(body).expect("an ASN is parsed");
        assert_eq!(got.asn, 15169);
        assert_eq!(got.organization, "GOOGLE, US");
        assert_eq!(got.covering_prefix.as_deref(), Some("8.8.8.0/24"));
    }

    #[test]
    fn ip_lookup_placeholder_org_and_skips_entries_without_asn() {
        // First entry carries no ASN; the second does, with an empty holder — the
        // owning org falls back to a placeholder, and the ASN may be a string.
        let body = br#"{
            "data": {
                "asns": [
                    {"holder": "SOME, XX"},
                    {"asn": "19281", "holder": "  "}
                ],
                "resource": "9.9.9.0/24"
            }
        }"#;
        let got = parse_ip_lookup(body).expect("the second entry's ASN is used");
        assert_eq!(got.asn, 19281);
        assert_eq!(got.organization, "unknown organization");
        assert_eq!(got.covering_prefix.as_deref(), Some("9.9.9.0/24"));
    }

    #[test]
    fn ip_lookup_tolerates_garbage_and_empty() {
        assert!(parse_ip_lookup(b"not json").is_none());
        // Unannounced IP: RIPEstat returns an empty `asns` array.
        assert!(parse_ip_lookup(br#"{"data":{"asns":[]}}"#).is_none());
        assert!(parse_ip_lookup(br#"{"data":{}}"#).is_none());
    }

    // --- ASN-prefix parsing (task 2) -------------------------------------------

    #[test]
    fn parses_v4_and_v6_prefixes_dedup_in_order() {
        // A captured RIPEstat `announced-prefixes` response (trimmed): v4 and v6
        // share one `prefixes` array, each entry with a `prefix` + `timelines`.
        let body = br#"{
            "data": {
                "prefixes": [
                    {"prefix": "8.8.8.0/24", "timelines": [{"starttime": "2020-01-01T00:00:00"}]},
                    {"prefix": "8.8.4.0/24", "timelines": []},
                    {"prefix": "8.8.8.0/24", "timelines": []},
                    {"prefix": "2001:4860::/32", "timelines": []}
                ],
                "resource": "15169"
            }
        }"#;
        let got = parse_asn_prefixes(body);
        assert_eq!(
            got,
            vec![
                "8.8.8.0/24".to_string(),
                "8.8.4.0/24".to_string(),
                "2001:4860::/32".to_string(),
            ]
        );
    }

    #[test]
    fn parse_prefixes_tolerates_garbage() {
        assert!(parse_asn_prefixes(b"not json").is_empty());
        assert!(parse_asn_prefixes(br#"{}"#).is_empty());
        assert!(parse_asn_prefixes(br#"{"data":{}}"#).is_empty());
    }

    // --- DoH A-record extraction (task 1) --------------------------------------

    #[test]
    fn doh_extracts_first_a_record() {
        let body =
            br#"{"Status":0,"Answer":[{"name":"example.com","type":1,"data":"93.184.216.34"}]}"#;
        assert_eq!(doh_first_a_record(body).as_deref(), Some("93.184.216.34"));
    }

    #[test]
    fn doh_skips_cname_answers_and_takes_the_a() {
        // A CNAME (type 5) precedes the A (type 1); only the A address is taken.
        let body = br#"{"Status":0,"Answer":[
            {"name":"www.example.com","type":5,"data":"example.com"},
            {"name":"example.com","type":1,"data":"203.0.113.7"}
        ]}"#;
        assert_eq!(doh_first_a_record(body).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn doh_none_on_nxdomain_empty_or_garbage() {
        assert!(doh_first_a_record(br#"{"Status":3}"#).is_none());
        assert!(doh_first_a_record(br#"{"Status":0,"Answer":[]}"#).is_none());
        assert!(doh_first_a_record(br#"{"Status":0}"#).is_none());
        assert!(doh_first_a_record(b"not json").is_none());
    }

    // --- Netblock cap + truncation logging (task 4) ----------------------------

    #[test]
    fn cap_truncates_and_reports_dropped() {
        let small: Vec<String> = (0..3).map(|i| format!("10.0.{i}.0/24")).collect();
        let (kept, dropped) = cap_netblocks(small.clone(), MAX_NETBLOCKS);
        assert_eq!(kept, small);
        assert_eq!(dropped, 0);

        let big: Vec<String> = (0..(MAX_NETBLOCKS + 4))
            .map(|i| format!("10.{i}.0.0/16"))
            .collect();
        let (kept, dropped) = cap_netblocks(big, MAX_NETBLOCKS);
        assert_eq!(kept.len(), MAX_NETBLOCKS);
        assert_eq!(dropped, 4);
    }

    // --- Finding construction (task 3) -----------------------------------------

    #[test]
    fn asn_finding_names_asn_and_organization() {
        let finding = asn_finding(&target(), "example.com", "8.8.8.8", &info());
        assert_eq!(finding.scanner_id, "asn_enumeration");
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.title.contains("AS15169"));
        assert!(finding.title.contains("Google LLC"));
        let evidence = finding.evidence.unwrap();
        assert_eq!(evidence["asn"], 15169);
        assert_eq!(evidence["organization"], "Google LLC");
        assert_eq!(evidence["resolved_ip"], "8.8.8.8");
        assert_eq!(evidence["covering_prefix"], "8.8.8.0/24");
    }

    #[test]
    fn netblock_finding_names_netblock_asn_and_organization() {
        let finding = netblock_finding(&target(), "example.com", "8.8.4.0/24", &info());
        assert_eq!(finding.scanner_id, "asn_enumeration");
        assert_eq!(finding.status, Status::Info);
        assert!(finding.title.contains("8.8.4.0/24"));
        assert!(finding.title.contains("AS15169"));
        let evidence = finding.evidence.unwrap();
        assert_eq!(evidence["netblock"], "8.8.4.0/24");
        assert_eq!(evidence["asn"], 15169);
        assert_eq!(evidence["organization"], "Google LLC");
    }
}
