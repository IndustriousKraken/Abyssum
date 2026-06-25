//! CORS misconfiguration scanner.
//!
//! [`CorsScanner`] replays one request to the target carrying a set of crafted
//! `Origin` header values and inspects how the server's cross-origin response
//! headers ([`Access-Control-Allow-Origin`][acao] / [`Access-Control-Allow-Credentials`][acac])
//! react to each. A permissive policy — one that reflects an attacker origin,
//! trusts a look-alike, accepts the `null` origin, or pairs a wildcard with
//! credentials — lets a malicious page read a logged-in victim's authenticated
//! API responses, so it maps directly to a reportable bug-bounty finding.
//!
//! Like every scanner it owns none of the cross-cutting concerns: every probe
//! goes through [`ScanContext::send`], so pacing, the rotating User-Agent,
//! cancellation, progress, and the attached credential all apply uniformly and
//! the stealth floor cannot be bypassed. The scanner crafts its `Origin` values
//! inline from the [`Target`] and seeds no wordlist.
//!
//! ## Classification
//!
//! Credentials count as *enabled* only when the returned `ACAC` value equals
//! `true` (case-insensitive). Severity tracks exploitability: a credentialed
//! reflection (an attacker page reading a *logged-in* victim's data) outranks the
//! same reflection without credentials, and a bare wildcard — which leaks only
//! public, unauthenticated data — is the floor.
//!
//! [acao]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
//! [acac]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::{
    HeaderName, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_ORIGIN, ORIGIN,
};
use url::Url;

use abyssum_core::{
    BaseScanner, Error, Finding, ProgressUpdate, RequestSpec, Result, ScanContext, ScannerFactory,
    ScannerRegistry, Severity, Status, Target,
};

/// The stable scanner id. The registry keys on this and a scan selects by it; it
/// must never change.
const ID: &str = "cors";

/// An arbitrary attacker-controlled origin, unrelated to any real target. Uses the
/// reserved `.example` TLD (RFC 2606) so it can never collide with a live host;
/// the value need not resolve — reflection is a pure string echo.
const ATTACKER_ORIGIN: &str = "https://abyssum-cors-probe.example";

/// The opaque `null` origin (sandboxed iframes, redirects, `file://` documents,
/// and `data:` URLs all present as `Origin: null`). A server that reflects it
/// trusts an origin any attacker can produce.
const NULL_ORIGIN: &str = "null";

/// A file/opaque origin. Distinct from the bare `null` probe so a server that
/// echoes the literal `file://` origin is caught even if it would not reflect
/// `null`.
const FILE_ORIGIN: &str = "file://";

/// Which kind of crafted origin a probe carries. Recorded on the finding so the
/// operator sees *why* an origin should never have been trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OriginClass {
    /// An arbitrary attacker origin, unrelated to the target.
    Arbitrary,
    /// The opaque `null` origin.
    Null,
    /// An untrusted host that merely contains the target's domain as a substring
    /// (defeats naive substring/regex allow-listing).
    LookAlike,
    /// A non-default scheme/port origin the server should not trust.
    OtherSchemePort,
    /// A file/opaque (`file://`) origin.
    FileOrigin,
}

impl OriginClass {
    /// A stable, lowercase label for finding evidence.
    fn label(self) -> &'static str {
        match self {
            OriginClass::Arbitrary => "arbitrary",
            OriginClass::Null => "null",
            OriginClass::LookAlike => "look_alike",
            OriginClass::OtherSchemePort => "other_scheme_port",
            OriginClass::FileOrigin => "file_origin",
        }
    }
}

/// One crafted `Origin` header value and its class.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CraftedOrigin {
    /// The exact `Origin` header value sent on the probe.
    value: String,
    /// What kind of origin it is.
    class: OriginClass,
}

impl CraftedOrigin {
    fn new(value: impl Into<String>, class: OriginClass) -> Self {
        Self {
            value: value.into(),
            class,
        }
    }
}

/// Detects permissive CORS policies by replaying crafted `Origin` headers.
pub struct CorsScanner;

impl CorsScanner {
    /// The stable scanner id, exposed for registration and selection.
    pub const ID: &'static str = ID;

    /// Build a CORS scanner. It is stateless — it crafts its origins inline from
    /// the target at scan time and reads no wordlist.
    pub fn new() -> Self {
        Self
    }
}

impl Default for CorsScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BaseScanner for CorsScanner {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "CORS Misconfiguration"
    }

    fn description(&self) -> &str {
        "Replays a request with crafted Origin headers (an attacker origin, the \
         null origin, a target look-alike, a non-default scheme/port, and a file \
         origin) and inspects the Access-Control-Allow-Origin / \
         Access-Control-Allow-Credentials response headers to detect permissive \
         cross-origin policies — reflected origins, wildcard-with-credentials, and \
         null-origin acceptance."
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        self.validate_target(target)?;

        let url = target.full_url();
        let origins = crafted_origins(target);
        let total = origins.len();
        let mut findings = Vec::new();

        for (index, origin) in origins.iter().enumerate() {
            // Stop promptly on cancellation, returning the findings gathered so
            // far rather than erroring.
            if ctx.is_cancelled() {
                break;
            }

            match probe(ctx, &url, origin).await {
                Ok(observation) => {
                    if let Some(verdict) = classify(origin, &observation) {
                        findings.push(finding_for(target, &url, origin, &observation, verdict));
                    }
                }
                // Cancellation is not a transport failure: surface it rather than
                // masking it as a partial success. (`ScanContext::send` does not
                // currently raise `Cancelled` — the loop's `is_cancelled()` check
                // above handles the cooperative case — but matching it keeps the
                // contract robust if the request path becomes cancellation-aware.)
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(err) => {
                    // A transport failure or a pacing halt (sustained target
                    // distress). Respect it: stop probing and return the findings
                    // gathered so far rather than hammering a struggling target —
                    // but log the halt so it is not silent.
                    tracing::warn!(
                        scanner = ID,
                        origin = %origin.value,
                        error = %err,
                        "stopping CORS scan after a request failure; \
                         returning partial findings"
                    );
                    break;
                }
            }

            ctx.report_progress(progress(index + 1, total, &origin.value));
        }

        Ok(findings)
    }
}

/// Register the CORS scanner under its stable id. It carries no state and reads no
/// seeded store, so the factory ignores the config it is handed.
pub fn register(registry: &mut ScannerRegistry) {
    let factory: ScannerFactory =
        Arc::new(|_config| Box::new(CorsScanner::new()) as Box<dyn BaseScanner>);
    registry.register(ID, factory);
}

/// The crafted-origin set for `target`, derived from the target's own domain at
/// scan time so the look-alike and per-target variants are meaningful.
///
/// Order is stable: arbitrary, null, look-alike, non-default scheme/port, file.
fn crafted_origins(target: &Target) -> Vec<CraftedOrigin> {
    // `scan` calls `validate_target` first, which guarantees a host; the fallback
    // keeps this free function total for direct unit tests.
    let host = target.host().unwrap_or("target");
    vec![
        CraftedOrigin::new(ATTACKER_ORIGIN, OriginClass::Arbitrary),
        CraftedOrigin::new(NULL_ORIGIN, OriginClass::Null),
        // The target's domain appears as a substring of an attacker-controlled
        // host — `https://<target>.attacker.example`. A naive `contains(host)`
        // allow-list trusts it; a correct suffix/exact check does not.
        CraftedOrigin::new(
            format!("https://{host}.attacker.example"),
            OriginClass::LookAlike,
        ),
        // A non-default scheme (http, not the typical https) AND a non-default
        // port on the target's own host: should the API trust this origin, it is
        // reflecting one it ought not.
        CraftedOrigin::new(format!("http://{host}:1337"), OriginClass::OtherSchemePort),
        CraftedOrigin::new(FILE_ORIGIN, OriginClass::FileOrigin),
    ]
}

/// The cross-origin response headers a single probe observed.
#[derive(Debug, Clone)]
struct Observation {
    /// The returned `Access-Control-Allow-Origin`, if present.
    acao: Option<String>,
    /// The returned `Access-Control-Allow-Credentials` raw value, if present.
    acac_raw: Option<String>,
    /// Whether credentials are enabled — `ACAC` equals `true` (case-insensitive).
    credentials_allowed: bool,
}

/// What permissive misconfiguration a probe revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Misconfig {
    /// `ACAO: *` combined with `ACAC: true`.
    WildcardWithCredentials,
    /// The server echoed the crafted origin back in `ACAO`.
    ReflectedOrigin,
    /// The server reflected the `null` origin in response to the null probe.
    NullOriginAccepted,
    /// `ACAO: *` without credentials.
    BareWildcard,
}

/// A classified probe: the misconfiguration observed and whether credentials were
/// allowed alongside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Verdict {
    kind: Misconfig,
    credentialed: bool,
}

/// Classify one probe's response into a misconfiguration, or `None` when the
/// policy is sound for the crafted origin.
///
/// A missing (or empty) `Access-Control-Allow-Origin` is never a finding, and a
/// fixed allowed origin unrelated to the crafted one is a *properly restricted*
/// policy — also no finding. A returned `ACAO: null` only counts when it answers
/// the dedicated null probe: returning `null` to a non-null origin does not grant
/// that origin access, so it is not exploitable by that probe.
fn classify(origin: &CraftedOrigin, observation: &Observation) -> Option<Verdict> {
    let acao = observation.acao.as_deref()?.trim();
    if acao.is_empty() {
        return None;
    }
    let credentialed = observation.credentials_allowed;

    // A wildcard allowance is independent of which origin we sent.
    if acao == "*" {
        let kind = if credentialed {
            Misconfig::WildcardWithCredentials
        } else {
            Misconfig::BareWildcard
        };
        return Some(Verdict { kind, credentialed });
    }

    match origin.class {
        // The null origin is only "accepted" when the server reflects `null` for
        // our null probe — not when some unrelated probe happens to yield `null`.
        OriginClass::Null => {
            if acao.eq_ignore_ascii_case("null") {
                Some(Verdict {
                    kind: Misconfig::NullOriginAccepted,
                    credentialed,
                })
            } else {
                None
            }
        }
        // Every other class is a reflection: the server echoed exactly the origin
        // we crafted. Anything else (a fixed, unrelated `ACAO`) is sound.
        _ => {
            if acao == origin.value {
                Some(Verdict {
                    kind: Misconfig::ReflectedOrigin,
                    credentialed,
                })
            } else {
                None
            }
        }
    }
}

/// The severity of a verdict. Credentialed cross-origin exposure outranks the
/// equivalent misconfiguration without credentials; a bare wildcard (public data
/// only) is the floor.
fn severity_of(verdict: &Verdict) -> Severity {
    match verdict.kind {
        // Wildcard with credentials is always credentialed exposure.
        Misconfig::WildcardWithCredentials => Severity::High,
        Misconfig::ReflectedOrigin | Misconfig::NullOriginAccepted => {
            if verdict.credentialed {
                Severity::High
            } else {
                Severity::Medium
            }
        }
        Misconfig::BareWildcard => Severity::Low,
    }
}

/// The human-readable title and description for a classified probe.
fn describe(origin: &CraftedOrigin, verdict: &Verdict) -> (String, String) {
    let creds = if verdict.credentialed {
        " with credentials allowed"
    } else {
        ""
    };
    match verdict.kind {
        Misconfig::WildcardWithCredentials => (
            "Wildcard Access-Control-Allow-Origin combined with credentials".to_string(),
            "The server returns `Access-Control-Allow-Origin: *` together with \
             `Access-Control-Allow-Credentials: true`. Although a compliant browser \
             refuses this exact pair, a server advertising both is misconfigured and \
             may expose credentialed responses to any origin."
                .to_string(),
        ),
        Misconfig::BareWildcard => (
            "Bare wildcard Access-Control-Allow-Origin".to_string(),
            "The server returns `Access-Control-Allow-Origin: *` without credentials. \
             Any origin can read unauthenticated responses; impact is limited to \
             public data."
                .to_string(),
        ),
        Misconfig::NullOriginAccepted => (
            format!("Null origin accepted{creds}"),
            format!(
                "The server reflected `Access-Control-Allow-Origin: null` in response to a \
                 null-origin probe{creds}. The opaque `null` origin is produced by sandboxed \
                 iframes, redirects, and `file://`/`data:` documents, so any attacker can \
                 present it and read the response."
            ),
        ),
        Misconfig::ReflectedOrigin => {
            let what = match origin.class {
                OriginClass::Arbitrary => "an arbitrary attacker origin",
                OriginClass::LookAlike => {
                    "an untrusted look-alike origin (the target domain appears only as a \
                     substring of an attacker-controlled host)"
                }
                OriginClass::OtherSchemePort => "a non-default scheme/port origin",
                OriginClass::FileOrigin => "a file/opaque origin",
                // Null reflection is a distinct verdict; never reaches here.
                OriginClass::Null => "an untrusted origin",
            };
            (
                format!("Reflected origin in Access-Control-Allow-Origin{creds}"),
                format!(
                    "The server echoed the crafted origin `{}` back in \
                     `Access-Control-Allow-Origin`{creds}, trusting {what}. A malicious page \
                     served from that origin can read the response.",
                    origin.value
                ),
            )
        }
    }
}

/// Build the [`Finding`] for a classified probe, carrying the reproduction
/// evidence: the origin sent, the `ACAO` and `ACAC` returned, and the probed URL.
fn finding_for(
    target: &Target,
    url: &Url,
    origin: &CraftedOrigin,
    observation: &Observation,
    verdict: Verdict,
) -> Finding {
    let (title, description) = describe(origin, &verdict);
    let evidence = serde_json::json!({
        "origin_sent": origin.value,
        "origin_class": origin.class.label(),
        "access_control_allow_origin": observation.acao,
        "access_control_allow_credentials": observation.acac_raw,
        "credentials_allowed": verdict.credentialed,
        "probed_url": url.as_str(),
        "misconfiguration": misconfig_label(verdict.kind),
    });

    Finding::builder(ID, target.clone(), title)
        .status(Status::Vulnerable)
        .severity(severity_of(&verdict))
        .description(description)
        .evidence(evidence)
        .recommendations(
            "Validate the Origin against an explicit allow-list of exact, trusted origins; \
             never reflect an arbitrary Origin, never combine a wildcard with credentials, \
             and never trust the `null` origin.",
        )
        .build()
}

/// A stable, lowercase label for a misconfiguration kind (finding evidence).
fn misconfig_label(kind: Misconfig) -> &'static str {
    match kind {
        Misconfig::WildcardWithCredentials => "wildcard_with_credentials",
        Misconfig::ReflectedOrigin => "reflected_origin",
        Misconfig::NullOriginAccepted => "null_origin_accepted",
        Misconfig::BareWildcard => "bare_wildcard",
    }
}

/// Send one probe carrying `origin` and reduce the response to the cross-origin
/// headers classification needs. The body is irrelevant to CORS, so it is never
/// read — dropping the response closes the connection.
async fn probe(ctx: &ScanContext, url: &Url, origin: &CraftedOrigin) -> Result<Observation> {
    let request = RequestSpec::get(url.clone()).header(ORIGIN.as_str(), origin.value.clone());
    let response = ctx.send(request).await?;

    let acao = header_value(&response, ACCESS_CONTROL_ALLOW_ORIGIN);
    let acac_raw = header_value(&response, ACCESS_CONTROL_ALLOW_CREDENTIALS);
    let credentials_allowed = acac_raw
        .as_deref()
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    Ok(Observation {
        acao,
        acac_raw,
        credentials_allowed,
    })
}

/// Read a single response header as an owned string, if present and valid UTF-8.
fn header_value(response: &reqwest::Response, name: HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

/// Build a scanner-internal progress update for origin `completed` of `total`,
/// naming the origin currently being probed.
fn progress(completed: usize, total: usize, origin: &str) -> ProgressUpdate {
    ProgressUpdate::new(ID, completed, total)
        .current_item(origin.to_string())
        .message(format!("probing origin {completed}/{total}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    fn arbitrary() -> CraftedOrigin {
        CraftedOrigin::new(ATTACKER_ORIGIN, OriginClass::Arbitrary)
    }

    fn null() -> CraftedOrigin {
        CraftedOrigin::new(NULL_ORIGIN, OriginClass::Null)
    }

    fn look_alike() -> CraftedOrigin {
        CraftedOrigin::new(
            "https://example.com.attacker.example",
            OriginClass::LookAlike,
        )
    }

    /// Build an observation from raw header values.
    fn obs(acao: Option<&str>, acac: Option<&str>) -> Observation {
        let acac_raw = acac.map(|s| s.to_string());
        let credentials_allowed = acac_raw
            .as_deref()
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Observation {
            acao: acao.map(|s| s.to_string()),
            acac_raw,
            credentials_allowed,
        }
    }

    // --- Metadata (task 1.2) ---------------------------------------------------

    #[test]
    fn metadata_is_stable() {
        let scanner = CorsScanner::new();
        assert_eq!(scanner.id(), "cors");
        assert_eq!(CorsScanner::ID, "cors");
        assert!(!scanner.name().is_empty());
        assert!(!scanner.description().is_empty());
    }

    // --- Crafted origins (tasks 2.1, 2.2) --------------------------------------

    #[test]
    fn crafted_origins_cover_every_class_derived_from_target() {
        let origins = crafted_origins(&target());
        let classes: Vec<OriginClass> = origins.iter().map(|o| o.class).collect();
        assert_eq!(
            classes,
            vec![
                OriginClass::Arbitrary,
                OriginClass::Null,
                OriginClass::LookAlike,
                OriginClass::OtherSchemePort,
                OriginClass::FileOrigin,
            ],
            "all five crafted-origin classes present, in stable order"
        );

        // The null probe is the literal opaque origin.
        assert_eq!(origins[1].value, "null");

        // The look-alike and scheme/port variants are derived from the target's
        // own host at scan time and contain it as a substring.
        let look_alike = &origins[2];
        assert!(
            look_alike.value.contains("example.com"),
            "look-alike must contain the target domain as a substring: {}",
            look_alike.value
        );
        assert_ne!(
            look_alike.value, "https://example.com",
            "the look-alike is an attacker host, not the real origin"
        );
        let scheme_port = &origins[3];
        assert!(scheme_port.value.contains("example.com"));
        assert!(scheme_port.value.starts_with("http://"));
        assert!(scheme_port.value.contains(":1337"));
    }

    #[test]
    fn look_alike_is_derived_per_target() {
        let other = Target::parse("https://victim.test").unwrap();
        let origins = crafted_origins(&other);
        assert!(origins[2].value.contains("victim.test"));
        assert!(!origins[2].value.contains("example.com"));
    }

    // --- Classifier matrix (task 5.1) ------------------------------------------

    #[test]
    fn no_acao_is_not_a_finding() {
        assert!(classify(&arbitrary(), &obs(None, None)).is_none());
        assert!(classify(&arbitrary(), &obs(None, Some("true"))).is_none());
        // An empty ACAO is treated as no allowance.
        assert!(classify(&arbitrary(), &obs(Some("   "), Some("true"))).is_none());
    }

    #[test]
    fn properly_restricted_origin_is_not_a_finding() {
        // A fixed allowed origin unrelated to the crafted attacker origin.
        let fixed = obs(Some("https://app.trusted.example"), Some("true"));
        assert!(classify(&arbitrary(), &fixed).is_none());
        assert!(classify(&look_alike(), &fixed).is_none());
        // Returning `null` to a *non-null* probe does not grant that origin access.
        assert!(classify(&arbitrary(), &obs(Some("null"), Some("true"))).is_none());
    }

    #[test]
    fn wildcard_with_credentials_is_high() {
        let v = classify(&arbitrary(), &obs(Some("*"), Some("true"))).unwrap();
        assert_eq!(v.kind, Misconfig::WildcardWithCredentials);
        assert!(v.credentialed);
        assert_eq!(severity_of(&v), Severity::High);
    }

    #[test]
    fn bare_wildcard_is_low() {
        let v = classify(&arbitrary(), &obs(Some("*"), None)).unwrap();
        assert_eq!(v.kind, Misconfig::BareWildcard);
        assert!(!v.credentialed);
        assert_eq!(severity_of(&v), Severity::Low);
        // ACAC present but not "true" is also bare wildcard.
        let v2 = classify(&arbitrary(), &obs(Some("*"), Some("false"))).unwrap();
        assert_eq!(v2.kind, Misconfig::BareWildcard);
    }

    #[test]
    fn reflected_arbitrary_origin_credentialed_vs_not() {
        let with = classify(&arbitrary(), &obs(Some(ATTACKER_ORIGIN), Some("true"))).unwrap();
        assert_eq!(with.kind, Misconfig::ReflectedOrigin);
        assert_eq!(severity_of(&with), Severity::High);

        let without = classify(&arbitrary(), &obs(Some(ATTACKER_ORIGIN), None)).unwrap();
        assert_eq!(without.kind, Misconfig::ReflectedOrigin);
        assert_eq!(severity_of(&without), Severity::Medium);
    }

    #[test]
    fn reflected_look_alike_origin_is_a_finding() {
        let la = look_alike();
        let v = classify(&la, &obs(Some(&la.value), None)).unwrap();
        assert_eq!(v.kind, Misconfig::ReflectedOrigin);
        assert_eq!(severity_of(&v), Severity::Medium);
    }

    #[test]
    fn null_origin_accepted_credentialed_vs_not() {
        let with = classify(&null(), &obs(Some("null"), Some("true"))).unwrap();
        assert_eq!(with.kind, Misconfig::NullOriginAccepted);
        assert_eq!(severity_of(&with), Severity::High);

        let without = classify(&null(), &obs(Some("null"), None)).unwrap();
        assert_eq!(without.kind, Misconfig::NullOriginAccepted);
        assert_eq!(severity_of(&without), Severity::Medium);

        // Case-insensitive ACAC.
        let mixed = classify(&null(), &obs(Some("null"), Some("TRUE"))).unwrap();
        assert_eq!(severity_of(&mixed), Severity::High);
    }

    #[test]
    fn null_probe_with_non_null_acao_is_not_a_finding() {
        // A null probe that gets a fixed, unrelated ACAO back is sound.
        assert!(classify(
            &null(),
            &obs(Some("https://app.trusted.example"), Some("true"))
        )
        .is_none());
    }

    /// Task 4.4 / spec: credentialed exposure always outranks the same
    /// misconfiguration without credentials, and a bare wildcard is the floor.
    #[test]
    fn severity_orders_credentialed_above_uncredentialed() {
        let reflected_creds =
            classify(&arbitrary(), &obs(Some(ATTACKER_ORIGIN), Some("true"))).unwrap();
        let reflected_no_creds = classify(&arbitrary(), &obs(Some(ATTACKER_ORIGIN), None)).unwrap();
        let bare = classify(&arbitrary(), &obs(Some("*"), None)).unwrap();

        assert!(severity_of(&reflected_creds) > severity_of(&reflected_no_creds));
        assert!(severity_of(&bare) < severity_of(&reflected_creds));

        let null_creds = classify(&null(), &obs(Some("null"), Some("true"))).unwrap();
        let null_no_creds = classify(&null(), &obs(Some("null"), None)).unwrap();
        assert!(severity_of(&null_creds) > severity_of(&null_no_creds));
    }

    // --- ACAC parsing (task 4.1) -----------------------------------------------

    #[test]
    fn credentials_enabled_only_when_value_equals_true() {
        assert!(obs(Some("*"), Some("true")).credentials_allowed);
        assert!(obs(Some("*"), Some("True")).credentials_allowed);
        assert!(obs(Some("*"), Some("  TRUE  ")).credentials_allowed);
        assert!(!obs(Some("*"), Some("false")).credentials_allowed);
        assert!(!obs(Some("*"), Some("1")).credentials_allowed);
        assert!(!obs(Some("*"), Some("yes")).credentials_allowed);
        assert!(!obs(Some("*"), None).credentials_allowed);
    }

    // --- Finding construction (task 4.5) ---------------------------------------

    #[test]
    fn finding_carries_full_evidence() {
        let url = Url::parse("https://example.com/api").unwrap();
        let origin = arbitrary();
        let observation = obs(Some(ATTACKER_ORIGIN), Some("true"));
        let verdict = classify(&origin, &observation).unwrap();
        let finding = finding_for(&target(), &url, &origin, &observation, verdict);

        assert_eq!(finding.scanner_id, "cors");
        assert_eq!(finding.status, Status::Vulnerable);
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.description.is_some());

        let evidence = finding.evidence.unwrap();
        assert_eq!(evidence["origin_sent"], ATTACKER_ORIGIN);
        assert_eq!(evidence["origin_class"], "arbitrary");
        assert_eq!(evidence["access_control_allow_origin"], ATTACKER_ORIGIN);
        assert_eq!(evidence["access_control_allow_credentials"], "true");
        assert_eq!(evidence["credentials_allowed"], true);
        assert_eq!(evidence["probed_url"], "https://example.com/api");
        assert_eq!(evidence["misconfiguration"], "reflected_origin");
    }

    #[test]
    fn bare_wildcard_evidence_records_absent_acac_as_null() {
        let url = Url::parse("https://example.com/").unwrap();
        let origin = arbitrary();
        let observation = obs(Some("*"), None);
        let verdict = classify(&origin, &observation).unwrap();
        let finding = finding_for(&target(), &url, &origin, &observation, verdict);
        assert_eq!(finding.severity, Severity::Low);
        let evidence = finding.evidence.unwrap();
        assert!(evidence["access_control_allow_credentials"].is_null());
        assert_eq!(evidence["credentials_allowed"], false);
        assert_eq!(evidence["misconfiguration"], "bare_wildcard");
    }
}
