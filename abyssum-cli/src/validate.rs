//! Input validation — performed up front, before any request is issued.
//!
//! Targets are parsed into [`Target`]s, defaulting the scheme to `https` when one
//! is absent; an unparseable target (or one with no host) is rejected. Requested
//! scanner ids are checked against the registry's `available()` ids — the single
//! source of truth — so an unknown id never reaches a scan. Both rejections happen
//! before the orchestrator runs, so a bad selection issues no traffic.

use abyssum_core::{Error, Result, Target};

/// Parse and validate a single target string into a [`Target`].
///
/// A target given without a URL scheme (a bare host like `api.example.com` or
/// `10.0.0.5:8080/path`) is treated as an `https` URL. A string that cannot be
/// parsed as a valid URL, or one that resolves to a URL with no host, is an
/// [`Error::Target`].
pub fn parse_target(raw: &str) -> Result<Target> {
    let with_scheme = ensure_scheme(raw);
    let target = Target::parse(&with_scheme)?;
    match target.host() {
        Some(host) if !host.is_empty() => Ok(target),
        _ => Err(Error::Target(format!("target {raw:?} has no host"))),
    }
}

/// Parse every target string, failing on the first invalid one. Returns the
/// targets in the order supplied.
pub fn parse_targets(raws: &[String]) -> Result<Vec<Target>> {
    raws.iter().map(|raw| parse_target(raw)).collect()
}

/// Prepend `https://` unless `raw` already carries an explicit URL scheme.
fn ensure_scheme(raw: &str) -> String {
    if has_explicit_scheme(raw) {
        raw.to_string()
    } else {
        format!("https://{raw}")
    }
}

/// Whether `raw` begins with a syntactically valid `scheme://` prefix.
///
/// A URL scheme is an ASCII letter followed by letters, digits, `+`, `-`, or `.`
/// (RFC 3986). Detecting the scheme by the `://` separator — rather than handing
/// the bare string to `Url::parse` — avoids the footgun where `example.com:8080`
/// parses with `example.com` as its "scheme".
fn has_explicit_scheme(raw: &str) -> bool {
    match raw.find("://") {
        Some(end) if end > 0 => {
            let scheme = &raw[..end];
            let mut chars = scheme.chars();
            chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
        _ => false,
    }
}

/// Resolve the requested scanner ids against the registry's `available` ids,
/// rejecting any that are not registered.
///
/// Returns the requested ids unchanged when all are known; otherwise an
/// [`Error::ScannerNotFound`] naming every unknown id (so the operator sees all of
/// them at once, not just the first). The check uses `available()` as the source
/// of truth, so it cannot drift as scanners are added or removed.
pub fn resolve_scanners(requested: &[String], available: &[String]) -> Result<Vec<String>> {
    let unknown: Vec<String> = requested
        .iter()
        .filter(|id| !available.iter().any(|a| a == *id))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(Error::ScannerNotFound(unknown.join(", ")));
    }
    Ok(requested.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_scheme_to_https_for_a_bare_host() {
        let target = parse_target("api.example.com").unwrap();
        assert_eq!(target.base_url().scheme(), "https");
        assert_eq!(target.host(), Some("api.example.com"));
    }

    #[test]
    fn defaults_scheme_for_a_bare_host_with_port_and_path() {
        // The `example.com:8080`-as-scheme footgun must not bite: the host is the
        // host, the port is the port.
        let target = parse_target("10.0.0.5:8080").unwrap();
        assert_eq!(target.base_url().scheme(), "https");
        assert_eq!(target.host(), Some("10.0.0.5"));
        assert_eq!(target.base_url().port(), Some(8080));
    }

    #[test]
    fn preserves_an_explicit_scheme() {
        let http = parse_target("http://insecure.test").unwrap();
        assert_eq!(http.base_url().scheme(), "http");
        let https = parse_target("https://secure.test").unwrap();
        assert_eq!(https.base_url().scheme(), "https");
    }

    #[test]
    fn rejects_a_garbage_url() {
        // A space is not a valid host character, so even after defaulting the
        // scheme the URL fails to parse.
        assert!(matches!(parse_target("not a url"), Err(Error::Target(_))));
        // A space in the host is rejected even with an explicit scheme.
        assert!(matches!(
            parse_target("http://exa mple.com"),
            Err(Error::Target(_))
        ));
    }

    #[test]
    fn rejects_a_target_with_no_host() {
        assert!(matches!(parse_target("https://"), Err(Error::Target(_))));
    }

    #[test]
    fn parse_targets_fails_on_the_first_invalid() {
        let err = parse_targets(&["good.test".into(), "bad host".into()]).unwrap_err();
        assert!(matches!(err, Error::Target(_)));
    }

    #[test]
    fn resolves_known_scanner_ids() {
        let available = vec!["cors".to_string(), "bac".to_string(), "idor".to_string()];
        let resolved = resolve_scanners(&["cors".into(), "idor".into()], &available).unwrap();
        assert_eq!(resolved, vec!["cors".to_string(), "idor".to_string()]);
    }

    #[test]
    fn rejects_unknown_scanner_ids() {
        let available = vec!["cors".to_string(), "bac".to_string()];
        let err = resolve_scanners(&["cors".into(), "ghost".into()], &available).unwrap_err();
        match err {
            Error::ScannerNotFound(ids) => assert!(ids.contains("ghost")),
            other => panic!("expected ScannerNotFound, got {other:?}"),
        }
    }
}
