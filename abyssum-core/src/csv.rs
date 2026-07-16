//! Shared CSV field escaping, used by every CSV renderer in the crate (the report
//! and the run diff), so the RFC 4180 quoting rule lives in exactly one place.

/// Escape a CSV field per RFC 4180: wrap in double quotes (doubling any interior
/// quote) when it contains a comma, quote, or line break; otherwise emit verbatim.
pub(crate) fn escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::escape;

    #[test]
    fn quotes_only_fields_with_special_characters() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("a,b"), "\"a,b\"");
        assert_eq!(escape("she said \"hi\""), "\"she said \"\"hi\"\"\"");
        assert_eq!(escape("line\nbreak"), "\"line\nbreak\"");
    }
}
