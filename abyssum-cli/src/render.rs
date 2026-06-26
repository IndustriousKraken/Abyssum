//! Rendering one findings set as a table, JSON, or CSV.
//!
//! All three formats are pure projections of the **same** `&[Finding]`: no
//! renderer re-runs a scanner or re-queries persistence, so the formats can never
//! disagree on content. The table and CSV share one column extractor
//! ([`cells`]) — scanner, target, status, severity, title — while JSON serializes
//! the full finding records for machine consumption.

use abyssum_core::{Error, Finding, Result, Severity, Status};

use crate::cli::OutputFormat;

/// The shared column headers, in the order every tabular format emits them.
pub const COLUMNS: [&str; 5] = ["Scanner", "Target", "Status", "Severity", "Title"];

/// Render `findings` in the chosen `format`. Each rendering ends with a trailing
/// newline so the caller can print it verbatim.
pub fn render(findings: &[Finding], format: OutputFormat) -> Result<String> {
    Ok(match format {
        OutputFormat::Table => render_table(findings),
        OutputFormat::Json => render_json(findings)?,
        OutputFormat::Csv => render_csv(findings),
    })
}

/// The five display cells for one finding: scanner, target (full URL), status,
/// severity, title — the same data the table and CSV both project.
fn cells(finding: &Finding) -> [String; 5] {
    [
        finding.scanner_id.clone(),
        finding.target.full_url().to_string(),
        status_str(finding.status).to_string(),
        severity_str(finding.severity).to_string(),
        finding.title.clone(),
    ]
}

/// The lowercase wire spelling of a [`Status`] (matches its serde name).
fn status_str(status: Status) -> &'static str {
    match status {
        Status::Vulnerable => "vulnerable",
        Status::Safe => "safe",
        Status::Info => "info",
    }
}

/// The lowercase wire spelling of a [`Severity`] (matches its serde name).
fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Render an aligned, human-readable table with a header and separator row.
///
/// Embedded newlines in a cell are collapsed to spaces so a multi-line title
/// cannot break the row layout (CSV preserves them faithfully instead).
fn render_table(findings: &[Finding]) -> String {
    let rows: Vec<[String; 5]> = findings
        .iter()
        .map(|f| cells(f).map(|cell| collapse_whitespace(&cell)))
        .collect();

    let mut widths: [usize; 5] = COLUMNS.map(str::len);
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }

    let mut out = String::new();
    push_row(&mut out, &COLUMNS.map(String::from), &widths);
    let separators: [String; 5] = std::array::from_fn(|i| "-".repeat(widths[i]));
    push_row(&mut out, &separators, &widths);
    for row in &rows {
        push_row(&mut out, row, &widths);
    }
    if rows.is_empty() {
        out.push_str("(no findings)\n");
    }
    out
}

/// Append one `" | "`-separated, right-padded row to `out`.
fn push_row(out: &mut String, row: &[String; 5], widths: &[usize; 5]) {
    let padded: Vec<String> = row
        .iter()
        .enumerate()
        .map(|(i, cell)| {
            let pad = widths[i].saturating_sub(cell.chars().count());
            format!("{cell}{}", " ".repeat(pad))
        })
        .collect();
    out.push_str(padded.join(" | ").trim_end());
    out.push('\n');
}

/// Collapse any run of whitespace (including newlines) into single spaces.
fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Render the findings as pretty-printed, machine-readable JSON.
fn render_json(findings: &[Finding]) -> Result<String> {
    let mut json = serde_json::to_string_pretty(findings)
        .map_err(|e| Error::Other(format!("failed to render findings as JSON: {e}")))?;
    json.push('\n');
    Ok(json)
}

/// Render the findings as CSV with the stable [`COLUMNS`] header row. Fields
/// containing commas, quotes, or newlines are escaped per RFC 4180 so the output
/// stays parseable.
fn render_csv(findings: &[Finding]) -> String {
    let mut out = String::new();
    push_csv_record(&mut out, &COLUMNS.map(String::from));
    for finding in findings {
        push_csv_record(&mut out, &cells(finding));
    }
    out
}

/// Append one CSV record (terminated by `\n`) with each field escaped.
fn push_csv_record(out: &mut String, fields: &[String; 5]) {
    let escaped: Vec<String> = fields.iter().map(|f| csv_escape(f)).collect();
    out.push_str(&escaped.join(","));
    out.push('\n');
}

/// Escape a CSV field: wrap it in double quotes (doubling any interior quote) when
/// it contains a comma, quote, or line break; otherwise emit it verbatim.
fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssum_core::Target;

    /// A fixed fixture: three findings, one carrying a title with an embedded
    /// comma and newline to exercise CSV escaping.
    fn fixture() -> Vec<Finding> {
        vec![
            Finding::builder(
                "cors",
                Target::parse("https://a.test").unwrap(),
                "Reflected origin",
            )
            .severity(Severity::High)
            .status(Status::Vulnerable)
            .build(),
            Finding::builder(
                "bac",
                Target::parse("https://b.test").unwrap().with_path("/admin"),
                "Admin reachable, no auth\nrequired",
            )
            .severity(Severity::Critical)
            .status(Status::Vulnerable)
            .build(),
            Finding::builder(
                "rest_discovery",
                Target::parse("https://c.test").unwrap(),
                "Endpoint observed",
            )
            .build(),
        ]
    }

    /// The set of titles present in the fixture, for cross-format agreement checks.
    fn fixture_titles() -> Vec<String> {
        fixture().iter().map(|f| f.title.clone()).collect()
    }

    #[test]
    fn table_has_the_expected_columns_and_rows() {
        let table = render_table(&fixture());
        let header = table.lines().next().unwrap();
        for column in COLUMNS {
            assert!(header.contains(column), "header missing {column}: {header}");
        }
        // Header + separator + one line per finding.
        assert_eq!(table.lines().count(), 2 + fixture().len());
        assert!(table.contains("cors"));
        assert!(table.contains("https://b.test/admin"));
        // The multi-line title is collapsed onto a single row.
        assert!(table.contains("Admin reachable, no auth required"));
    }

    #[test]
    fn empty_findings_render_a_table_with_a_placeholder() {
        let table = render_table(&[]);
        assert!(table.contains("Scanner"));
        assert!(table.contains("(no findings)"));
    }

    #[test]
    fn json_round_trips_to_the_same_findings() {
        // Build the fixture once: each build stamps fresh timestamps, so reusing a
        // single set is what makes the round-trip comparison exact.
        let findings = fixture();
        let json = render_json(&findings).unwrap();
        let back: Vec<Finding> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, findings);
    }

    #[test]
    fn csv_has_a_stable_header_and_escapes_special_characters() {
        let csv = render_csv(&fixture());
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().unwrap(),
            "Scanner,Target,Status,Severity,Title"
        );

        // The comma+newline title is quoted, with the newline preserved inside the
        // quoted field (so the record spans two physical lines).
        assert!(
            csv.contains("\"Admin reachable, no auth\nrequired\""),
            "CSV did not escape the comma/newline title: {csv:?}"
        );

        // Re-parsing the CSV with a real parser recovers exactly the rows we wrote.
        let records = parse_csv(&csv);
        assert_eq!(records.len(), fixture().len() + 1, "header + one row each");
        assert_eq!(records[0], COLUMNS.to_vec());
        assert_eq!(records[2][4], "Admin reachable, no auth\nrequired");
    }

    #[test]
    fn all_three_formats_reflect_the_same_findings() {
        let findings = fixture();
        let table = render(&findings, OutputFormat::Table).unwrap();
        let json = render(&findings, OutputFormat::Json).unwrap();
        let csv = render(&findings, OutputFormat::Csv).unwrap();

        // JSON: parsed back, the findings are identical to the source.
        let from_json: Vec<Finding> = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json, findings);

        // CSV: the data rows (after the header) carry every title.
        let csv_titles: Vec<String> = parse_csv(&csv)
            .into_iter()
            .skip(1)
            .map(|record| record[4].clone())
            .collect();
        assert_eq!(csv_titles, fixture_titles());

        // Table: every title appears (with internal whitespace collapsed).
        for title in fixture_titles() {
            assert!(table.contains(&collapse_whitespace(&title)));
        }
    }

    /// A minimal RFC 4180 CSV parser sufficient for the test fixtures: handles
    /// quoted fields, doubled quotes, and embedded commas/newlines.
    fn parse_csv(input: &str) -> Vec<Vec<String>> {
        let mut records = Vec::new();
        let mut record = Vec::new();
        let mut field = String::new();
        let mut in_quotes = false;
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if in_quotes {
                match c {
                    '"' if chars.peek() == Some(&'"') => {
                        chars.next();
                        field.push('"');
                    }
                    '"' => in_quotes = false,
                    other => field.push(other),
                }
            } else {
                match c {
                    '"' => in_quotes = true,
                    ',' => {
                        record.push(std::mem::take(&mut field));
                    }
                    '\n' => {
                        record.push(std::mem::take(&mut field));
                        records.push(std::mem::take(&mut record));
                    }
                    '\r' => {}
                    other => field.push(other),
                }
            }
        }
        if !field.is_empty() || !record.is_empty() {
            record.push(field);
            records.push(record);
        }
        records
    }
}
