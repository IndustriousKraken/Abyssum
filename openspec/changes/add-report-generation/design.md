# Design: Report Generation

## Technical Approach

A `ReportGenerator` in `abyssum-core` reads a session and its findings through the persistence
layer (`add-result-persistence`) and serializes them into one of four output forms. It performs
no I/O of its own beyond the store read and returns the rendered bytes/string to the caller
(CLI writes to stdout/file; web returns them as a download). It never touches the network.

```
load session + findings from store
    -> render(format, options) -> String/bytes
formats: markdown | json | csv | hackerone
```

Findings already carry scanner id, target, status classification, severity, and evidence from
persistence. The generator adds two derived, type-keyed lookups that are *content*, not new
behavior: a remediation recommendation and an impact statement per finding type. These are
static tables (CORS, BAC, IDOR, GraphQL, REST discovery, OpenAPI) with a sensible generic
fallback, mirroring v1's `_get_remediation` / `_generate_impact_statement`.

## Library Choices

- **JSON:** `serde` / `serde_json` for the export shape.
- **CSV:** the `csv` crate for correct quoting/escaping of descriptions and evidence.
- **Markdown / HackerOne:** plain string templating (`format!` / a tiny string builder); no
  templating engine needed for these documents.
- **Time formatting:** `chrono`/`time` (whichever the workspace already uses) for the scan-date
  and export-timestamp strings.

## Key Decisions

### Decision: Reports are pure functions of stored data
The generator reads the store and renders. It does not re-scan, re-fetch, or mutate anything,
so a report is deterministic and reproducible for a given session state and can be tested with
in-memory fixtures.

### Decision: Only reportable findings appear
A report includes the findings persistence classifies as actual issues (status indicating a
vulnerability/exposure), not benign/absent probe results, so a submission is not padded with
non-findings. The exact status set is whatever persistence stores; the observable contract is
"benign results are excluded".

### Decision: Severity ordering and HackerOne lead finding
Severity orders critical > high > medium > low > info. Markdown groups findings in that order;
the HackerOne export leads with the single most-severe finding and appends the rest as
additional findings. Ties break deterministically (e.g. by stored order) so output is stable.

### Decision: Remediation/impact text is built-in content
v1 keyed remediation, impact, and references off the finding type. v2 keeps that as embedded
content tables in the report layer rather than storing it per finding, so adding a scanner type
only requires a table entry. Unknown types fall back to a generic recommendation.

### Decision: Annotations are out of scope here
v1 folded session notes/tags into reports, but in the v2 implementation order annotations
(#15) and report-generation (#16) are independent and this change depends only on
`result-persistence`. So the spec does not require notes/tags in reports; an annotations change
may later `MODIFIED` these requirements to weave them in.

## Testing

- Unit-render each format from an in-memory fixture session with a mix of severities; assert the
  document contains the target, the severity breakdown counts, each finding's type/severity/
  endpoint, evidence (when included) and remediation text.
- Test the evidence-omission option produces a report with no evidence blocks.
- Test CSV has a header row plus exactly one row per reportable finding, with descriptions and
  evidence correctly quoted/escaped.
- Test JSON round-trips: parse the export and assert session count, per-session metadata, and
  finding fields.
- Test the HackerOne export leads with the most-severe finding and errors when a session has no
  reportable findings.
- Test that benign/non-finding results are excluded from every format.
- **No network, no real targets** — all fixtures are in-memory.
