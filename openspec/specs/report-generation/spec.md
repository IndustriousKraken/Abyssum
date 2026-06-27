# report-generation Specification

## Purpose
TBD - created by archiving change d01-add-report-generation. Update Purpose after archive.
## Requirements
### Requirement: Markdown Submission Report
The system SHALL render a scan session's findings as a self-contained Markdown document
suitable for a bug-bounty submission, including session metadata, an executive summary with a
severity breakdown, and per-finding detail covering type, severity, target endpoint,
description, evidence (included by default; omissible per the Evidence Inclusion Control
requirement), and a remediation recommendation.

#### Scenario: Report contains session metadata and summary
- **GIVEN** a stored session with one or more findings
- **WHEN** a Markdown report is generated for the session
- **THEN** the document SHALL include the session's target, scan date, scanner ids, and session identifier
- **AND** SHALL include a summary stating the total number of findings
- **AND** SHALL include a count of findings for each severity level

#### Scenario: Each finding is detailed
- **GIVEN** a stored session with a finding of a given type and severity
- **WHEN** a Markdown report is generated
- **THEN** the document SHALL include that finding's type, severity, target endpoint, and description
- **AND** SHALL include a remediation recommendation for the finding

#### Scenario: Findings ordered most-severe-first
- **GIVEN** a session with findings of differing severities
- **WHEN** a Markdown report is generated
- **THEN** higher-severity findings SHALL appear before lower-severity findings

#### Scenario: Unknown session is rejected
- **WHEN** a report is requested for a session identifier that does not exist
- **THEN** the system SHALL return a not-found error
- **AND** SHALL NOT produce a report

### Requirement: Evidence Inclusion Control
The system SHALL include each finding's evidence in Markdown, JSON, and HackerOne-formatted
reports by default and SHALL provide an option to omit evidence so a redacted report can be
produced. CSV output is a summary-only format and does not carry evidence.

#### Scenario: Evidence included by default
- **GIVEN** a finding that carries evidence
- **WHEN** a report is generated with evidence inclusion enabled
- **THEN** the finding's evidence SHALL appear in the report

#### Scenario: Evidence omitted on request
- **GIVEN** a finding that carries evidence
- **WHEN** a report is generated with evidence inclusion disabled
- **THEN** the report SHALL NOT contain that finding's evidence
- **AND** SHALL still contain the finding's type, severity, and description

### Requirement: JSON Export
The system SHALL produce a structured, machine-readable JSON export covering one or more
sessions, where each session carries its metadata and its full list of findings including each
finding's type, severity, target, status classification, and evidence (included by default;
omissible per the Evidence Inclusion Control requirement).

#### Scenario: Export a single session
- **GIVEN** a stored session with findings
- **WHEN** a JSON export is generated for that session
- **THEN** the export SHALL be valid JSON
- **AND** SHALL contain the session's metadata and each finding's type, severity, target, status, and evidence (when evidence inclusion is enabled)

#### Scenario: Export multiple sessions together
- **GIVEN** two stored sessions
- **WHEN** a JSON export is generated for both
- **THEN** the export SHALL report a session count of two
- **AND** SHALL contain a separate entry for each session

### Requirement: CSV Summary
The system SHALL produce a CSV summary with a header row followed by exactly one row per
reportable finding across the selected sessions, carrying the session, target, scanner id,
finding type, severity, endpoint, and a description.

#### Scenario: One row per finding
- **GIVEN** selected sessions containing a known number of reportable findings
- **WHEN** a CSV summary is generated
- **THEN** the output SHALL contain a header row
- **AND** SHALL contain exactly one data row per reportable finding
- **AND** each row SHALL include the session, target, scanner id, finding type, severity, endpoint, and description

#### Scenario: Special characters are escaped
- **GIVEN** a finding whose description contains a comma, quote, or newline
- **WHEN** a CSV summary is generated
- **THEN** the field SHALL be quoted or escaped so the CSV remains well-formed

### Requirement: HackerOne-Formatted Export
The system SHALL produce a Markdown report shaped to a HackerOne submission, leading with the
session's most-severe finding and presenting Summary, Steps To Reproduce, Impact, and
Supporting Material sections, and listing any remaining findings.

#### Scenario: Lead with the most-severe finding
- **GIVEN** a session whose findings span several severities
- **WHEN** a HackerOne-formatted export is generated
- **THEN** the report SHALL be built around the highest-severity finding
- **AND** SHALL include Summary, Steps To Reproduce, Impact, and Supporting Material sections

#### Scenario: Additional findings are listed
- **GIVEN** a session with more than one reportable finding
- **WHEN** a HackerOne-formatted export is generated
- **THEN** the report SHALL list the findings other than the lead finding

#### Scenario: No reportable findings is an error
- **GIVEN** a session that has no reportable findings
- **WHEN** a HackerOne-formatted export is requested
- **THEN** the system SHALL return an error indicating there is nothing to report

### Requirement: Only Reportable Findings Included
The system SHALL include only findings classified as actual issues in every report format,
excluding benign or absent probe results so a report is not padded with non-findings.

#### Scenario: Benign results are excluded
- **GIVEN** a session whose stored results include both reportable findings and benign results
- **WHEN** a report is generated in any format
- **THEN** the report SHALL include the reportable findings
- **AND** SHALL NOT include the benign results

### Requirement: Report Command Surface
The CLI SHALL expose a command that generates a report for one or more stored sessions in a
chosen format — markdown, json, csv, or hackerone — writing it to standard output or a named
file, with an option to omit evidence, so report generation is reachable by an operator and
not merely an internal capability. The markdown and hackerone formats accept exactly one
session identifier; the json and csv formats accept one or more session identifiers.

#### Scenario: Generate a report in a chosen format
- **GIVEN** one or more stored sessions with reportable findings
- **WHEN** the operator runs the report command naming those sessions and a format
- **THEN** the system SHALL write the report in that format to the chosen destination

#### Scenario: Report command rejects an unknown session
- **WHEN** the report command names a session identifier that does not exist
- **THEN** the system SHALL exit with an error
- **AND** SHALL NOT write a report

