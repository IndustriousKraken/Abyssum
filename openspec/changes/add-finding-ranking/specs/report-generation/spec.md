# report-generation

## MODIFIED Requirements

### Requirement: Markdown Submission Report
The system SHALL render a scan session's findings as a self-contained Markdown document
suitable for a bug-bounty submission, including session metadata, an executive summary with a
severity breakdown, and per-finding detail covering type, severity, target endpoint,
description, evidence (included by default; omissible per the Evidence Inclusion Control
requirement), and a remediation recommendation.

#### Scenario: Findings ordered most-severe-first
- **GIVEN** a session with findings of differing statuses and severities
- **WHEN** a Markdown report is generated
- **THEN** findings SHALL be ordered by status — vulnerable first, then safe, then informational
- **AND** within each status, higher-severity findings SHALL appear before lower-severity findings

### Requirement: HackerOne-Formatted Export
The system SHALL produce a Markdown report shaped to a HackerOne submission, leading with the
session's most important finding (per the importance ordering: vulnerable status first, then
highest severity) and presenting Summary, Steps To Reproduce, Impact, and Supporting Material
sections, and listing any remaining findings.

#### Scenario: Lead with the most-important finding
- **GIVEN** a session whose findings span several statuses and severities
- **WHEN** a HackerOne-formatted export is generated
- **THEN** the report SHALL be built around the finding ranked most important — vulnerable status first, then highest severity
- **AND** SHALL include Summary, Steps To Reproduce, Impact, and Supporting Material sections
