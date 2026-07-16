# finding-ranking Specification

## Purpose
TBD - created by archiving change add-finding-ranking. Update Purpose after archive.
## Requirements
### Requirement: Collapse Duplicate Findings
The system SHALL collapse findings that describe the same issue — the same scanner,
the same normalized target/endpoint, and the same finding class — into a single
reported finding that carries the number of times the issue was observed. Findings
that differ in scanner, target/endpoint, or class SHALL remain separate.

#### Scenario: Repeated identical findings collapse
- **GIVEN** several findings sharing scanner, normalized target/endpoint, and class
- **WHEN** results are reported
- **THEN** they SHALL appear as a single finding with an occurrence count reflecting how many were observed

#### Scenario: Distinct findings are not collapsed
- **GIVEN** two findings that differ in scanner, target/endpoint, or class
- **WHEN** results are reported
- **THEN** they SHALL remain separate findings

### Requirement: Rank Findings By Importance
Reported findings SHALL be ordered by importance: findings with vulnerable status
before those with safe or informational status, then by descending severity. Ordering
SHALL be deterministic, so that findings of equal rank keep a stable, repeatable order.

This requirement modifies the canonical `report-generation` spec's ordering rules so that they follow this importance ordering rather than severity alone: the 'Findings ordered most-severe-first' scenario under 'Markdown Submission Report' is ordered by status (vulnerable first, then safe, then informational) and within each status by descending severity; the 'Lead with the most-severe finding' scenario under 'HackerOne-Formatted Export' leads with the most important finding (vulnerable status first, then highest severity).

#### Scenario: Higher importance sorts first
- **GIVEN** a mix of findings across statuses and severities
- **WHEN** results are reported
- **THEN** vulnerable findings SHALL appear before informational ones
- **AND** within the same status, higher severity SHALL appear before lower severity

#### Scenario: Equal-rank ordering is stable
- **GIVEN** two findings of equal status and severity
- **WHEN** the same results are reported more than once
- **THEN** their relative order SHALL be the same each time

