# run-diff Specification

## Purpose
TBD - created by archiving change add-run-diff. Update Purpose after archive.
## Requirements
### Requirement: Diff Two Scan Sessions
The CLI SHALL accept two stored scan sessions — an older and a newer — and report the
difference between their findings for the same targets: findings present in the newer
session but not the older (added), findings present in the older but not the newer
(resolved), and findings matched across both whose severity or status changed
(changed). Findings that are unchanged SHALL NOT appear in the detailed delta. If
either session identifier does not refer to a stored session, the command SHALL report
the error and produce no diff.

#### Scenario: Added finding is reported
- **GIVEN** a finding present in the newer session and absent from the older
- **WHEN** the two sessions are diffed
- **THEN** it SHALL be reported as added

#### Scenario: Resolved finding is reported
- **GIVEN** a finding present in the older session and absent from the newer
- **WHEN** the two sessions are diffed
- **THEN** it SHALL be reported as resolved

#### Scenario: Changed finding is reported
- **GIVEN** a finding present in both sessions whose severity or status differs between them
- **WHEN** the two sessions are diffed
- **THEN** it SHALL be reported as changed, showing the old and new severity or status

#### Scenario: Unchanged findings are excluded from the detail
- **GIVEN** a finding identical in both sessions
- **WHEN** the two sessions are diffed
- **THEN** it SHALL NOT appear in the detailed delta

#### Scenario: Unknown session is rejected
- **GIVEN** a session identifier that does not refer to a stored session
- **WHEN** a diff is requested with it
- **THEN** the command SHALL report the error and produce no diff

