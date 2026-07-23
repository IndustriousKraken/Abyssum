# web-ui

## ADDED Requirements

### Requirement: Engagement Results Rollup
The web interface SHALL present, on an engagement's detail view, a rollup of the results across
the scans associated with that engagement — a breakdown of findings by severity together with the
findings aggregated across those scans — so an operator sees the engagement's results in one place
without opening each scan. The rollup SHALL include only sessions associated with the engagement
that the operator is already permitted to see under the existing per-user visibility rule: a
non-admin operator's rollup covers only their own sessions within the engagement, while an
operator with the admin role sees all of the engagement's sessions. The rollup SHALL NOT disclose
any session or finding the operator could not already view.

#### Scenario: Rollup summarizes the operator's findings across the engagement's scans
- **GIVEN** an engagement with several associated scans the operator owns, which have produced findings
- **WHEN** the operator opens the engagement's detail view
- **THEN** the system SHALL show a breakdown of those findings by severity
- **AND** SHALL present the findings aggregated across the operator's scans associated with the engagement

#### Scenario: Rollup covers only the engagement's sessions
- **GIVEN** findings spread across sessions associated with the engagement and other sessions that are not
- **WHEN** the rollup is shown
- **THEN** it SHALL count and present only findings from sessions associated with that engagement
- **AND** SHALL NOT include findings from other engagements or from unassociated sessions

#### Scenario: Rollup does not widen per-user visibility
- **GIVEN** an engagement whose associated sessions include one owned by a different operator
- **AND** an authenticated non-admin operator viewing that engagement
- **WHEN** the rollup is shown
- **THEN** it SHALL NOT include the other operator's session or its findings
- **AND** an operator with the admin role viewing the same engagement SHALL see all of its associated sessions in the rollup
