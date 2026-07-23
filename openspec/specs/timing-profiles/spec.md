# timing-profiles Specification

## Purpose
TBD - created by archiving change g05-add-timing-profiles. Update Purpose after archive.
## Requirements
### Requirement: A Library Of Selectable Timing Profiles
The system SHALL provide a built-in library of timing profiles spanning from fast to highly
cautious, including an organic profile whose request timing imitates irregular, non-periodic
traffic. Each profile SHALL define how target-facing requests are paced — the delay
distribution — so an operator can choose a balance between finishing quickly and staying
inconspicuous without hand-tuning individual delays.

#### Scenario: The library spans the fast-to-cautious range
- **GIVEN** the built-in timing-profile library
- **WHEN** an operator reviews it
- **THEN** it SHALL offer multiple profiles ranging from faster to more cautious pacing

#### Scenario: An organic profile is available
- **GIVEN** the built-in timing-profile library
- **WHEN** an operator reviews it
- **THEN** it SHALL include an organic profile whose timing is irregular and non-periodic

### Requirement: Timing Profiles Are Per-User And Reusable
Timing profiles SHALL be owned by a user and reusable across that user's scans. A user's
profiles SHALL be visible and selectable only to that user, and a user SHALL be able to select
one of their profiles when starting a scan and to adjust or add their own.

#### Scenario: A profile is reusable across scans
- **GIVEN** a user with a saved timing profile
- **WHEN** they start more than one scan
- **THEN** the same profile SHALL be selectable for each

#### Scenario: Profiles are private to their owner
- **GIVEN** two users each with their own profiles
- **WHEN** one user views the selectable profiles
- **THEN** the other user's profiles SHALL NOT be visible to them

#### Scenario: A user may select a profile when starting a scan
- **GIVEN** a user starting a scan
- **WHEN** they choose a timing profile
- **THEN** that selection SHALL be recorded for the scan

### Requirement: A Scan Runs Under Its Selected Timing Profile
The system SHALL pace a scan's target-facing requests according to the timing profile selected
for that scan. When no profile is selected, a conservative default profile SHALL apply.

#### Scenario: The selected profile governs pacing
- **GIVEN** a scan started with a selected timing profile
- **WHEN** it issues target-facing requests
- **THEN** their pacing SHALL follow that profile's distribution

#### Scenario: No selection uses the conservative default
- **GIVEN** a scan started without selecting a profile
- **WHEN** it issues target-facing requests
- **THEN** a conservative default profile SHALL apply

### Requirement: The Organic Profile Avoids A Detectable Cadence
The organic profile SHALL draw inter-request gaps from a distribution that is neither a fixed
period nor a narrow constant band, and SHALL include occasional longer pauses, so its traffic
does not exhibit a constant rate or a detectable periodic cadence.

#### Scenario: Gaps are irregular and heavy-tailed
- **GIVEN** the organic profile is active
- **WHEN** many requests are paced
- **THEN** the gaps SHALL NOT all be near-equal
- **AND** occasional gaps SHALL be substantially longer than the typical gap

#### Scenario: No fixed period
- **GIVEN** the organic profile is active
- **WHEN** many requests are paced
- **THEN** the gaps SHALL NOT repeat on a fixed period

### Requirement: Timing Profiles Preserve Target Safety
A timing profile SHALL NOT disable the protections that keep the system from overwhelming a
target. Adaptive backoff on rate-limit signals and the target-distress stop condition SHALL
remain in effect regardless of the selected profile.

#### Scenario: Distress halt still applies under any profile
- **GIVEN** any selected timing profile
- **WHEN** a target's responses signal sustained distress
- **THEN** the distress stop condition SHALL still halt probing of that target

#### Scenario: Backoff still applies under any profile
- **GIVEN** any selected timing profile
- **WHEN** a target signals rate limiting
- **THEN** adaptive backoff SHALL still increase the delay for that target

