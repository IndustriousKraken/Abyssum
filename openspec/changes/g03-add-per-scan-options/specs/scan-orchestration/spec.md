# scan-orchestration

## ADDED Requirements

### Requirement: A Scan Is Started With Options
A scan SHALL be able to be started with a set of per-scan options recorded for that scan, so
that scan-specific choices are carried with the scan rather than coming only from global
configuration. A scan started with no options SHALL behave exactly as one started before this
capability existed, with defaults applying.

#### Scenario: Options are recorded for the scan
- **GIVEN** a scan started with a set of per-scan options
- **WHEN** the scan is created
- **THEN** those options SHALL be recorded for that scan

#### Scenario: No options means defaults
- **GIVEN** a scan started without any per-scan options
- **WHEN** the scan runs
- **THEN** it SHALL behave as it would have before per-scan options existed, applying defaults

### Requirement: Per-Scan Options Are Available To Scanners
The engine SHALL make a scan's per-scan options available to scanners through the scan context
during the run, so a scanner can adjust its behavior for that scan. Exposing options SHALL NOT
introduce any way to issue a request that bypasses pacing.

#### Scenario: A scanner reads the scan's options
- **GIVEN** a scan running with per-scan options set
- **WHEN** a scanner consults the scan context
- **THEN** it SHALL be able to read the options relevant to it

#### Scenario: Options add no unpaced request path
- **GIVEN** a scan context that carries per-scan options
- **WHEN** a scanner uses the context
- **THEN** the only request path SHALL still pace through the shared rate limiter
- **AND** the options SHALL NOT provide a way to send an unpaced request
