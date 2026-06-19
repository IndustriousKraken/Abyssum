# Scan Orchestration Delta

## ADDED Requirements

### Requirement: Base Scanner Contract

Every scanner SHALL expose a stable identifier, a human-readable name, and a description,
and SHALL provide a single operation that scans one target and returns zero or more
findings. A scanner SHALL NOT own request pacing, progress reporting, or cancellation; those
SHALL be supplied to it when it runs.

#### Scenario: Scanner exposes stable identity

- **WHEN** a scanner is inspected
- **THEN** it SHALL report a stable scanner id, a human-readable name, and a description
- **AND** the scanner id SHALL be the value used to select the scanner

#### Scenario: Scanning a target yields findings

- **GIVEN** a scanner and a target the scanner can handle
- **WHEN** the engine runs the scanner against the target
- **THEN** the scanner SHALL return zero or more findings
- **AND** each finding SHALL identify the target it concerns and the scanner that produced it

### Requirement: Scanner Registry And Selection

The system SHALL expose available scanners through a registry in which each scanner is
addressable by its stable id, and a scan SHALL select scanners by id.

#### Scenario: List available scanners

- **WHEN** the registry is queried for available scanners
- **THEN** it SHALL return each registered scanner's stable id

#### Scenario: Select scanners by id

- **GIVEN** a registry containing a scanner with a known id
- **WHEN** a scan is requested naming that id
- **THEN** the engine SHALL run that scanner

#### Scenario: Unknown scanner id is rejected before scanning

- **GIVEN** a scan request naming a scanner id that is not registered
- **WHEN** the engine prepares the scan
- **THEN** it SHALL reject the request with a clear error
- **AND** it SHALL NOT issue any requests to any target

### Requirement: Scan Context Provided To Scanners

When the engine runs a scanner it SHALL provide a scan context that lets the scanner issue
HTTP requests, pace those requests through the shared rate limiter, report progress, and
observe a cancellation signal.

#### Scenario: Requests are paced through the shared limiter

- **GIVEN** a scanner issuing multiple requests via the scan context
- **WHEN** the scanner sends each request
- **THEN** the request SHALL be paced through the shared rate limiter so the configured
  pacing floor is never undercut

#### Scenario: Scanner reports progress through the context

- **GIVEN** a scanner running with a scan context that carries a progress callback
- **WHEN** the scanner reports progress
- **THEN** the progress SHALL be delivered to the callback

#### Scenario: Scanner observes cancellation through the context

- **GIVEN** a scan context whose cancellation signal has been raised
- **WHEN** the scanner checks for cancellation
- **THEN** the context SHALL indicate the scan is cancelled

### Requirement: Scan Session Lifecycle

A scan session SHALL run the selected scanners against one or more targets, aggregate all
findings, and move through observable lifecycle states from running to a terminal state of
completed, cancelled, or errored.

#### Scenario: Session aggregates findings from all scanners and targets

- **GIVEN** a session selecting multiple scanners over multiple targets
- **WHEN** the session runs to completion
- **THEN** every finding produced by any selected scanner on any target SHALL be aggregated
  into the session
- **AND** the session SHALL reach the completed state

#### Scenario: Lifecycle states are observable

- **GIVEN** a session that has been started
- **WHEN** its status is queried while it runs and after it finishes
- **THEN** the status SHALL read running while the scan is in progress
- **AND** SHALL read completed, cancelled, or errored once the scan ends

#### Scenario: One target's failure does not abort the session

- **GIVEN** a session in which a scanner fails on one target
- **WHEN** the session continues
- **THEN** the engine SHALL record the error and proceed with the remaining targets and
  scanners
- **AND** the session SHALL still reach a terminal state rather than aborting

### Requirement: Progress Events During A Scan

While a scan session runs, the engine SHALL emit progress updates that report how many units
have been tested out of the total and what is currently being tested.

#### Scenario: Progress carries tested, total, and current

- **GIVEN** a session in progress
- **WHEN** the engine emits a progress update
- **THEN** the update SHALL indicate how many units have been tested out of the total
- **AND** SHALL indicate the item currently being tested

#### Scenario: Progress is emitted during the scan, not only at the end

- **GIVEN** a session running multiple units of work
- **WHEN** the scan proceeds
- **THEN** progress updates SHALL be emitted as units complete, before the session reaches a
  terminal state

### Requirement: Cancellation With Prompt Partial Results

A running scan session SHALL be cancellable, and on cancellation scanners SHALL stop issuing
new requests promptly, the session SHALL transition to the cancelled state, and the findings
gathered before cancellation SHALL remain available.

#### Scenario: Cancellation stops new requests promptly

- **GIVEN** a scan session in progress
- **WHEN** the session is cancelled
- **THEN** scanners SHALL stop issuing new requests promptly
- **AND** the session status SHALL transition to cancelled

#### Scenario: Partial findings survive cancellation

- **GIVEN** a scan that has produced some findings
- **WHEN** the scan is cancelled before completing
- **THEN** the findings gathered before cancellation SHALL remain available in the session
