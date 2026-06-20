# Scan Orchestration Delta

## ADDED Requirements

### Requirement: Scan Target Model

A scan target SHALL be represented by a single shared target type so every scanner, the
engine, and persistence describe a target the same way. A target SHALL carry a base URL (the
scheme, host, and optional port that identifies the origin) and MAY carry a path or route
beneath that origin. A target MAY also carry a parameterized path template containing a
placeholder for an object reference, so reference-enumeration scanners can substitute values.
The registrable host used for per-domain pacing SHALL be derivable from the target's base URL.

#### Scenario: Target exposes its origin and full URL

- **GIVEN** a target constructed from a base URL and an optional path
- **WHEN** the engine resolves the target
- **THEN** the target SHALL expose the base URL identifying its origin
- **AND** SHALL expose a full URL formed by joining the base URL with the path when a path is present

#### Scenario: Pacing host derives from the target

- **GIVEN** a target whose base URL names a host
- **WHEN** the engine paces requests to that target
- **THEN** the per-domain pacing SHALL key on the host derived from the target's base URL

#### Scenario: Object-reference template carries a placeholder

- **GIVEN** a target that includes a parameterized path template with an object-reference placeholder
- **WHEN** a reference-enumeration scanner substitutes a value for the placeholder
- **THEN** the scanner SHALL obtain a concrete full URL for that value

### Requirement: Canonical Finding Record

The engine SHALL represent every result with one shared finding type so scanners,
persistence, reporting, and analysis all describe a finding identically. A finding SHALL
carry the scanner id that produced it, the target it concerns, a severity level, a status
classification, and a title; SHALL allow an optional description, optional structured
evidence, and optional remediation guidance; and SHALL record a timestamp. A finding that has
been persisted SHALL be addressable by a stable identifier. The severity and status SHALL each
be drawn from the fixed sets defined below; severity SHALL NOT be omitted.

#### Scenario: Finding identifies its origin and disposition

- **GIVEN** a scanner produces a finding
- **WHEN** the finding is inspected
- **THEN** it SHALL identify the producing scanner and the target it concerns
- **AND** it SHALL carry a severity level and a status classification, each from the defined sets
- **AND** it SHALL carry a human-readable title

#### Scenario: A persisted finding is referenceable by a stable identifier

- **GIVEN** a finding that has been stored
- **WHEN** another capability needs to reference that finding
- **THEN** the finding SHALL be addressable by a stable identifier that does not change

### Requirement: Finding Severity Levels

Every finding's severity SHALL be exactly one of a fixed, ordered set of levels —
informational, low, medium, high, critical — shared by all scanners, so severity is
comparable and filterable across scanners. A scanner that reports only observations SHALL use
the informational level rather than omitting severity.

#### Scenario: Severity is from the shared set

- **WHEN** any scanner emits a finding
- **THEN** the finding's severity SHALL be exactly one of informational, low, medium, high, or critical

#### Scenario: Severity levels are ordered

- **GIVEN** two findings with different severities
- **WHEN** they are compared
- **THEN** the levels SHALL order from informational (lowest) through critical (highest)

### Requirement: Finding Status Classification

Every finding's status SHALL be exactly one of a fixed set of dispositions shared by all
scanners — vulnerable, safe, or informational — distinguishing a confirmed weakness from a
checked-and-sound result from a neutral observation. Scanner-specific detail (such as
"accessible" or "introspection enabled") SHALL be conveyed in the finding's title or
description, not by inventing new status values.

#### Scenario: Status is from the shared set

- **WHEN** any scanner emits a finding
- **THEN** the finding's status SHALL be exactly one of vulnerable, safe, or informational

#### Scenario: Reportable findings are identifiable by status

- **GIVEN** findings with differing statuses
- **WHEN** a consumer selects the findings worth reporting
- **THEN** it SHALL be able to identify the vulnerable findings by their status

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

When the engine runs a scanner it SHALL provide a scan context that is the scanner's only
means of issuing HTTP requests, so that every request is paced through the shared rate limiter
and carries a User-Agent applied by the engine, and that lets the scanner report progress and
observe a cancellation signal. The context SHALL NOT expose any way to issue a request that
bypasses pacing.

#### Scenario: Requests are paced through the shared limiter

- **GIVEN** a scanner issuing multiple requests via the scan context
- **WHEN** the scanner sends each request
- **THEN** the request SHALL be paced through the shared rate limiter so the configured
  pacing floor is never undercut

#### Scenario: No unpaced request path is available

- **GIVEN** a scanner with a scan context
- **WHEN** the scanner issues any HTTP request
- **THEN** the only request path the context provides SHALL pace through the shared rate limiter
- **AND** there SHALL be no context-provided way to send a request that skips pacing

#### Scenario: Each request carries a User-Agent applied by the engine

- **GIVEN** a scanner issuing requests through the context
- **WHEN** each request is sent
- **THEN** the engine SHALL set the request's User-Agent from its configured User-Agent source

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
