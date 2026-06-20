# Rate Limiting Delta

## ADDED Requirements

### Requirement: Randomized Per-Request Pacing

Between consecutive requests to the same domain the system SHALL wait a random duration drawn
uniformly between the configured minimum and maximum delay, so request timing does not form a
fixed or predictable pattern.

#### Scenario: Delay falls within the configured band

- **GIVEN** a configured minimum and maximum delay
- **WHEN** the system paces a request to a domain that has been seen before
- **THEN** the applied delay SHALL be at least the configured minimum
- **AND** the applied delay SHALL be at most the configured maximum plus any active backoff

#### Scenario: Successive delays vary

- **GIVEN** a configured minimum that is strictly less than the configured maximum
- **WHEN** the system paces many requests to the same domain
- **THEN** the applied delays SHALL NOT all be identical

### Requirement: First Request Has No Artificial Delay

The system SHALL issue the first request to a given domain with no artificial pacing delay,
applying pacing only to subsequent requests to that domain.

#### Scenario: First request to a domain is immediate

- **GIVEN** a domain that has not yet been requested in this run
- **WHEN** the system paces the first request to that domain
- **THEN** it SHALL apply no artificial delay

#### Scenario: Second request to a domain is paced

- **GIVEN** a domain whose first request has already been made
- **WHEN** the system paces the next request to that domain
- **THEN** it SHALL apply a delay of at least the configured minimum

### Requirement: Per-Domain Independent Pacing

The system SHALL track pacing state independently for each domain, so activity against one
host does not affect the timing of requests to another host.

#### Scenario: A new domain still gets its free first request

- **GIVEN** one domain has already been paced for several requests
- **WHEN** the system paces the first request to a different domain
- **THEN** that different domain SHALL receive its first request with no artificial delay

#### Scenario: Backoff is isolated per domain

- **GIVEN** one domain has accumulated extra backoff from rate-limit signals
- **WHEN** the system paces a request to a different domain with no such signals
- **THEN** the different domain's delay SHALL NOT include the first domain's extra backoff

### Requirement: Adaptive Backoff On Rate-Limit Signals

The system SHALL add extra delay for a domain when its responses signal rate limiting or
forbidden access, growing that extra delay on repeated signals up to a fixed cap and
recovering it back toward zero as signals stop.

#### Scenario: A rate-limit signal adds backoff

- **GIVEN** a domain being paced at the configured delay
- **WHEN** the system observes a rate-limit-or-forbidden response status from that domain
- **THEN** the next pacing delay for that domain SHALL be longer than it would have been
  without the signal

#### Scenario: Repeated signals grow backoff up to a cap

- **GIVEN** a domain that keeps returning rate-limit-or-forbidden responses
- **WHEN** the system observes successive such signals
- **THEN** the extra backoff for that domain SHALL increase with each signal
- **AND** SHALL NOT exceed the fixed cap

#### Scenario: Backoff recovers when signals stop

- **GIVEN** a domain whose extra backoff has grown from prior signals
- **WHEN** the system subsequently observes non-signal completions from that domain
- **THEN** the extra backoff for that domain SHALL decrease toward zero

### Requirement: Back Off On Target Distress

The system SHALL treat signs of server distress from a domain — a surge of server-error
(5xx) responses or a sustained elevated error rate — as a reason to increase backoff for
that domain, and SHALL surface sustained distress as a stop condition rather than continuing
to probe at full pace. This protects the target from being overwhelmed, consistent with the
project's infrastructure-respect philosophy.

#### Scenario: Server errors increase backoff

- **GIVEN** a domain that begins returning server-error (5xx) responses
- **WHEN** the system observes those responses
- **THEN** the next pacing delay for that domain SHALL be longer than it would have been
  without them

#### Scenario: Sustained distress halts further probing

- **GIVEN** a domain whose error rate remains elevated beyond a configured threshold over a
  window of requests
- **WHEN** the system evaluates whether to continue
- **THEN** it SHALL stop issuing further requests to that domain
- **AND** SHALL report that scanning was halted due to target distress

### Requirement: Configured Minimum Is A Hard Floor

The system SHALL treat the configured minimum delay as an absolute floor that adaptive logic
may never drop below; adaptive logic may only ever increase the delay, never decrease it
below the floor.

#### Scenario: Backoff never reduces below the floor

- **GIVEN** a domain with extra backoff that is currently decaying toward zero
- **WHEN** the system paces a request to that domain
- **THEN** the applied delay SHALL be at least the configured minimum

#### Scenario: Floor holds at maximum backoff

- **GIVEN** a domain whose extra backoff has reached its cap
- **WHEN** the system paces a request to that domain
- **THEN** the applied delay SHALL be at least the configured minimum
- **AND** SHALL be greater than or equal to the delay that would apply with no backoff
