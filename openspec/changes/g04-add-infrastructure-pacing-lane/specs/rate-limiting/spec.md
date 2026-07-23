# rate-limiting

## MODIFIED Requirements

### Requirement: Randomized Per-Request Pacing

Between consecutive requests to the same target domain the system SHALL wait a duration drawn
from the active pacing policy — by default a random duration drawn uniformly between the
configured minimum and maximum delay — so request timing does not form a fixed or predictable
pattern.

#### Scenario: Delay falls within the configured band

- **GIVEN** a configured minimum and maximum delay and the default pacing policy
- **WHEN** the system paces a request to a target domain that has been seen before
- **THEN** the applied delay SHALL be at least the configured minimum
- **AND** the applied delay SHALL be at most the configured maximum plus any active backoff

#### Scenario: Successive delays vary

- **GIVEN** a configured minimum that is strictly less than the configured maximum
- **WHEN** the system paces many requests to the same target domain
- **THEN** the applied delays SHALL NOT all be identical

### Requirement: Configured Minimum Is A Hard Floor

The system SHALL treat the configured minimum delay as an absolute floor for target traffic
that adaptive logic may never drop below; adaptive logic may only ever increase the delay,
never decrease it below the floor.

#### Scenario: Backoff never reduces below the floor

- **GIVEN** a target domain with extra backoff that is currently decaying toward zero
- **WHEN** the system paces a request to that domain
- **THEN** the applied delay SHALL be at least the configured minimum

#### Scenario: Floor holds at maximum backoff

- **GIVEN** a target domain whose extra backoff has reached its cap
- **WHEN** the system paces a request to that domain
- **THEN** the applied delay SHALL be at least the configured minimum
- **AND** SHALL be greater than or equal to the delay that would apply with no backoff

## ADDED Requirements

### Requirement: Support-Infrastructure Lookups Use A Separate Faster Lane
The system SHALL classify each outbound request by the endpoint it is sent to. A request sent
to the target or to a host derived from it is target traffic. A request sent to a third-party
service the operator queries in order to discover or map the target — a public DNS resolver, a
certificate-transparency aggregator, or a registration-data service — is a
support-infrastructure lookup, even when the information it asks for concerns a target host
(for example, a DNS-over-HTTPS query to a public resolver asking whether a candidate subdomain
exists). Support-infrastructure lookups SHALL be paced by a separate, configurable policy that
is faster than the target pacing floor and SHALL NOT be held to that floor, and the
target-distress stop condition SHALL NOT by itself halt them. Such lookups SHALL still back off
in response to an explicit rate-limit signal from the support service.

#### Scenario: A resolver lookup is not paced at the target floor
- **GIVEN** a scan that resolves many candidate names through a public DNS resolver
- **WHEN** the system paces those resolver lookups
- **THEN** they SHALL be paced by the support-infrastructure policy
- **AND** SHALL NOT be held to the target pacing floor

#### Scenario: Requests sent directly to target hosts remain on the target policy
- **GIVEN** a scan that sends requests directly to the target or to hosts discovered for it
- **WHEN** the system paces those requests
- **THEN** they SHALL be paced as target traffic, subject to the target pacing floor

#### Scenario: A throttling support service is still respected
- **GIVEN** a support service that returns a rate-limit signal
- **WHEN** the system continues issuing lookups to it
- **THEN** it SHALL back off in response to that signal

#### Scenario: Target distress does not halt support lookups
- **GIVEN** a target domain under distress that has halted target probing
- **WHEN** support-infrastructure lookups are still required
- **THEN** the distress halt SHALL NOT by itself stop those lookups
