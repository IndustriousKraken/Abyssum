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
