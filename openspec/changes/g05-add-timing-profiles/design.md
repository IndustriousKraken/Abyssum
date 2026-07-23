# Design

## The ~5-profile library

A small, opinionated set spanning the finish-fast ↔ stay-invisible axis. Indicative:

- **Fast** — small delay, higher concurrency; for authorized/lab targets where speed wins.
- **Steady** — today's uniform 1–3s window; the conservative default.
- **Cautious** — wider, slower window.
- **Organic** — irregular, non-periodic gaps (see below); the thesis profile.
- **Paranoid** — long organic gaps with heavy tails; for the most sensitive engagements.

Exact names/parameters are guidance, not contract; the spec pins the *shape* (a spectrum, an
organic model, a conservative default).

## The organic model

Draw inter-request gaps from a heavy-tailed distribution (e.g. exponential / log-normal)
rather than a uniform band, occasionally injecting a much longer pause. The result has no
constant rate and no fixed period, so it evades both cadence detection and simple
volume-per-window thresholds — the "looks like a person browsing" shape. It is a pacing
*policy* in the sense `g04-add-infrastructure-pacing-lane` establishes: the selected profile
supplies the policy the rate limiter draws from for target traffic.

## Storage, ownership, selection

Profiles are rows owned by a user (like scan sessions and custom wordlists), seeded per user
from the built-in library and editable by that user, never visible to another. The scan
form gains a profile selector; the choice rides on the scan as a per-scan option (the same
per-scan-options plumbing other in-flight work needs) through to the rate limiter. The CLI has
no authenticated user, so it uses the conservative default (a CLI flag to name a built-in
profile is a reasonable later addition, but ownership stays a web concept).

## Safety is not negotiable

A profile parameterizes the delay distribution and floor only. Adaptive backoff on rate-limit
signals and the target-distress stop condition are independent of the profile and always
apply, so no profile — not even Fast — can turn the scanner into something that hammers a
target through distress signals.
