# Reusable timing profiles, including an organic (irregular) model

## Why

Pacing today is a single uniform delay window (1–3s), configured globally. That defeats a
fixed cadence but still reads as machine traffic: a constant rate inside a narrow band, which
simple log-based detection catches on volume-per-window even when the period varies. The
project's thesis is patient, low-and-slow, evade-the-behavioral-defender scanning — so how the
target-facing traffic is *shaped* deserves to be a first-class, reusable choice, not a pair of
numbers edited per run.

## What Changes

- Add a built-in **library of timing profiles** spanning fast to highly cautious, including an
  **organic** profile whose inter-request gaps imitate irregular human/organic traffic
  (non-uniform, non-periodic, with occasional long pauses) rather than a constant rate.
- Profiles are **per-user and reusable**: each user has their own set, seeded from the
  built-in library and extendable, visible only to them, and **selectable when starting a
  scan** in the web UI.
- A scan runs its target-facing pacing under the selected profile; with none selected, a
  conservative default profile applies.
- Profiles change *timing shape only* — they never disable the protections that keep the
  scanner from overwhelming a target (adaptive backoff and the distress halt stay in force).

## Depends on / shares with `g04-add-infrastructure-pacing-lane`

This change relies on the pacing draw being **policy-driven** rather than always uniform. That
generalization is a MODIFY of `Randomized Per-Request Pacing`, carried **identically** in both
this change and `g04-add-infrastructure-pacing-lane`, so the two are archive-order-independent
(each sets the requirement to the same text). This change adds nothing else to rate-limiting;
its own requirements live in the new `timing-profiles` capability.
