# Tasks

- [ ] Generalize the pacing draw so a request's delay comes from the active pacing policy
      (uniform-by-default preserved) — the shared MODIFY of `Randomized Per-Request Pacing`,
      identical to the one in `g04-add-infrastructure-pacing-lane`.
- [ ] Define a timing-profile model: a name plus a delay distribution (window + shape),
      including an organic (heavy-tailed, occasional-long-pause) shape and a conservative
      default.
- [ ] Seed the built-in library (~5 profiles across fast↔cautious, including organic) per user.
- [ ] Persist profiles owned by a user; a user's profiles are visible/selectable only to them,
      and reusable across their scans; allow a user to add/adjust their own.
- [ ] Thread a per-scan profile selection from scan start through to the rate limiter, so the
      scan's target-facing pacing uses the selected profile; default to the conservative
      profile when none is selected.
- [ ] Add a profile selector to the web scan form, and a management surface for a user's
      profiles.
- [ ] Keep adaptive backoff and the distress halt in force regardless of the selected profile.
- [ ] Test: the organic profile yields non-uniform, non-periodic gaps with occasional long
      pauses; selecting a profile changes a scan's target pacing; distress halt still fires
      under any profile; one user cannot see another's profiles.
