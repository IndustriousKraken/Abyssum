---
title: Collaboration on engagements (invite operators to a shared engagement)
status: proposed
added: 2026-07-23
---

Engagements ship owner-scoped: the operator who creates an engagement is its only authorized
user, and scans/documents within it are per-operator. That is the right default, but teams
running a shared client engagement will want more than one person working under it.

The foundation is laid so this is additive, not a redesign (see change `h01-add-engagements`):

- Every engagement-scoped item — the scan association and each document — already records **who
  added it and when**. Attribution never needs backfilling.
- Access is already expressed as **"the engagement's authorized operators,"** a set recorded per
  engagement that today contains exactly the creator. Widening that set is the whole feature.

Worth deciding when we build it:
- **Invite / membership model** — how an owner adds another operator to the authorized set, and
  whether there are roles (e.g. viewer vs. editor vs. owner).
- **What a member may do** — see all scans/documents, add their own, start scans under the
  engagement, edit or remove others' items?
- **Removal** — what happens to items added by an operator who is later removed from the
  engagement (retain with attribution vs. restrict).

Deliberately deferred until per-engagement work is in real use, so the collaboration model
follows observed need rather than guesswork. Related: `roadmap/wordlist-sharing.md` raises the
same snapshot-vs-live and who-may-share questions for shared reference data.
