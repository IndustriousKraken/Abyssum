---
title: Sharing custom wordlists between users
status: proposed
added: 2026-07-23
---

Custom wordlists are per-user: each operator imports and edits their own, and one person's
additions never change another's scan results. That is the right default for a multi-user
tool, but it means a team re-imports the same list several times.

Worth considering later: a way to share a list with other users on the instance — publishing
a list as instance-wide reference data, copying another user's list into your own, or an
admin-curated set that sits alongside the seeded lists. Any of these needs an answer for what
happens when the source list changes afterwards (snapshot vs. live reference), and for who
may publish.

Deliberately out of scope until per-user lists exist and are in real use — the sharing model
should follow observed need rather than guesswork.
