---
title: Recon phone-home box & two-phase engagements
status: deferred
added: 2026-07-16
---

A drop-in box that runs Abyssum against a network/perimeter, encrypts findings, and
ships them home over a sync channel. **Recon only — not C2** (no inbound tasking, no
post-exploitation); stays on the observation side of the line. Useful standalone — a
network assessment need not prove RCE to be valuable.

Enables a two-phase engagement model: Phase 1 maps the environment and warns the
client where they're soft (remediation window); Phase 2 is a later, deeper
privilege-gaining pass. Recon-and-remediate before exploitation is more honest and
more useful than the usual single-shot test.
