---
title: Internal / red-team surface & C2 interop
status: deferred
added: 2026-07-16
---

The patient, low-and-slow, evade-the-behavioral-defender posture transfers naturally
to internal red-team work. Decisions recorded:
- **v1 does not touch C2.** Design a clean export/handoff seam instead: Abyssum
  produces the surface map, candidate footholds, and harvested intel in consumable
  form. That data boundary is the entire C2 interface needed for now.
- **Integrate, don't reinvent.** Do not build a C2 framework — Mythic/Sliver already
  do tasking, payloads, post-ex, operator UX. Build only Abyssum's differentiator (a
  patient low-and-slow transport/C2 profile + recon-correlation brain) as a pluggable
  agent/profile for an existing framework (Mythic natural host, Sliver fallback).
- **Separate repo, shared core.** Offensive/implant pieces live in their own
  private repo depending on a surface-agnostic `abyssum-core`; the open-sourceable
  scanner stays public. Abusable surfaces stay behind their own door — without writing
  the engine twice.
