# Future Capabilities — Preserved Intent (NOT v1)

These are **out of scope for v1** (see Non-Goals in `project.md`) but their *intent* is
captured here so a future OpenSpec change can be written faithfully rather than reinvented.
This file is intent only — when one of these is built, its behavior contract goes into
`openspec/specs/` as a normal change. Nothing here is a commitment or a v1 requirement.

## Observing Proxy (the differentiator)

A lightweight proxy that **observes and filters** API traffic — deliberately **not** an
intercepting proxy like Burp Suite or ZAP. This is a defining difference from default tooling
in the space, in the same spirit as the stealth posture: stay out of the way.

**Design ideals:**
- **Non-blocking.** Traffic flows through uninterrupted; the operator's browsing/testing is
  never paused on a breakpoint. Requests/responses are captured *asynchronously* and the
  response is returned immediately.
- **Observable.** Every request/response is captured and indexed for search (by endpoint,
  parameter, header, status, time).
- **Filterable.** Smart filters surface the interesting traffic automatically — auth
  tokens/cookies, notable parameters (IDOR/pagination candidates), API endpoints, error
  responses, and vulnerability hints — with an interest/priority score.
- **Exportable.** Clean export (HAR, OpenAPI, Postman, raw) and an API so external tools and
  AI agents can consume the captured traffic, including replaying a captured request with
  modifications.
- **Lightweight.** Minimal performance impact; passive by default.

**How it feeds Abyssum:** observed traffic yields real targets and parameters → hand them to
the scanner; surface IDOR/param candidates for follow-up; replay-with-mutation hooks for
external tooling. Stored in its own SQLite traffic store with a real-time filtering view.

**Why deferred:** v1 is the scanner core; the proxy is a separable module that connects to
Abyssum rather than living inside it (infrastructure-agnostic, loose coupling).

## Deep Surface Mapping

Finding the infrastructure people forgot they exposed — squarely on-thesis ("the hidden
things, the deeper infrastructure"):

- **Subdomain takeover** — dangling DNS pointing at unclaimed cloud resources.
- **Origin-IP discovery** — the real host behind a CDN/WAF (Cloudflare et al.), so testing can
  reach the origin the perimeter was meant to hide.
- **ASN / netblock enumeration** — expand from an org to all the netblocks and assets it
  actually owns. (Scope line: asset *enumeration* is in bounds; anything touching BGP route
  *manipulation* is explicitly out — illegal and off-thesis.)
- **Forgotten cloud assets** — exposed buckets, stale endpoints, abandoned services.

## Recon Phone-Home Box & Two-Phase Engagements

A drop-in box that runs Abyssum against a network/perimeter, encrypts its findings, and
**ships them home** over a sync channel. This is **recon only — not C2** (no inbound tasking,
no post-exploitation); it stays firmly on the observation side of the line, and is the natural
next surface once the external scanner is stable. It is **useful standalone** — a network
assessment doesn't need to prove RCE to be valuable.

It enables a **two-phase engagement model**: Phase 1 — the box maps the environment and warns
the client where they're soft, giving them a remediation window to fix the obvious things;
Phase 2 — a later, deeper pass attempts to gain privileges in the network. Sequencing
recon-and-remediate *before* exploitation is more honest and more useful than the usual
single-shot test, and packaging it as distinct phases is uncommon.

## Internal / Red-Team Surface & C2 Interop

The patient, low-and-slow, evade-the-behavioral-defender posture transfers naturally to
internal red-team work (where good long engagements already run this way). Decisions recorded:

- **v1 does not touch C2.** Instead, design a clean **export / handoff seam**: Abyssum produces
  the surface map, candidate footholds, and harvested intel in a *consumable* form. That data
  boundary is the entire C2 interface needed for now, and it costs almost nothing to build.
- **Integrate, don't reinvent.** Do not build a C2 *framework* — the ecosystem (e.g. Mythic,
  Sliver) already does tasking, payloads, post-ex, and operator UX well. The one part worth
  building is Abyssum's **differentiator**: a *patient, low-and-slow transport / C2 profile*
  plus the recon-correlation brain, contributed as a **pluggable agent / profile** to an
  existing framework (Mythic is the natural host; Sliver the fallback). Build only the
  patience; borrow the plumbing.
- **Separate repo, shared core.** The offensive / implant pieces live in their own
  (private / invite-only, at least initially) repository that depends on a shared,
  surface-agnostic `abyssum-core` library. The clean, defensible, open-sourceable scanner stays
  in the public `abyssum` repo; the abusable surfaces stay behind their own door with their own
  licensing and access control — without writing the engine twice.

## Embedded / OT / RF Surfaces

Linux-first host assessment, vulnerable-firmware discovery, and weird-protocol pivot chains
(the thermometer → Zigbee → somewhere-unexpected path). Under-tooled relative to the
IT/Windows/web-centric mainstream, and the *purest* expression of "finds the occult." In the
taxonomy these are **new surface adapters** — they extend the engine, they don't fragment it.

## Other deferred capabilities (intent in brief)

- **IP rotation / egress** — infrastructure-agnostic rotating egress (VPS / residential /
  VPN), a separate module Abyssum connects to; helps avoid CDN/WAF correlation. Not tied to
  any one cloud.
- **Distributed testing / personas** — coordinate multiple scanning identities and timing
  profiles (human-browsing, crawler, mobile) across instances; an evolution of the stealth
  posture, not a v1 concern.
- **Inbound AI-agent API** — expose Abyssum's own API so external AI agents can *drive* it via
  tool calls. (v1 AI is **outbound only**: Abyssum calls an OpenAI-compatible API to analyze
  findings. See `ai-assist`.)
- **Webhooks & bulk external API operations** — batch operations and event callbacks.
- **User-uploaded custom wordlists** — v1 ships curated wordlists seeded into the DB
  (`seed-data`); user-supplied lists are a later extension.
- **Advanced monitoring dashboard & health-check endpoint** — disk/DB/scanner-availability
  health and richer real-time metrics.
- **Session export/import & merging** — collaboration/portability of scan sessions.
