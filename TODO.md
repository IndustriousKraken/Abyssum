# Abyssum — Idea Backlog

Raw capture for ideas that aren't ready to spec. Low ceremony — dump things here freely.

## The funnel (where ideas go)

1. **`TODO.md` (here)** — raw ideas, no structure required.
2. **`openspec/future-capabilities.md`** — once an idea has a thesis-fit rationale and a rough
   shape (intent captured, not yet buildable).
3. **`openspec/changes/<name>/`** — only when spec'd and buildable. Do **not** put raw ideas
   here; the build pipeline (octopus-autocoder) treats everything under `changes/` as work to
   build.

## Fit filter

Abyssum is a *patient, stealthy, persistent engine*. Every idea should be one of three kinds —
if it's none of these, it's probably not Abyssum:

- **Surface** — a new environment to point the engine at (external API ✓ v1; internal network;
  cloud; embedded/OT/RF; …).
- **Detection / correlation** — something new we infer from collected data.
- **Evasion / transport** — how we stay quiet and move data.

And it must serve the thesis: **slow, deep, thorough, stealthy, finds the occult.** If it's
"fast and loud," it belongs in Nuclei, not here.

## Backlog

### Detections / correlation
- [ ] Cross-endpoint / stateful reasoning — bugs that only appear across a multi-step flow.
- [ ] Auth-differential testing — run the same surface as anon / user-A / user-B / admin and
      diff the responses (where real access-control bugs hide).
- [ ] Change-detection / diffing for unattended runs — "what changed since last run," so a
      week-long run surfaces deltas, not 10,000 findings.
- [ ] Signal-vs-noise ranking — ruthless prioritization; low false-positive output is
      existential for unattended use.
- [ ] AI-assisted correlation — connect findings with the analysis model (analysis only, never
      action; keyless/self-hosted to avoid refusals on authorized work).

### Surfaces
- [ ] Deep surface mapping — subdomain takeover, origin-IP discovery behind CDN/WAF,
      ASN/netblock enumeration, forgotten cloud assets. (ASN enum yes; BGP route manipulation
      no.) → intent in `future-capabilities.md`.
- [ ] Recon phone-home box — standalone; powers the two-phase warn-then-breach engagement
      model. → intent captured.
- [ ] Internal / red-team surface — separate private repo; integrate with Mythic/Sliver rather
      than building a C2 framework. → intent captured.
- [ ] Embedded / OT / RF — Linux-first hosts, vulnerable firmware, weird-protocol pivot chains.

### Evasion / transport
- [ ] Advanced detector evasion (behavioral WAF, AI-driven NDR) — claims only ever as specific,
      reproducible case reports, never blanket assertions.
- [ ] Origin-bypass transport — reach the origin directly once it's discovered.
- [ ] IP rotation / egress diversity → intent in `future-capabilities.md`.

> Promote an item to `future-capabilities.md` once its intent is clear; promote to a change
> folder only when it's ready to build.
