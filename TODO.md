# Abyssum — Idea Backlog

Raw capture for ideas that aren't ready to spec. Low ceremony — dump things here freely.

## The funnel (where ideas go)

1. **`TODO.md` (here)** — raw ideas, no structure required.
2. **`roadmap/<slug>.md`** — once an idea has a thesis-fit rationale and a rough shape
   (status-tracked intent, not yet buildable). Format in `OCTOPUS.md`.
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
- [ ] AI-assisted correlation — connect findings with the analysis model (analysis only, never
      action; keyless/self-hosted to avoid refusals on authorized work).

> Graduated to `openspec/changes/`: auth-differential testing, signal-vs-noise ranking,
> change-detection/run diffing.

### Surfaces
- [ ] Deep surface mapping — subdomain takeover, origin-IP discovery behind CDN/WAF,
      ASN/netblock enumeration, forgotten cloud assets. (ASN enum yes; BGP route manipulation
      no.) → in `roadmap/deep-surface-mapping.md`.
- [ ] Recon phone-home box — standalone; powers the two-phase warn-then-breach engagement
      model. → intent captured.
- [ ] Internal / red-team surface — separate private repo; integrate with Mythic/Sliver rather
      than building a C2 framework. → intent captured.
- [ ] Embedded / OT / RF — Linux-first hosts, vulnerable firmware, weird-protocol pivot chains.

### Evasion / transport
- [ ] Advanced detector evasion (behavioral WAF, AI-driven NDR) — claims only ever as specific,
      reproducible case reports, never blanket assertions.
- [ ] Origin-bypass transport — reach the origin directly once it's discovered.
- [ ] IP rotation / egress diversity → in `roadmap/ip-rotation-egress.md`.

> Promote an item to `roadmap/` once its intent is clear; promote to a change
> folder only when it's ready to build.
