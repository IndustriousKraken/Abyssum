---
title: Report authoring — templates + AI writing assist
status: proposed
added: 2026-07-23
---

Findings live in Abyssum; the report that goes to the client is written somewhere else — a Word
or Excel doc where findings get pasted and rewritten by hand. The gap between "the tool found it"
and "the client-ready writeup" is where a lot of a tester's manual time goes, especially for
API/webapp work delivered to institutions that expect a polished report.

The future feature: collect and prioritize an engagement's findings and emit a report that needs
much less manual editing.

- **Templates** — report shapes beyond the fixed Markdown / JSON / CSV / HackerOne formats that
  `report-generation` produces today. The engagement (`h01-add-engagements`) is the natural unit a
  client report covers, and `h02`'s per-engagement results rollup is the raw material.
- **AI writing assist** — extend `ai-assist` (today: on-demand per-finding analysis) to drafting
  report prose — summary, impact, steps to reproduce, remediation — from the structured findings.
  It stays outbound-only and best-effort/non-fatal, as that capability already requires.
- **Prioritization** — lean on `finding-ranking` (dedup + rank by importance) so a report leads
  with what matters and does not repeat the same issue.
- **Template customization + a reusable snippet library** — testers see the same vulns repeatedly
  and each has their own, often unwritten, way of presenting mitigation for a given class. Let an
  operator save and reuse their own templates and per-vulnerability remediation snippets — personal
  tradecraft, stored and applied so it is not retyped every report.

This is per-operator, like custom wordlists. Sharing templates/snippets across a team raises the
same snapshot-vs-live and who-may-publish questions as `wordlist-sharing.md` and
`engagement-collaboration.md`, so it waits on the same collaboration model.

Deliberately deferred: large surface, and the template/snippet model should follow how real
reports are actually written rather than guesswork. Builds on `engagements` (the report unit),
`report-generation` (formats and severity ordering), `ai-assist` (drafting), and `finding-ranking`
(prioritization).
