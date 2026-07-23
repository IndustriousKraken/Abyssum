# Engagements: organize scans under a recorded authorization

## Why

Abyssum's whole premise is *authorized* testing, but today the authorization lives outside the
tool — in someone's inbox or a signed PDF on a laptop. Scans are a flat per-operator list with
nothing tying them to the job they belong to or the scope that permits them. Operators running
several bug-bounty programs or client engagements at once have no way to group a job's scans,
and no place to keep the scope and proof of authorization next to the work it governs.

This change adds **engagements**: a named grouping an operator creates, under which scans are
organized and the job's scope and authorization documents are kept for easy reference. It makes
the tool's defining claim — that testing was authorized — auditable inside the tool.

## What Changes

- An operator can create an **engagement** with a name; it records its creator and creation time.
- A scan can be **associated with an engagement** — chosen when the scan is started, or assigned
  afterward. A scan belongs to at most one engagement; a scan with none behaves exactly as today.
- An engagement can hold one or more **scope / authorization documents**, each supplied as
  **pasted text** (bug-bounty scopes are usually plain text), an **external URL** (program or
  contract scope pages), or an **uploaded file** (a signed authorization for a custom job).
- Documents are shown for reference: pasted text inline, a URL as a link, and an uploaded **PDF
  rendered inline using the browser's native viewer** — no client-side PDF library, no external
  code.
- Operator-supplied documents are untrusted content, so they are served safely: a fixed document
  content type, sniffing disabled, never served as active content in the app's origin, and bounded
  in type and size.
- Engagements follow the same **per-user visibility** as sessions (an operator sees their own;
  admin sees all).

## Non-goals

- **The stored scope does not constrain scanning.** It is operator reference material only; the
  system never reads it to decide what a scan targets or how a scanner behaves. Machine-enforced
  scope is a separate, harder problem (fuzzy parsing → false confidence) and is deliberately out.
- **No collaboration machinery is built here.** Invites, membership, and roles are deferred (see
  `roadmap/engagement-collaboration.md`). This change only leaves the seam: each item records who
  added it, and access is expressed as "the engagement's authorized operators" — a set that today
  contains exactly the creator, so widening it later is additive, not a redesign.

## Note

This is additive. The `engagements` capability is new; the `web-ui` delta adds new pages and does
not modify existing requirements. Associating a scan with an engagement is an optional new input
and does not change the existing `Start A Scan From The Web` contract. Nothing here touches
`ScanContext::send`, the pacing floor, or User-Agent rotation.
