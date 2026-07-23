# Design notes

## Capability placement

The domain — what an engagement is, that it holds documents, that it persists, and who added
each item — lives in a new `engagements` capability. The *surface* concerns — the pages, safe
serving/rendering, and per-user visibility enforcement — live in the `web-ui` delta. This mirrors
the existing split: `result-persistence` owns that a session records an owner (data, ownership-
blind), while `web-ui` owns who may see it (policy). Engagement storage rides the existing
`Schema Initialization And Migration` requirement — a new table is a forward migration, not a new
persistence contract.

## Reference-only, by requirement

The scope/authorization content is never interpreted. This is a first-class requirement
(`A Stored Scope Is Operator Reference Only`), not just a proposal note, because "we already store
the scope" is exactly the kind of thing that later creeps into "so the scanner should read it."
Machine-enforced scope from freeform bug-bounty text is unreliable and would give false confidence
about what is in bounds; keeping it out is a safety choice, not a laziness one.

## Collaboration seam (built later, designed now)

Per the request, the future collaboration case should be writable without a redesign. Two cheap
decisions make that true, and only these two:

1. **Provenance is recorded from day one.** Every engagement-scoped item — the scan association and
   each document — records which operator added it and when. This is the one thing that is painful
   to retrofit (you cannot backfill who-did-what after the fact), so it is captured now even though
   only one operator can act today.
2. **Access is a set, not a person.** Visibility is expressed as "the engagement's authorized
   operators," recorded per engagement, and today that set is exactly its creator. Inviting others
   later widens the set — a new requirement, not a rewrite of this one.

No invite flow, membership table semantics, or roles are specified here. `roadmap/engagement-
collaboration.md` captures the deferred feature.

## Untrusted-document handling

Attached files are operator-supplied and rendered back to (eventually other) operators, so they
are treated as untrusted:

- Served with a fixed document content type and `X-Content-Type-Options: nosniff`; never served as
  `text/html` or otherwise as active content in the app's origin (that would be stored XSS).
- A PDF is displayed via the browser's **native** viewer (an inline embed of the stored bytes) —
  no PDF.js or other client library, consistent with the project's self-contained, no-external-code
  posture. "Render inline" is therefore a zero-dependency requirement, not a bundle.
- Bounded type allowlist and size cap at upload; over-limit is rejected, not truncated.

## Multiple documents per engagement

An engagement holds a *set* of documents rather than a single scope field. A custom job commonly
needs both a scope (pasted or linked) and a separate signed authorization (uploaded), and different
operators may add different documents once collaboration exists. A set costs almost nothing more to
specify and avoids an immediate "oops, we need two" retrofit.
