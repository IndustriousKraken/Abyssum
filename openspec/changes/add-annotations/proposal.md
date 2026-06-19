## Why

Bug bounty work is a long, iterative grind: an operator runs many scans against many
targets over days, then has to remember why a session mattered, what they already triaged,
and which findings are worth writing up. Abyssum needs a lightweight annotation layer so an
operator can record context on a scan session or a finding (freeform notes), categorize
sessions with reusable color-coded tags, and later find that work again by searching note
text or filtering by tag.

This mirrors the v1 "scan notes + color tags" feature (Phase 5) but re-expressed as
language-agnostic behavior and made multi-user aware: annotations live under the same
ownership and `admin` visibility rules as the scan sessions and findings they decorate
(see `project.md` and `add-web-interface`). It depends on result persistence
(`add-result-persistence`) for durable storage and on the web interface
(`add-web-interface`) for the authenticated surface that owns sessions and findings.

## What Changes

### 1. Freeform notes on sessions and findings

An operator can attach one or more freeform notes to a scan session, and to an individual
finding within a session. Each note records its author and creation time. Notes can be
edited and deleted. Empty/whitespace-only note content is rejected. Notes are owned with
their session: only the session's owner (or an `admin`) may read, add, edit, or delete its
notes.

### 2. Color-coded tags applied to sessions

An operator can create reusable tags, each with a unique name, a hex color, and an optional
description. Tags are applied to scan sessions (many tags per session, many sessions per
tag) and can be removed from a session. Applying a tag by a name that does not yet exist
creates it. Tag names are normalized so the same name is never duplicated, and an invalid
color is rejected. The system can list all tags with how many sessions each is applied to.

### 3. Search and filter by note content and by tag

An operator can search their sessions by note text (substring match) and filter their
sessions by one or more tags, choosing whether a session must carry all of the named tags
or any of them. Results are scoped to the requester's own sessions, with an `admin` able to
search across all sessions.

## Impact

- Adds the `annotations` capability to `openspec/specs/`.
- Extends the persisted model (notes, tags, session↔tag and finding↔note associations) on
  top of `add-result-persistence`, and adds annotation surfaces to `add-web-interface`.
- No change to scanning behavior; this is metadata layered over existing sessions/findings.
