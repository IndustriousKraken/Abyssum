# Tasks

## 1. Storage schema
- [ ] 1.1 Add a forward migration creating a `notes` table (id, `session_id` → sessions.session_id, optional `finding_id` → findings.finding_id, content, author, created_at, edited_at)
- [ ] 1.2 Add a forward migration creating a `tags` table (id, normalized unique name, hex color, optional description)
- [ ] 1.3 Add a `session_tags` join table (session id, tag id) for the many-to-many application
- [ ] 1.4 Wire deletion cascades: deleting a session removes its notes and tag-applications; deleting a finding removes its notes; shared tags are never deleted by these cascades

## 2. Notes
- [ ] 2.1 Implement `add_note` for a session and for a finding within a session, trimming content and rejecting empty/whitespace-only content
- [ ] 2.2 Stamp author and creation time on add
- [ ] 2.3 Implement `edit_note` updating content (same emptiness validation) and stamping an edited time
- [ ] 2.4 Implement `delete_note`
- [ ] 2.5 Implement listing a session's notes and a finding's notes, newest-first

## 3. Tags
- [ ] 3.1 Implement `create_tag` with name normalization (trim + case-fold), uniqueness check, and hex-color (`#RRGGBB`) validation
- [ ] 3.2 Implement `apply_tags` to a session, auto-creating any tag whose normalized name does not yet exist, and ignoring tags already applied
- [ ] 3.3 Implement `remove_tag` from a session
- [ ] 3.4 Implement `list_tags` returning each tag with the count of sessions it is applied to
- [ ] 3.5 Implement listing the tags applied to a given session

## 4. Search and filter
- [ ] 4.1 Implement `search_sessions_by_note` doing a substring match over note content, scoped to the requester
- [ ] 4.2 Implement `filter_sessions_by_tags` supporting match-all and match-any semantics, scoped to the requester
- [ ] 4.3 Honor `admin` scope so an admin search/filter spans all owners

## 5. Authorization
- [ ] 5.1 Gate every note and tag-application operation on session ownership: owner or `admin` may read/write, others are denied
- [ ] 5.2 Reject note operations that reference a non-existent session, or a finding not belonging to the named session

## 6. Web surface
- [ ] 6.1 Add authenticated routes to add/edit/delete a note on a session and on a finding, returning an updated notes fragment
- [ ] 6.2 Add authenticated routes to create a tag, apply/remove tags on a session, and list all tags, returning tag-chip fragments
- [ ] 6.3 Add authenticated search/filter routes (by note text, by tags with all/any) returning a session-list fragment scoped to the viewer

## 7. Tests (local only — no real targets)
- [ ] 7.1 Unit-test note validation (empty/whitespace rejected) and tag validation (bad hex color rejected, duplicate name rejected, name normalization collapses case/whitespace)
- [ ] 7.2 Integration-test add/edit/delete of a session note and a finding note against a local store
- [ ] 7.3 Integration-test apply/remove tags, apply-by-unknown-name auto-create, and that re-applying an existing tag does not duplicate
- [ ] 7.4 Test that `list_tags` usage counts are correct and that deleting a session removes its notes and tag-applications while leaving shared tags intact
- [ ] 7.5 Test note substring search and tag match-all vs match-any filtering
- [ ] 7.6 Test ownership: a non-owner non-admin is denied; an `admin` can read/write and search across owners
