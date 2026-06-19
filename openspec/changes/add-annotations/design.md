# Design: Annotations (Notes + Color Tags)

## Technical Approach

Annotations are persisted metadata layered over the existing `sessions` and `findings`
tables from `add-result-persistence`. The annotation logic lives in `abyssum-core`
(alongside persistence and auth) so both surfaces can reuse it; the web routes in
`abyssum-web` are thin handlers that render HTMX fragments. No scanner code is touched.

```
notes        — freeform text, author, created_at, edited_at; FK to session, optional FK to finding
tags         — unique normalized name, hex color, optional description
session_tags — many-to-many join between sessions and tags
```

A note belongs to exactly one session; it may additionally reference one finding within
that session (a finding-level note) or none (a session-level note). Tags attach only to
sessions (matching v1; finding-level tagging is not in scope).

## Library / Storage Choices

- **Storage:** `sqlx` against the same SQLite database `add-result-persistence` owns; the
  new tables are added via a forward migration so existing data is preserved.
- **Web:** `axum` handlers returning server-rendered HTMX fragments (notes list, tag chips,
  search results), consistent with `add-web-interface`. No new frontend stack.
- **Cascade:** deleting a session deletes its notes and its `session_tags` rows but never
  the shared `tags` themselves; deleting a finding deletes only that finding's notes.

## Key Decisions

### Decision: Ownership follows the parent session
Notes and tag-applications inherit the owner of the session they decorate. Authorization is
the same gate `add-web-interface` already applies: the owner or an `admin` may read/write;
anyone else is denied. The annotation layer never widens visibility beyond what the
underlying session allows.

### Decision: Tags are global objects, applications are per-session
A `tag` (name + color + description) is shared across the instance; what is owned is the
*application* of a tag to a session. This lets two operators reuse the same `auth-bypass`
tag while each only seeing their own tagged sessions. Tag names are normalized (trimmed,
case-folded) so `Auth-Bypass` and `auth-bypass` are the same tag and never duplicate.

### Decision: Apply-by-name auto-creates
Applying a tag whose normalized name does not exist creates the tag (with a default color)
and then applies it, so an operator can tag fluidly without a separate create step — while
an explicit create path still exists to set a specific color/description up front.

### Decision: Edit is added on top of v1
v1 supported add + delete for notes; this change adds edit (update content, stamp
`edited_at`) per the capability brief, keeping the same emptiness validation as add.

## Validation Rules (informs the spec, kept testable)

| Input | Rule |
|-------|------|
| Note content | non-empty after trimming whitespace, else rejected |
| Tag name | non-empty after trim; normalized (trim + lowercase); unique |
| Tag color | must be a 7-character hex string of the form `#RRGGBB`, else rejected |
| Note target | must reference an existing session (and, for a finding-note, a finding in that session) |

## Testing

- Unit tests for validation: empty note rejected; bad hex color rejected; duplicate tag
  name rejected on explicit create; name normalization collapses case/whitespace.
- Integration tests against the persistence layer: add/edit/delete a session note and a
  finding note; apply/remove tags; apply-by-unknown-name auto-creates; list tags reports
  correct usage counts; deleting a session removes its notes and tag-applications but leaves
  shared tags intact.
- Search tests: substring note search returns matching sessions; tag filter with match-all
  vs match-any returns the right sessions; results are scoped to the owner and an `admin`
  sees across owners.
- **No network, no real targets** — all tests run against a local store and fixtures.
