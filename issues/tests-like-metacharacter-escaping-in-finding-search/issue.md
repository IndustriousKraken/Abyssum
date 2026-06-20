# tests-like-metacharacter-escaping-in-finding-search

## Coverage gap

`DatabaseManager::search_findings` implements the free-text query as a SQL
`LIKE` over title and description, wrapping the user's query in `%...%` and
running every character through `escape_like` with an `ESCAPE '\'` clause so that
the SQL wildcard characters `%`, `_`, and the escape character `\` are matched
**literally** rather than as wildcards
(`abyssum-core/src/persistence/db.rs:284-292` build the clause;
`escape_like` at `abyssum-core/src/persistence/db.rs:477`).

The escaping branch is untested. The only free-text test,
`filter_by_free_text_is_case_insensitive`
(`abyssum-core/tests/persistence.rs:449`), queries the plain word `"cors"`, which
contains no metacharacters — so `escape_like` runs but its effect is never
asserted, and the `ESCAPE` clause is never distinguished from a no-op. If the
escaping regressed (or were removed), a query containing `%` would behave as a
"match everything" wildcard and a query containing `_` would match any single
character, silently returning rows that do not contain the queried text. This is
a behavioral consequence with no current test.

## Source location

- `abyssum-core/src/persistence/db.rs` — `search_findings` free-text branch
  (284-292), `escape_like` (477-486).
- Tests land in `abyssum-core/tests/persistence.rs`.

## Acceptance criteria (against the existing specification)

This asserts already-implemented behavior; it introduces **no** new or changed
contract. `escape_like` and the `ESCAPE '\'` clause already make the free-text
query a literal substring match — these tests pin that.

Grounded in `openspec/specs/result-persistence/spec.md`, **Requirement: Filter
Findings**, scenario **Filter by free-text query**:

> - **GIVEN** stored findings whose titles and descriptions contain differing text
> - **WHEN** findings are queried with a free-text query
> - **THEN** only findings whose title or description matches the query SHALL be returned

"matches the query" means a literal substring of the title or description. A
query string containing `%`, `_`, or `\` SHALL therefore match only findings
whose title or description actually contains those characters in sequence — never
all findings, and never findings that merely fit a wildcard pattern.

Acceptance: with a seeded fixture mixing findings that do and do not contain the
metacharacters literally, a query containing a `%` / `_` / `\` returns exactly
the findings whose title or description contains that literal text.
