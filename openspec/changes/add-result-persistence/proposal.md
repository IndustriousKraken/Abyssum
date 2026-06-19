## Why

A scan is worthless if its findings vanish when the process exits. Bug bounty work is
iterative — operators re-run scans over days, compare a target's findings across time, and
pull up past evidence when writing a report. The engine therefore needs durable storage for
scan sessions and the findings they produce, plus a way to query and filter that history.

This change adds the `result-persistence` capability: it defines how scan sessions and their
findings are stored so they survive a restart, and how stored sessions and findings are
queried and filtered. It depends only on the bootstrap workspace (config, error model) and
is a sibling of orchestration — orchestration produces sessions and findings; persistence
keeps them.

Ownership and visibility are deliberately **out of scope** here: the `authentication` change
(#13) owns which user can see which session. This capability stores and queries scans and
findings without any notion of who owns them.

## What Changes

### 1. Durable storage of scan sessions

Persist each scan session with its identity, status, the targets and scanner ids it covers,
its timing, and request/error counts. A session written before a restart is readable
unchanged after the process restarts.

### 2. Durable storage of findings

Persist each finding under its session, retaining its scanner id, target, status /
classification, severity, and evidence. A finding survives a restart with those fields
intact.

### 3. Query and filter sessions and findings

Retrieve a single session with its findings, list sessions newest-first with paging, and
filter findings by status, scanner id, target, free-text, and a date range. Deleting a
session removes its findings atomically.

### 4. Schema initialization and migration

Create the storage schema on first use and apply forward migrations on later startups so an
existing store is upgraded in place rather than discarded.

## Impact

- Adds the `result-persistence` capability to `openspec/specs/`.
- Unblocks the CLI (#12), web (#14), annotations (#15), reports (#16), and AI-assist (#17),
  all of which read or write persisted findings.
- No user-facing scanning behavior yet; this is the storage substrate.
