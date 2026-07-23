# Per-user custom wordlists, uploaded through the UI

## Why

The seeded subdomain wordlist is 29 generic words — far too thin for real recon, where an
operator wants to paste or upload a serious list (SecLists-sized). Today wordlists are
read-only seeded reference data with no way to add your own, and the UI exposes nothing. This
adds per-user custom wordlists an operator provides by pasting text or uploading a `.txt` file
in the web UI, selectable per scan.

## What Changes

- An authenticated operator can **provide their own wordlist** — paste text or upload a text
  file — owned by them and visible only to them.
- Imported content is **normalized** (trim, drop blanks and comments, lowercase, dedupe) and
  the import is **reported** ("imported N, dropped M: duplicates/blank/invalid"), not silent.
- A custom wordlist is **selectable per scan**; the scanners that consume a wordlist use the
  selected one, else the seeded default.
- The number of entries a scan uses is **bounded by a configurable limit**, and truncation is
  reported rather than silent — so a 50,000-line paste doesn't quietly become 2,048.

## Depends on

- `g03-add-per-scan-options` — carries the selected wordlist on the scan.
- `g01-enforce-recon-scope-invariant` — the safety precondition. Pasted lists are untrusted; that
  change makes candidate names valid DNS labels and confines every probe to the target's apex,
  so a crafted entry cannot redirect a request. This change relies on it and does not restate
  it.

## Out of scope

Server-side URL-fetch import (an operator can `curl` a list locally and upload it; a
server-side fetch of an operator-supplied URL is SSRF surface we don't need). Sharing lists
between users — captured in `roadmap/wordlist-sharing.md`.
