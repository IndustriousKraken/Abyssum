# Per-scan options carried on a scan

## Why

Several wanted features are *per-scan* choices, not global configuration: whether a scan runs
active subdomain brute-force, which custom wordlist it uses, and which timing profile shapes
its pacing. Today a scan is created from just its targets and scanners, and scanner behavior
comes only from global config — so these choices have nowhere to live per run. This change
establishes the small shared foundation those features build on: a scan can be started with a
set of options, and scanners can read them while the scan runs.

## What Changes

- A scan can be started with a set of **per-scan options**, recorded for that scan.
- The engine makes those options available to scanners through the scan context during the
  run, so a scanner can adjust its behavior for that scan.
- A scan started with no options behaves exactly as before — defaults apply.
- No new way to issue an unpaced request is introduced; options are data, not a request path.

## Note

This is additive (new requirements in scan-orchestration), so it does not modify the existing
`Scan Context Provided To Scanners` contract. The feature changes that consume it
(`g06-add-per-scan-brute-force-toggle`, `g07-add-user-wordlist-upload`, and the already-spec'd
`g05-add-timing-profiles`) express their behavior at the capability level and depend on this only
as an implementation mechanism.
