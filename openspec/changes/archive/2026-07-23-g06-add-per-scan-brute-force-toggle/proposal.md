# Enable active subdomain brute-force per scan

## Why

Active subdomain brute-force exists but is gated only by a global config flag
(`scanning.subdomain_bruteforce`, off by default). There is no way to turn it on for a single
scan, and the web UI exposes no control for it at all — so a UI operator cannot use it. It
should be a per-scan choice: off by default (staying passive and conservative), opt-in for the
scan where the operator wants it.

## What Changes

- The operator can enable active subdomain brute-force for a **specific scan** via a per-scan
  option — off by default.
- The web scan form gains a control for it; the CLI gains a flag.
- When enabled for a scan, that scan's subdomain reconnaissance performs the active
  brute-force; when not, it stays passive.

## Depends on

`g03-add-per-scan-options` (the mechanism that carries the choice on the scan). This change is a
pure ADD in `surface-mapping` — it does not modify the existing brute-force requirement (which
already says the source is off by default "unless the operator enables it"; this is one way the
operator enables it), so it does not collide with `g04-add-infrastructure-pacing-lane`, which
modifies that requirement.
