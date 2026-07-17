# Design

Part of the surface-mapping capability, reusing `ScanContext::send`.

**Candidate generation.** Permute the target's domain labels and organization name with
common affixes and separators (`-dev`, `-prod`, `-assets`, `backup`, …) to build likely
bucket/asset names. Seed a small built-in affix list; the existing wordlist mechanism can
supply more later.

**Probing.** For each candidate, request the provider's storage endpoint (S3 virtual-host
or path style, GCS, Azure Blob) and classify from the response: does-not-exist, exists-
but-access-denied, or exists-and-listable/readable. Public listing/readability is the
high-value finding.

**Severity.** Exists-and-public → high/critical (data exposure). Exists-but-denied → an
informational footprint finding.

**Scope line.** Confirm existence and exposure only; do not enumerate or download object
contents beyond the minimum needed to prove public readability. Per-provider-host pacing
applies via the rate limiter.
