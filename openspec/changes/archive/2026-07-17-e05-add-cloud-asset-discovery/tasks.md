# Tasks

- [x] Generate candidate asset names by permuting the target's domain/organization
      identifiers with a built-in affix list; deduplicate candidates.
- [x] Probe known cloud-provider storage endpoints (S3/GCS/Azure) for each candidate
      through `ScanContext::send` (paced, rotating User-Agent).
- [x] Classify each probe result: does-not-exist, exists-but-denied, or exists-and-
      publicly-readable/listable.
- [x] Report existing assets as findings; report publicly readable/listable ones at high
      severity (data exposure). Do not report non-existent candidates.
- [x] Do not download or enumerate object contents beyond confirming public readability.
- [x] Cap the number of candidates probed and log when the cap truncates results.
- [x] Test (no real network): a stubbed public bucket yields a high-severity finding, a
      denied one yields an info finding, and a missing one yields nothing.
