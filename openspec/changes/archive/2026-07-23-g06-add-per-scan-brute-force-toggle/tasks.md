# Tasks

- [x] Add a per-scan option (via `g03-add-per-scan-options`) for enabling active subdomain
      brute-force, defaulting to off.
- [x] Have `subdomain_recon` read the per-scan option to decide whether to run brute-force,
      falling back to the global `scanning.subdomain_bruteforce` default when unset.
- [x] Add a control to the web scan form (e.g. a checkbox) to enable it for a scan.
- [x] Add a CLI flag (e.g. `--bruteforce`) to enable it for a run.
- [x] Test: a scan with the option on runs brute-force; a scan with it off stays passive; the
      choice does not leak between scans.
