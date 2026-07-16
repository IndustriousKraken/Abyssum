# Tasks

- [x] Detect whether a target is fronted by a CDN/WAF (response-header / IP-ownership
      markers) and only attempt origin discovery when it is.
- [x] Gather candidate origin IPs from passive sources (historical/passive DNS,
      certificate data), fetched through `ScanContext::send`.
- [x] Confirm a candidate by issuing a direct request to the IP with the target's `Host`
      header and comparing the response to the perimeter baseline (reuse the BAC/IDOR
      body-normalization comparison); treat a content match with CDN markers absent as a
      confirmed origin.
- [x] Report a confirmed origin as a finding naming the host and the origin IP; do not
      report unconfirmed candidates as the origin.
- [x] Ensure every lookup and probe passes through the paced request path.
- [x] Test (no real network): a stubbed candidate that serves matching content is
      confirmed; one that serves different content is not reported as origin.
