# Tasks

- [x] Export captured traffic to HAR (direct serialization) and raw request/response from
      the traffic store.
- [x] Synthesize an OpenAPI description from observed endpoints (group by method + path
      template, infer params/responses from examples); mark it best-effort, not complete.
- [x] (Optional) Add Postman collection export on the same read path.
- [x] Expose a read-only API over the store so external tools/agents can query captured
      traffic by the indexed dimensions.
- [x] Support replaying a stored request with operator-specified modifications, issuing the
      replay through `ScanContext::send` (paced) and capturing its response.
- [x] Test: HAR/OpenAPI/raw export of a small captured set produces the expected shapes;
      a replay with a modified header issues a paced request and captures the result.
