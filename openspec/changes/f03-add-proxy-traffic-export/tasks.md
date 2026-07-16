# Tasks

- [ ] Export captured traffic to HAR (direct serialization) and raw request/response from
      the traffic store.
- [ ] Synthesize an OpenAPI description from observed endpoints (group by method + path
      template, infer params/responses from examples); mark it best-effort, not complete.
- [ ] (Optional) Add Postman collection export on the same read path.
- [ ] Expose a read-only API over the store so external tools/agents can query captured
      traffic by the indexed dimensions.
- [ ] Support replaying a stored request with operator-specified modifications, issuing the
      replay through `ScanContext::send` (paced) and capturing its response.
- [ ] Test: HAR/OpenAPI/raw export of a small captured set produces the expected shapes;
      a replay with a modified header issues a paced request and captures the result.
