# Design: AI-Assist (Outbound OpenAI-Compatible Analysis)

## Technical Approach

Add an `ai` module to `abyssum-core` exposing an `analyze_finding(&Finding) -> Result<String>`
entry point. It builds a chat-completions request from the finding's persisted fields and
POSTs it to the configured OpenAI-compatible endpoint, then extracts the assistant message
text from the response.

```
build_prompt(finding)            # scanner id, target, status, severity, evidence -> messages
  -> POST {base_url}/chat/completions  { model, messages }   (Authorization only if key set)
  -> parse choices[0].message.content
  -> Ok(analysis_text)  |  Err(clear, non-fatal message)
```

The caller (CLI command or web handler in later changes) treats the `Err` as a displayable
notice, not a failure that propagates up and aborts anything.

## Library / Crate Choices

- **HTTP:** `reqwest` (the workspace HTTP client) with JSON via `serde`/`serde_json`. No
  dedicated OpenAI SDK crate — the chat-completions request/response is a tiny, stable JSON
  shape, and an SDK would impose its own auth assumptions (mandatory key) that conflict with
  the absent-key requirement.
- **Timeout:** `reqwest`'s per-request timeout, configurable; defaults conservatively so a
  hung provider cannot stall triage.
- **Config:** `serde`-deserialized `AiConfig` slotted into the existing layered config
  (defaults < YAML file < `ABYSSUM_*` env), consistent with `bootstrap-rust-workspace`.

## Config Keys (this change owns these)

```yaml
ai:
  base_url: http://localhost:11434/v1   # any OpenAI-compatible endpoint (Ollama shown)
  model: llama3.1                        # model name the endpoint serves
  api_key: null                          # OPTIONAL — omit/empty for keyless endpoints
  timeout_seconds: 30                    # best-effort cutoff
  enabled: true                          # off => analyze requests return a clear "disabled" notice
```

Env overrides follow the established prefix, e.g. `ABYSSUM_AI__API_KEY`,
`ABYSSUM_AI__BASE_URL`, `ABYSSUM_AI__MODEL`. The key may also come from the environment so
it need never be written to disk.

## Key Decisions

### Decision: Optional key handling (hard canon requirement)
When `api_key` is null/empty, the request is sent with **no** `Authorization` header — not an
empty bearer token, which some servers reject. When a key is present, it is sent as a bearer
credential. Both paths must be exercised by tests against a local mock server.

### Decision: Best-effort, never fatal
`analyze_finding` returns `Result` and the contract is that callers convert `Err` into an
operator-visible message. Network errors, non-2xx provider responses, malformed bodies,
timeouts, and "AI disabled / unconfigured" all map to distinct, clear `Err` messages. None
of them unwinds into the scan engine, the persistence layer, or any caller's success path.

### Decision: Outbound only
No server, route, listener, or callback is added that lets an external agent invoke Abyssum.
This is enforced structurally (the module only *calls out*) and is a stated non-goal in the
canon.

### Decision: Per-finding surface (canon default)
v1 analyzes one finding on demand rather than auto-summarizing whole sessions (see open
question #4 in `project.md`). The prompt is assembled from a single `Finding`'s stored
fields so the analysis is grounded in concrete evidence.

## Testing

- Unit-test prompt assembly from a representative `Finding` (all fields present; evidence
  truncation if oversized).
- Unit/serde-test `AiConfig` defaults, file overlay, env override, and the null/empty-key
  case.
- Integration-test against a **local mock HTTP server** that mimics an OpenAI-compatible
  `/chat/completions` endpoint:
  - happy path returns the assistant text;
  - a request made with **no** API key configured succeeds (mock asserts no `Authorization`
    header was sent);
  - a request with a key configured sends a bearer credential;
  - a 500 / malformed body / timeout each yield a clear non-fatal error.
- **No real providers, no real targets.** All tests are local and deterministic.
