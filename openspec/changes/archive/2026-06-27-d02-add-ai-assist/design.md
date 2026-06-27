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
  max_evidence_chars: 4000               # evidence is truncated to this before sending
  temperature: 0.2                       # low => stable, repeatable analysis
  max_tokens: null                       # optional cap on the response length
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

### Decision: A fixed system prompt frames authorized analysis
The request carries a fixed system message that frames the model as a security analyst
assisting **authorized** bug-bounty / pentest work, and asks it to assess the finding's
validity and severity, explain the security impact, and suggest remediation — grounded in the
provided evidence. This framing matters: the canon notes that hosted models sometimes refuse
legitimate authorized-analysis requests, and prompt phrasing is the lever that most affects
that (the keyless/self-hosted path is the other mitigation). The user message carries the
finding's scanner id, target, status, severity, title, and (truncated) evidence. Request
params default to a low temperature for stable analysis; the exact wording is content, but the
*presence* of an authorized-context system message is a behavioral requirement.

### Decision: Evidence truncation has a concrete bound
Evidence is truncated to a configurable `ai.max_evidence_chars` (default 4000) before sending,
so a large finding cannot blow the request size. Truncation is marked in the prompt so the
model knows the evidence was clipped.

### Decision: The analysis surface lives on the finding
`analyze_finding` is reachable from the web finding-detail view via an "Analyze with AI"
action (and an equivalent CLI path), so the on-demand request the scenarios describe has a
concrete trigger. The surface treats a non-fatal `Err` as a displayed notice, never a failure.

### Decision: Request parameters and response robustness
The chat request is **non-streaming** (`stream: false`) — the analysis is shown as one block,
which keeps response handling simple and the best-effort error mapping total. `temperature`
defaults low (**0.2**) for stable, repeatable analysis rather than creative variation;
`temperature` and `max_tokens` are optional config keys with conservative defaults. Response
parsing reads `choices[0].message.content`; a response missing `choices`, an empty array, or a
`null`/absent `content` is treated as a malformed response → a clear non-fatal error (the same
path as a 500 or a transport failure), never a panic.

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
