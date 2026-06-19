# Tasks

## 1. AI provider configuration
- [ ] 1.1 Add an `ai` config section (`base_url`, `model`, `api_key` optional, `timeout_seconds`, `enabled`) deserialized into the existing layered config
- [ ] 1.2 Make `api_key` nullable/empty-friendly and overridable from `ABYSSUM_AI__*` env vars
- [ ] 1.3 Unit-test the config: defaults, file overlay, env override, and the null/empty key case

## 2. AI-assist module
- [ ] 2.1 Add an `ai` module in `abyssum-core` exposing an `analyze_finding` entry point that takes a stored `Finding` and returns a `Result` of analysis text
- [ ] 2.2 Build the chat request prompt from the finding's scanner id, target, status, severity, and evidence
- [ ] 2.3 Truncate oversized evidence before sending so a large finding cannot blow the request size

## 3. Outbound OpenAI-compatible call
- [ ] 3.1 POST a chat-completions request to `{base_url}/chat/completions` with the configured model
- [ ] 3.2 Attach a bearer credential ONLY when a key is configured; send NO authorization header when the key is absent/empty
- [ ] 3.3 Apply the configured request timeout
- [ ] 3.4 Parse the assistant message text from a successful response

## 4. Best-effort error handling
- [ ] 4.1 Map network failure, non-2xx provider responses, malformed bodies, and timeout to distinct clear error messages
- [ ] 4.2 Return a clear "AI disabled" / "AI not configured" message when `enabled` is false or required config is missing
- [ ] 4.3 Ensure `analyze_finding` only returns a value or error and never panics or propagates a failure that could abort a scan or persistence flow

## 5. Tests (local only — no real providers or targets)
- [ ] 5.1 Unit-test prompt assembly from a representative finding, including evidence truncation
- [ ] 5.2 Integration-test against a local mock OpenAI-compatible server: happy path returns the analysis text
- [ ] 5.3 Test that with NO key configured the request succeeds and the mock observed no authorization header
- [ ] 5.4 Test that with a key configured the request carries a bearer credential
- [ ] 5.5 Test that a 500 response, a malformed body, and a timeout each surface a clear non-fatal error and do not abort the caller
- [ ] 5.6 Test that an analyze request with AI disabled returns a clear notice and changes nothing else
