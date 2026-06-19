## Why

Bug bounty triage is slow: an operator stares at a raw finding (status, target, evidence)
and has to reason out severity, exploitability, and a write-up. The canon locks in an
**outbound, OpenAI-compatible** AI integration to accelerate that triage — Abyssum sends a
finding's context to a chat model and returns the model's analysis to the operator.

This change adds that AI-assist capability. It is deliberately narrow: **outbound only**
(no inbound agent API — an explicit v1 non-goal), **best-effort** (a provider problem must
never break a scan or the surrounding flow), and **absent-key-friendly** (a self-hosted
OpenAI-compatible endpoint such as Ollama must work with no API key — a hard canon
requirement). It depends on `result-persistence` for the stored `Finding` records it
analyzes.

## What Changes

### 1. On-demand AI analysis of a finding

An operator can request AI analysis for a single stored finding. The system assembles that
finding's context (scanner id, target, status classification, severity, evidence) into a
chat request, sends it to the configured provider, and returns the model's textual analysis
to the operator.

### 2. Configurable OpenAI-compatible provider

The provider is selected by configuration: a base URL and a model name identify any
OpenAI-compatible chat endpoint. The API key is **optional** — when the configured endpoint
requires no credential, requests are made with no key set and must still succeed.

### 3. Best-effort, non-fatal failures

Every AI call is best-effort. A provider error, an HTTP failure, a timeout, or a missing
configuration surfaces a clear message to the operator and is recorded as a failed attempt,
but never aborts the scan, the persistence flow, or any surrounding operation.

### 4. Outbound only

v1 exposes no inbound API for external agents to drive Abyssum. The capability is strictly
Abyssum-calls-out; there is no listener, callback, or agent-control surface.

## Impact

- Adds the `ai-assist` capability to `openspec/specs/`.
- Consumes the stored `Finding` shape from `result-persistence` (change #4).
- Extends configuration with an AI-provider section (base URL, model, optional key, timeout)
  via this change's own delta — owned here, not redefined elsewhere.
- No new scanner behavior; this augments triage of findings that already exist.
