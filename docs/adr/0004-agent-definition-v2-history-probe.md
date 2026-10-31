# 0004. Agent definition v2, listing history and provider probes

Status: accepted

## Context

The web panel edits managed agents and found gaps the contract could not fill. A definition
(`AgentDefinitionV1`, ADR 0001) has no tool policy, no limits of its own and no model prices,
and it is postcard: not self-describing, so a field cannot be appended to version 1 without
breaking every reader. The hub keeps only the current listing, so a version history cannot be
shown. Nothing checks that an agent's provider key works before a person starts a chat; only a
pool host may use that key, because the hub never reads definitions. Quota rows show limits
without the use counted against them. The panel mirrored the pool pin check in TypeScript.

## Decision

**Definition format 2.** `nocterm_keys::agents::AgentDefinitionV2` is the six version 1 fields
in their order followed by `tools: ToolPolicy { allowed: All | Only(names), approval: Never |
Ask | Always }`, `limits: AgentLimits { max_turns, max_output_tokens, max_spend_micros_per_run,
max_spend_micros_per_chat }` (each optional, at least 1, per-run spend not above per-chat) and
`pricing: Vec<ModelPrice { model, input/output/cached-input micros per million tokens,
revision }>` (one per listed model at most, amounts at most `MAX_PRICE_MICROS_PER_MTOK`, revision
`[A-Za-z0-9._-]{1,64}`). Bounds live in `nocterm_hub_model::agents::limits`, so the web's
generated `limits.ts` has them. `Ask` lets the person allow a tool once or for the chat; `Always`
asks on every call; read-only tools are never asked about.

`seal_definition_v2` writes an envelope with format version byte 2 and its own HKDF label
(`nocterm-agent-definition-v2/auth`), so changing the byte cannot make a version 2 envelope open
as version 1 or the reverse. The associated data (agent, scope, pool, version, sender) is
unchanged. `open_definition_any` chooses the decoder from `sealed_definition_version` and
returns `AgentDefinition::{V1, V2}`; `into_v2` gives a version 1 definition the meaning it
always had: every tool, approval `Ask`, no limits, no prices. `seal_definition` and
`open_definition` keep format 1 unchanged. Decoding refuses bytes after the last field, so the
bytes of one version never read as another. Format 3, if needed, repeats this pattern.

**Prices and the operator.** A definition's prices are the owner's statement for the models of
its own provider block. They do not replace the operator's managed pricing (the chat-launch
design's decision R5): a host takes the higher of the operator's ceiling and the owner's price
for a model, falls back to the operator's when the owner gave none, and the credential broker
stays the budget authority. Limits only lower what the runner and the operator allow.

**Host levels.** `AGENTS_PROTOCOL_DEFINITION_V2 = 2` (the host opens format 2) and
`AGENTS_PROTOCOL_PROVIDER_PROBE = 3` (the host answers probes) extend the levels of ADR 0002;
`AGENTS_PROTOCOL_CURRENT` is 3. The version byte is outside the box, so the hub can route a
format 2 envelope only to hosts at level 2 or above without reading it.

**Listing history.** `AgentService.ListAgentVersions(agent_id, after, limit)` pages
`AgentVersion { version, listing, updated_at_ms, updated_by_account_id }`, newest first. The
listing is the hub-visible storefront as `PutAgent` wrote it; envelopes, digests and anything
sealed are never part of it. A hub without history answers the current version only.
`AgentClient::list_agent_versions` returns `AgentVersionPage`.

**Provider probe.** `AgentService.ProbeProvider(agent_id, pool_id?)` returns `ProbeResult { ok,
latency_ms, models, error_code }`. The hub sends `NodeDown.probe_provider` (`ProbeProvider`:
request id, agent, pool, scope, sealing account, definition version and the pool's envelope) to
an online host of the pool at level 3 or above. The frame carries the envelope because a host
may hold no instance of the agent; it opens it exactly as for `ProvisionInstance`, uses the key
only inside its broker, keeps nothing and answers `NodeUp.probe_result` (`ProviderProbeReport`).
The error code is a `ProbeFailure` code, `[a-z0-9_]{1,64}`, never provider text, which may echo
the key; models are bounded by `MAX_PROBE_MODELS`. Without such a host the hub answers
`host_unavailable`, after `PROVIDER_PROBE_TIMEOUT_MS` it answers `timeout`. The same validated
conversion (`ProviderProbe` ⇄ `v1::ProbeResult`) is used by host, hub and client. Probing needs
the right to write the agent, and a hub may rate-limit it.

**Smaller additions.** `UsageReport.in_use` (`ScopeUse`) is the current use counted against
`ScopeLimits`, of the scope or of the account the request names. `nocterm-keys-wasm` exports
`WebAccount.sealDefinitionV2` (JSON of `AgentDefinitionV2`) and `checkPoolKeys`.

Not added: an SSH CA overview (derived from `ListAccessGrants`) and an administrator list of
organizations (private administration API).

## Consequences

- Every addition uses new tags, new messages or new functions; older peers ignore them and
  version 1 envelopes stay readable everywhere. `DefinitionError` gained `Invalid`.
- A host built from this contract must state the level it implements, not
  `AGENTS_PROTOCOL_CURRENT`, until it opens format 2 and answers probes; a hub must not send
  format 2 envelopes or probes to a host below the level.
- The owner still cannot reopen what they sealed: editing a version 2 definition needs the
  plaintext from the editing device, as for version 1.
