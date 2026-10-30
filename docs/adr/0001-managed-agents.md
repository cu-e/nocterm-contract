# 0001. Managed agents: sealed definitions, broker tokens and SSH CA grants

Status: accepted

## Context

A managed agent runs on a pool host the hub does not own the keys of. The hub is blind: it
stores and routes, and must not be able to read an agent's prompt, provider key or SSH
targets, nor substitute a host or a runner. Real secrets must never reach the sandbox that
runs the agent.

## Decision

**AgentDefinitionV1.** The plaintext of an agent (name, instructions, provider block with the
API key, named secrets, allowed hosts, SSH targets) is a `postcard` encoding of
`nocterm_keys::agents::AgentDefinitionV1`. Field order is the wire format; a change is a new
type and a new sealed format version. Limits are exported by `nocterm_hub_model::agents::limits`
and checked on both sealing and opening. The hub-visible part (`AgentListing`) never carries
these fields.

**Sealing to a pool key.** A pool is pinned by two public keys, `PoolKeys { encryption (X25519),
signing (Ed25519) }`, trusted on first use by one fingerprint (`check_pool_keys`, an error
`PoolKeyChanged` on change). The owner seals a definition with an authenticated box: the
owner's static X25519 key and a fresh ephemeral key, HKDF-SHA256, XChaCha20-Poly1305. The
associated data binds purpose, agent id, scope, pool id, the agent version and the sender's
fingerprint, so the hub cannot move an envelope to another agent, scope, pool or version, nor
replace the sender. `seal_definition` / `open_definition` are the only entry points;
`sealed_definition_version` lets a host choose a decoder before opening.

**Runner attestation.** A host signs `HostRunnerAttestation` (pool, host, instance, digest of
the runner setup document, time) with the pool signing key. The starting device verifies it
against the pinned key and the digest before importing the setup document.

**Credential broker.** The real API key reaches only the broker process on the pool host,
sealed by the owner to the broker's key (`seal_broker_secret`, bound to agent, scope, pool and
secret name). The runner receives a virtual token `nvt1_<base64url(id ‖ tag)>`, where `tag` is
HMAC-SHA256 under the broker's key over the token id and its claims (instance, chat, models,
budget, expiry). The broker stores the claims by id and revokes by deleting them.

**SSH CA.** The user's Ed25519 CA signs an `SshCaGrant` (agent principal `nocterm-agent-*`,
runner's ephemeral key, at most 24 hours, source addresses; forwarding is never allowed). A
server trusts the CA through one `authorized_keys` line
`cert-authority,principals="nocterm-agent-<id>" ssh-ed25519 <key>`, built and strictly parsed by
`CaLine`. The registry `agent_ssh_trust` (`SshTrustRecord`, states `Trusted`, `RemovalPending`,
`Removed`, `Drifted`) keeps the pure transition rules; reading and writing `authorized_keys`
belongs to the consumer.

**Receipt reclaim.** `retry_until_ms` on a publication, the capability bit
`CLOUD_FEATURE_RECEIPT_RECLAIM` (64), a signed `ChatDeletionTombstone` and 32-byte hashes of a
retired stream and a revoked runner are additive: clients that do not know them keep working
(`tests/agents_contract.rs`). The design's bit 32 was already taken by session start.
`nocterm-hub-client` sets a horizon only on request and only when the hub advertises bit 64
(otherwise `CloudError::Unsupported`); `RetireChat` is authenticated by the signed tombstone
alone, so the runner calls it without a session proof and repeats it while `compacted` is false.

## Consequences

- The hub can refuse service, not read or alter agents. A malicious hub could offer another
  pool key before the first pin; the fingerprint is the out-of-band check.
- A pool needs one key bundle instead of one key, because one key cannot both receive boxes and
  sign statements.
- Independent Python vectors in `fixtures/agents-v1` pin the byte layouts.
- `nocterm-keys-wasm` exposes unlocking, sealing, fingerprinting and attestation verification
  to the web panel; secrets stay inside WebAssembly.
