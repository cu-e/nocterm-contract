# 0012. Model edits retain the pool-sealed definition

Status: accepted. Extends [0004](0004-agent-definition-v2-history-probe.md).

## Context

Only a pool opens an agent definition. A browser editing its public listing cannot recover
the provider key, instructions, secrets, tool policy, limits or prices. Requiring a complete
replacement to add a model makes ordinary editing difficult, and constructing a replacement
from listing defaults would silently discard private settings. An in-memory pool cache would
not survive moving an instance to another host or restarting a host.

## Decision

Definition format 3 is a flat model edit retaining the original complete envelope once.
Its bytes are `3 ‖ purpose ‖ base_version:u64be ‖ base_length:u32be ‖ patch_length:u32be ‖
base_envelope ‖ patch_box ‖ manifest_mac:32`. The base is a complete format 1 or 2 envelope
for the same agent, scope, pool and owner, sealed at a positive version strictly below the
edit's. A base version may precede the current listing version because listing-only updates
retain the original envelope.

`patch_box` is the existing authenticated account-to-pool box at version 3, with the distinct
HKDF label `nocterm-agent-definition-model-patch-v3/auth`. Its plaintext is postcard
`AgentModelPatch { models: Vec<String> }`. Associated data appends the base version in decimal
and SHA-256 of the unchanged base envelope in lowercase hex after the existing context
(agent, scope, pool, edit version, owner fingerprint). The host verifies the manifest, opens
this box, then opens the original complete base in exactly its original context. No nested
edit can appear as a base.

The public manifest lets the owner reuse the stable base without decrypting private fields.
It is authenticated by HMAC-SHA256. The key is HKDF-SHA256 of static account/pool X25519 DH,
salt `owner_public:32 ‖ pool_public:32`, info
`nocterm-agent-definition-model-patch-v3/manifest`; noncontributory DH is refused. The MAC
covers the existing canonical `aad(AgentDefinition, context_with_sender)` followed by the
entire flat envelope before the MAC, including the original base and latest patch ciphertext.
The pool derives the same key. No key leaves the crypto owner.

When editing an existing format 3 envelope, the owner verifies that manifest under the prior
exact sealing context before extracting the base. A malicious hub therefore cannot swap
public base bytes, their version, or an older patch context into a fresh owner-authenticated
edit. The new edit stores only that stable base plus the latest complete model set. Repeated
edits have constant size and cost: two boxes are opened, with no edit chain, host cache or
historical SQL row. The entire envelope stays at most 128 KiB and each plaintext keeps the
existing definition bound; framing lengths are checked before slicing or allocating.

The complete nonempty model list has bounded, distinct, nonempty ids. Applying it changes
only `provider.models` and removes owner price entries for removed models. Prices for models
listed in the original complete base are preserved byte for byte, including when one is
removed and later added again. A model absent from that original base has no owner override
and uses the operator's existing pricing rules. The resulting full format 2 definition is validated.
Keys, instructions, secrets, policy, limits, endpoints, network rules and SSH targets remain
unchanged. `AgentDefinition::V3` returns that resolved definition; `into_v2` reads it normally.

`WebAccount.sealDefinitionPatch` receives the typed model request as bounded JSON, the base
envelope and the pinned pool encryption key. It seals inside WebAssembly. The old plaintext
and provider key never reach JavaScript or the hub. The existing owner pin and management
authorization rules are unchanged; an unrelated administrator cannot replace the owner pin.

`SealedDefinition.sealed_version` is additive protobuf field 5. It reports the stored base
context and is ignored on writes; zero means an older hub does not provide the information.
A caller must not guess the context from the listing version.

Hosts advertise `AGENTS_PROTOCOL_DEFINITION_PATCH = 5`. The hub routes format 3 provisioning
and probes only to such hosts; a retained instance on an older host fails with an upgrade
reason before either the definition or lease is sent. Unknown formats remain unsupported.
This is an additive capability and a new sealed format, not a change to existing signed
layouts or protobuf field numbers; protocol version 2 remains compatible.

## Consequences

Model edits work for existing format 1/2 definitions without re-entering private settings,
and repeated edits can be opened by a fresh host. Operators must upgrade the hub and hosts
before using the new format. Whole-definition replacement remains the explicit operation
for changing private settings. Editing prices without
knowing the original table is not inferred from public listing defaults.
