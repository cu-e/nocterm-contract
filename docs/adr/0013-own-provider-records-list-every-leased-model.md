# 0013. Own provider records list every model a lease permits

Status: superseded by [0015](0015-trusted-hub-runs-agents.md).
[0006](0006-cloud-chats-on-a-browser-device.md).

## Context

An own agent's encrypted provider record named one model, and the provider lease
therefore allowed only that model, even though an agent listing can name several.
A model picker must offer the actual leased models, and model-only edits must not
expose or replace the credential. The desktop kept a second encoder of this record.

## Decision

- `ProviderKeyRecord` is the one encoder and decoder. Existing `new`, `model` and
  byte accessors stay compatible; `new_models`, `models` and `with_models` cover a
  complete ordered list of at most 32 distinct bounded ids. The first is the default.
- Readers accept format 1 (`format`, `provider`, `model`, `key`) and format 2
  (`format`, `provider`, `models`, `key`). Writers produce byte-identical format 1
  for one model and format 2 for multiple models. Older readers reject format 2;
  they cannot accidentally narrow the lease to its first model.
- `ProviderLease` signs every model of that authenticated record in the existing
  `GrantPayload::Provider.allowed_models`. Its output names the default as before
  and also the complete list. Provider keys, signatures and command layouts do
  not change. The runner remains the authority that admits a model request.
- The browser collection-key handle reads only the model list or reseals a model-only
  edit. The collection id, canonical `key-<agent>` object id and `agent_provider_keys`
  kind remain authenticated; the provider and credential never cross into JavaScript.
- The desktop delegates record encoding to this contract instead of keeping a
  separate JSON format. Listings remain descriptive; an own composer obtains its
  choices from the actual completed lease.

## Alternatives

Adding catalog models to a one-model lease would display choices the runner must
refuse. Encoding a list in the existing `model` string would change an opaque model
id. Exposing decrypted provider records to JavaScript would grant unrelated secret
access for a model-only edit. All three are rejected.

## Consequences

Single-model fixtures and existing clients keep their current behavior. A device
needs this record reader to edit or lease a multi-model own agent. Editing models
is independent of editing the credential, while object compare-and-swap still
protects concurrent updates. The hub stores ciphertext and public listing metadata;
its listing cannot widen the signed lease.
