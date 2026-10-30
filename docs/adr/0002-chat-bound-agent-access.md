# 0002. Chat-bound agent access: per-chat tokens, running leases and per-model usage

Status: accepted

## Context

ADR 0001 gives the runner a broker virtual token. Access is meant to live as long as the chat
that uses it, not for a time the user picks, and the hub must reconcile with hosts and report
spend per model, still without seeing any secret.

## Decision

- `StartLease.chat_id` (optional) names the chat a lease serves. `NodeDown.chat_access`
  (`ChatAccess { lease_id, chat_id, op = ISSUE | REVOKE }`) asks the host's credential broker
  to issue or revoke that chat's virtual token. The hub sends identifiers only; the broker
  mints the token, hands it to the runner on the host and never reports it back. Stopping a
  lease revokes its tokens without a frame.
- `NodeHello.agents.running_leases` lists the leases the host runs (`lease_id`,
  `instance_id`, optional `chat_id`), so the hub can reconcile after a reconnect.
- `model` (string id, empty when unknown) is added to `InstanceUsage` and `UsageRow`; a window
  covering several models is reported as one message per model.
- `nocterm-keys-wasm` exports `loginAuth` (the `login-v1` value sent to the hub) and
  `WebAccount.unlockWithPassword` (a vault password with the keyset's recorded derivation).
- A chat retirement keeps `RetireChat` unauthenticated by a runner proof (the tombstone
  signature authenticates it), so `RunnerMethod` gains no variant.

## Consequences

All additions use new tags and defaults: an older hub or host ignores them and an older peer's
messages decode to the previous meaning. A host that does not know `chat_access` keeps the
token it has per lease.
