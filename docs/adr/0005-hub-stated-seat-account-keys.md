# 0005. Hub-stated seat account keys

Status: superseded by [0015](0015-trusted-hub-runs-agents.md).

## Context

A host provisions a seat (`ProvisionInstance`) for one account. It needs that account's
X25519 keyset public key twice: to open a personal agent's definition, whose sender is the
account itself, and to bind the runner it creates to the account, so that only the account's
devices can enrol it. Until now a host learned the key only from an operator pin. Every new
account therefore needed the server operator before its first personal seat, and seats failed
with `owner_unpinned` or `account_unpinned` (`ProvisionFailure`) for reasons the person could
not fix. The hub already stores each account's keyset public key, but the hub is not trusted to
say whose key it is (ADR 0001): a hub that substitutes a key could hand a host a runner it
controls.

## Decision

**The stated key.** `ProvisionInstance.account_public_key` (11) and
`ProbeProvider.account_public_key` (8) carry the 32-byte keyset public key the hub stores for
the seat account (`account_id`), or for the sealing account of a probe. The hub sends the field
only to hosts at `AGENTS_PROTOCOL_STATED_ACCOUNT_KEY` (4) or above; a host below ignores it as an
unknown field and keeps requiring a pin. Empty means the hub states no key.

**The device closes the loop.** The runner setup document binds the seat's account id and the
fingerprint of the keyset key the runner was created for, and the attestation signed by the
pinned pool key covers the document (ADR 0001). A device enrols a runner only when the document
names its own account id and the fingerprint of its own keyset public key. A substituted key thus yields a runner no device of the real
account enrols: the substitution is visible end to end and gains the hub nothing it could not
do by refusing service.

**Personal scope.** For an agent of `SCOPE_KIND_ACCOUNT`, a host at level 4 may use the stated
key as the owner key that opens the definition and as the runner's account key, without an
operator pin. The definition must open under it: the envelope's associated data binds the
sender's fingerprint, and the hub cannot produce an envelope sealed by the real owner. A hub
that states its own key and seals its own definition gets a runner bound to that key, which the
real account's devices refuse to enrol.

**Organization and instance scope.** For `SCOPE_KIND_ORG` and `SCOPE_KIND_INSTANCE` the
definition is sealed by an owner the operator pinned, and the runner receives the scope's
secrets through the broker. A hub-stated seat key would let a malicious hub bind such a runner
to a key it holds and drive it with the organization's secrets. A host therefore uses the
stated key in these scopes only when its operator explicitly opts in with a host setting;
otherwise it requires an operator pin for the seat account and fails with `account_unpinned`.

**Pins win.** When the operator pinned a key for the account and the hub states a different
one, the host refuses the seat (`account_key_mismatch`) in every scope, and the probe answers
`definition_unavailable`. A stated key never replaces or extends a pin.

## Consequences

- Personal agents work for a new account without the operator, at no loss of the
  end-to-end guarantees: the device's check, not the hub's statement, decides enrolment.
- Organization operators keep the previous behaviour unless they opt in, and can see why a seat
  failed (`account_unpinned`, `account_key_mismatch`) instead of a generic error.
- All additions are new tags and a new level; older hosts, hubs and clients are unaffected.
  A host must state level 4 only once it implements these rules, including the refusal on a
  mismatching pin.
