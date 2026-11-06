# 0007. Device flows, a resumable reader and freshness levels

Status: superseded by [0015](0015-trusted-hub-runs-agents.md).

Extends [0006](0006-cloud-chats-on-a-browser-device.md). Supersedes its "Freshness stays
mandatory" decision and its "the order and the waiting are the caller's" sentence on chat
creation.

## Context

ADR 0006 made the device checks a pure crate, but left the order of the steps to each client.
The web panel and the native client therefore each implemented reading, sending and creating
again: the panel read every chat from cursor 0 on every open and on every Watch hint, replayed
every chat of the list to find a title, and crossed the wasm boundary with JSON; the native
client polled a head probe every second and refused to show a chat whose seat was asleep.
Retries, receipt probes, the seat wake before a managed prompt, the claim wait of a new chat
and the own-runner provider lease existed only natively, or not at all in the browser.

A read that requires a fresh witness cannot show a sleeping seat's chat, although the hub holds
its verified, runner-signed records.

## Decision

**Flows decide, clients execute.** `nocterm-cloud-device` owns the order of every device step
as flows over one effect protocol (`flow`): a flow hands out typed `Effect`s (sign, Store list,
key, get, put and create, capability proof, head probe, replay, watch, publish, start a seat,
list seats, runner status), takes the answers as `Input`s and replay or watch frames as
`Frame`s, and reports `Step::Output`, `Idle { until_ms }`, `Done` or `Failed`. Time and
signatures come in; randomness is the operating system's inside the crate. There is no sleep
effect: a flow that waits says until when it is idle. The flows are `Discover`, `ListChats`,
`OpenChat`, `Deliver`, `CreateChat` and `ProviderLease`; `nocterm-keys-wasm` exposes them as
one `CloudDevice` with structured values and generated TypeScript declarations, and a native
client runs the same flows with its own executor.

**Signing stays outside, and is not an oracle.** A `Sign` effect carries a `SignRequest` that
only this crate makes, from the canonical bytes of a head query or command header it built,
and names the device key. `nocterm-hub-client`'s `sign_cloud` accepts only such values
(`CloudSignable`, a sealed trait) for its own key.

**A resumable reader.** `reader::ChatReader` keeps the verified position (transport cursor,
event sequence, writer epoch, last accepted record) and the transcript across replay rounds:
a Watch hint replays only what is new. A refused frame ends the round; records accepted before
it stay, so a transcript is always a verified prefix. The reader seals its state as a device
checkpoint (version 1, reducer version 1) with a key derived from the account key and the
chat's coordinate and runner pins (`nocterm_keys::cloud::CheckpointKey`, HKDF info
`nocterm-cloud-device-checkpoint/v1`, purpose 21). A restored checkpoint shows at once; a
checkpoint of another reducer version, chat, account or pin set is not restored, and the chat
is read from the start. A witness behind the restored position, or a different record at its
sequence, is a rollback and fails the chat.

**Freshness levels (supersedes "freshness stays mandatory").**
- `Current`: a fresh head witness answered and the round reached it. Rounds driven by Watch
  hints keep it; every record is still verified one by one.
- `Unconfirmed`: the runner did not answer the probe (≤10 s). The hub's records are shown as a
  verified prefix that newer history may follow; the page says so and offers to wake the seat.
- `Withheld`: the runner witnessed a head the hub's replay did not reach; the verified prefix
  is shown, labelled, until a later round reaches the witnessed head.

A probe runs when a chat opens, when its Watch reconnects, after a delivery receipt of a
command this device sent, and on an explicit refresh; never periodically. Commands are allowed
in every state: they carry the expected control revision, and a conflict settles them refused.

**Commands.** `Deliver` wakes a managed seat first when the caller names its agent, signs and
seals the command once, and publishes exactly the same bytes on every retry. A receipt settles
it `Delivered`; a refusal `Refused`; an unknown outcome is retried with backoff and every
third attempt asks the runner for a command receipt (`Accepted`, `Conflict`, or `NotFound`,
which republishes at once); when the admission window ends it is `Unreachable`. The open chat
tracks these states as pending commands and asks once for the model grant of an accepted prompt
of this device (ADR 0129 of the native client).

**Creating a chat is a flow.** `CreateChat` starts the managed seat for the chat, reads the
registry again once when its runner is not trusted yet, compare-creates the material and then
the grant (using records another device stored, and re-sealing a grant only for stored material
without one), publishes the grant, probes every second, republishes every 15 s and gives up
after 60 s. `ProviderLease` verifies the own runner's boot under its pinned signing key, opens
`agent_provider_keys/key-<agent>`, seals a 10-minute capsule to the boot, publishes
`IssueGrant(Provider)` under one grant id with the lease expiry as epoch, and renews at half
term while it runs.

**A shared transcript.** The reducer also shows SSH consent requests and session lifecycle,
numbers rows so a view can apply a `TranscriptDelta`, and keeps the pending commands of this
device (device-local, not in a checkpoint).

## Consequences

- One device implementation: the desktop moves onto these flows (its plan's phase 6) and the
  panel onto `CloudDevice` (phase 2); the old wasm classes are removed, and
  `fixtures/cloud-device-v1/web-session.json` is a recorded session over the flows.
- Opening a chat costs one probe and a replay of new records only; listing never replays.
- A sleeping seat's chat is readable, labelled `Unconfirmed`. A hub can show a stale prefix,
  never a forged or reordered one, and cannot hide history the runner witnessed without the
  read saying `Withheld`.
- Checkpoints are local, sealed and versioned; a reducer change costs one full read.
- Recorded test sessions draw probe nonces from a seed only with the `testing` feature, which no
  shipped build enables.
