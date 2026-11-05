# 0010. The device transport, resumable commands and the enrolled-seat rule

Status: accepted

Extends [0007](0007-device-flows-resumable-reader-and-freshness.md) (device flows): adds the
`Opening` freshness level, a stored form of a sealed command, and the rule for waking a seat.
Completes its "signing stays outside" decision for the request proofs of Cloud calls.

## Context

With ADR 0007 every device decision lives in `nocterm-cloud-device`, and a client only executes
effects. Moving the native client onto the flows showed what the contract still lacked:

- `nocterm-hub-client` had no way to send a request the core built. Its own device paths
  (`DeviceHeadProbes`, `CloudCommandInvocation`, `PreparedChatKeyGrant`) built and sealed their
  own queries and commands, duplicating the core. To send the core's bytes the native adapter
  signed each request's proof of possession itself, with the device key read from its own
  credential file and the public `pop::request_message` layout, and called `Capabilities`
  unsigned. The device key left the client that is meant to hold it.
- A command sealed before the application quit could only be republished as raw bytes: no
  receipt probe, no pending row after a restart.
- A restored reader said `Unconfirmed` before anything had been asked of the runner, so a client
  could not tell "opening" from "the seat is asleep".
- `StartInstance` named no pool. A client had to list seats and choose a pool itself so that a
  chat would wake the agent's seat and never provision a new one (ADR 0122 of the native
  client); a client that sent the effect as it was let the hub choose and could provision.
- A tool call's display (its title and whether its outcome was a result or an error) was rebuilt
  by each client from the tool name and arguments.

## Decision

**hub-client is the device transport.** `HubClient::{capabilities, probe_head, publish_one,
replay, watch, runner_status}` send exactly what a Cloud effect names: the access token is
refreshed first when it is about to expire, and the client's own signer adds the device's
proof over the method path. They answer with the core's `flow::Input` (or `CloudFrames` of
`flow::Frame`s) and fail with `CloudCallError`, whose `failure()` is the effect's
`EffectFailure` (a lost publication answer after sending is `Unknown`; a probe nobody answered
before it expired, at most 10 s, is `Unavailable`). They bound answers and verify nothing. An
executor maps effects to calls one to one; no client handles the device key or request proofs.
hub-client's device-side builders are deleted; its runner side (head-probe answers, uploads,
replay and watch of its own streams, summaries) stays.

**A stored command.** `OpenChat::stored(&deliver)` returns a `command::StoredCommand` once the
device signed: format 1, the publication (id, binding, ciphertext), the facts its receipt probe
names (semantic digest, expected control revision, accept-before) and its pending row, sealed
with a key derived from the account key for the chat generation (the checkpoint derivation with
label `nocterm/cloud-device-command/v1`), at most one relay frame of ciphertext and one of
prompt text. `OpenChat::resume` checks every bound and that the binding routes a command of
this chat with this command id, shows the pending row again and returns a `Deliver` that
publishes the same bytes. A resumed delivery reports `Delivered` on its receipt and then asks
the runner once whether it admitted the command, since an earlier run may have been admitted.
Nothing is resent when the run already started, the chat tracks the command, or its window
ended (`Unreachable`). The client files the bytes under the chat and command id and forgets
them when the delivery ends.

**`Opening`.** A new or restored reader is `Freshness::Opening { last_witnessed_at_ms }` until
its first round completes. A first round without any witness or probe ends `Unconfirmed`; no
round returns to `Opening`.

**A seat is woken only through its own pool.** `seat::hosting_seat` is the agent's seat with a
runner and a pool that is neither deleting, failed nor awaiting enrolment (a ready one first).
`Deliver`, `CreateChat` and `seat::WakeSeat` list the seats (`ListInstances`, whose entries now
carry `pool_id`) and ask for `StartInstance { agent_id, pool_id, chat_id }` of that seat. An
agent without one is `NotEnrolled` for a new chat; a delivery goes on without a wake.

**Tool display in the transcript.** `ToolCall::outcome` is a typed
`ToolOutcome::{Pending, Ok(json), Err(text)}` (a later `Pending` never hides a result), and
`ToolCall::{label, title}` give the header every client shows (`"<destination> · <label>"`)
from the contract's list of terminal tools (`hub_model::cloud::tool_arguments::TOOLS`). The
checkpoint reducer version is 3.

## Consequences

- The device key and request proofs stay inside hub-client on every native device; the native
  adapter's own proof interceptor and unsigned `Capabilities` call go away.
- A command survives a restart with its pending row and its receipt probe, and is never sealed
  twice.
- Clients show "opening" distinctly from a sleeping seat, and never choose a seat's pool.
- Breaking for clients: `Freshness::Opening`, `Effect::StartInstance.pool_id`,
  `InstanceEntry.pool_id`, `ToolCall::outcome`'s type, and the removed hub-client device types.
  Older checkpoints are read again once (reducer version 3). Wire formats are unchanged.
