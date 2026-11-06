# 0014. Bounded fragments carry logical device publications

Status: superseded by [0015](0015-trusted-hub-runs-agents.md).

## Context

Inline image parts belong to one signed command, whose encrypted body can exceed a
16 KiB relay frame. `PublishOne` and gRPC-web requests were deliberately restricted
to one frame and a 32 KiB protobuf message. A logical publication and its stored
restart copy must not inherit that per-frame limit.

## Decision

The existing signed logical-envelope ceiling remains 32 MiB plus authenticated-box
overhead. Frame and service-message ceilings remain 16 KiB and 32 KiB. Optional
capability bit 512, `CLOUD_FEATURE_FRAGMENTED_PUBLISH`, admits larger device
publications without changing capability version, signed command layouts, encrypted
bodies or publication identities. An older hub produces an actionable typed refusal.

`CommandHeader::plaintext_len` owns the exact signed plaintext framing size.
`OpenChat::deliver` checks the corresponding envelope size before tracking pending
state or returning a delivery. Sealing and stored-command reopening check the
negotiated envelope limit again. Prompt text remains separately limited to 16 KiB;
image count, image bytes, inference limits and provider authorization do not change.

Native `HubClient::publish` uses existing streamed `Publish` for a larger body.
The original immutable ciphertext is shared; the RPC consumer pulls one bounded
chunk at a time. `publish_one` retains its original one-frame contract.

Browsers use additive device-only unary `PublishFragment`. Each request repeats
the original `CloudPublication`, carries an offset and at most one negotiated-size
data chunk, and optionally finishes. Empty data is allowed only for finalization
at the declared total. Every request authenticates the original current device.
Staging resumes only the identical immutable header and issuer, retaining the
original persisted attempt, expiry and quota reservation. Exact duplicate bytes
at the same offset are idempotent; changed overlaps and gaps are refused. Finish
requires complete length and the original ciphertext digest, and commits the same
durable receipt at most once. A completed publication returns its original receipt
on a retry. No in-memory upload registry or unbounded request body is introduced.

`CloudPublishProgress.next_offset` stays between the submitted end and the declared
total. A final response must carry the durable receipt; an already completed
publication may return it early. Clients verify its publication id, digest and
nonzero cursor. This is a storage receipt, never a runner command admission.

The browser's existing publish effect has an optional `maxFrameBytes` only for
larger ciphertext. Its executor publishes sequential fragments with bounded
backpressure and retains the original encrypted body for delivery retries.
The stored-command format remains 1, with ciphertext bounded by the logical
envelope and pending text by its separate text limit. Existing one-frame stored
records retain their bytes. Consumers keep their own bounded storage admission;
a capability downgrade must not discard a valid original command.

## Alternatives

Raising relay frames or protobuf ceilings would expand every network operation's
allocation bound. A second signed command per image would change prompt identity,
authorization and retry semantics. Separate begin/append/finish RPCs would add a
larger public lifecycle. One idempotent fragment RPC reuses persisted publication
reservations, exact offsets, existing quotas and digest verification.

## Consequences

Valid images span multiple bounded requests while remaining one immutable signed
prompt. Old hubs need an update for large prompts; no attachment is silently
omitted. Expired incomplete staging is reclaimed under existing upload expiry.
Network cancellation never undoes an already durable receipt.
