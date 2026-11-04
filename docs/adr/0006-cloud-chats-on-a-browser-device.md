# 0006. Cloud chats on a browser device

Status: accepted

## Context

The hub's web panel runs on a browser device: the device key is a non-extractable WebCrypto
Ed25519 key registered with the hub like any other device, and the panel already unlocks the
account keyset in WebAssembly (`nocterm-keys-wasm`). Cloud chats (list, read, prompt, stop, allow,
answer approvals, create) were possible only from the native client, for three reasons that lie
in this contract:

- The formats a device needs beyond the wire types (the account's private records of hub trust,
  trusted runners, wrapped chat keys and stored chat key grants) were defined only inside the
  native client, under its licence.
- The device-side checks (capability pin, head probes, record context, sequence continuity,
  gap recovery, command sealing) lived in the native SDK (`nocterm-hub-client`), which needs
  tokio and tonic and signs with a device key it holds itself.
- `CloudService.Publish` is client streaming. gRPC-web in a browser cannot stream a request.

## Decision

**A pure device crate.** `nocterm-cloud-device` holds the formats and checks a device needs
without network, storage or a device key: it depends only on `nocterm-hub-model` and
`nocterm-keys`, so it builds for `wasm32-unknown-unknown`. Bindings stay in `nocterm-keys-wasm`.

**Private account records are specified here.** The four layouts (`cloud-hub-trust` /
`hub-authority-v1`, `cloud-runner-registry` / `trusted-runners-v1`, `cloud-chat-material`,
`cloud-chat-grant`), their collection ids (UUIDv8 of a labelled SHA-256) and object ids are
written from the format, not copied from the native client. Vectors produced by the native
encoder are checked in (`fixtures/cloud-device-v1/desktop-*.txt`) and the crate must reproduce
them byte for byte; any change to these layouts is a format change for both clients.

**Hub trust without the native origin.** A hub-trust record's context names the `host:port` the
native device configured, which a browser does not know. The browser lists the account's
`cloud-hub-trust` collections, opens `hub-authority-v1` in each, accepts a record only when the
collection id is the one its own context derives and its raw hub id, account id and account key
digest match the hub and account it signed in to, and shows the record's origin. Several matches
are the person's choice; none means Cloud was never set up on a native device. Trust is never
created in the browser.

**Two-step signing.** Everything a device signs (head queries and command headers) is produced as
canonical bytes; the caller signs them with Ed25519 (no prehash) and passes the signature back.
The crate verifies it under the device key named in the signed bytes before sealing with the
account key pair, so a wrong key or a wrong message fails before anything leaves the device.
Probe ids, challenges, command ids, nonces and grant ids come from the operating system's
randomness inside the crate.

**Freshness stays mandatory.** A chat is read only after a fresh head witness from the pinned
runner; a replay that ends below the witnessed head, or a record at a witnessed position that is
not the witnessed record, is refused. A sleeping seat must be woken first.

**A browser does not acknowledge.** Readers that acknowledged hold back compaction of a retired
chat; a discarded browser profile would hold it back for ever. The device replays from its own
cursor and never calls `Acknowledge`.

**Unary publish.** `CloudService.PublishOne(CloudPublishOne)` carries one publication whose
ciphertext fits one relay frame (at most 16 KiB) in a single request. It is the streamed
publication with one data frame and the finished marker, with the same idempotency by publication
id and the same receipt. It is device only and offered under capability bit 128
(`CLOUD_FEATURE_UNARY_PUBLISH`); a hub without the bit answers `UNIMPLEMENTED`.

**Commands a browser sends.** Prompt (runner-default bounds, no target or session), Stop, Allow
(an `IssueGrant(Inference)` with exactly the prompt's bounds, valid for half the prompt lifetime)
and approval answers. Every deadline is capped by the signed-in session's refresh expiry. Chat
creation is offered as building blocks (chat id, chat key wrapped for the account, sealed grant
stored before it is published); the order and the waiting are the caller's.

**A neutral transcript.** The crate reduces verified events to display rows (role, text, tool calls
with status, timestamps, runs with status and usage, pending approvals). It is display data,
separate from the native projection; both are tested over the same public event fixtures.

## Consequences

- The web panel can read and drive Cloud chats with the same end-to-end checks as a native device.
  Code served by the hub now holds the account key pair and Cloud write capability while the
  keyset is unlocked; that was already true of the account key, and the hub's ADR records it.
- The private record layouts become public format. The native client should consume these codecs
  (or keep a byte-identity test against the vectors) so the two cannot drift.
- `PublishOne` is additive; existing clients and hubs are unaffected. Commands larger than one
  frame (long prompts, images) still need streaming `Publish`.
- Device signing keys stay outside WebAssembly; a key that signs the wrong bytes is caught before
  sealing, not by the runner.
