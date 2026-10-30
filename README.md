# nocterm-contract

The protocol and client contract of the [Nocterm](https://github.com/cu-e/nocterm) hub: the wire
format, its generated stubs and the client every Nocterm application uses to talk to a hub.
Clients and hubs depend on this repository, pinned to a commit, so both sides read one definition.

| Crate | Purpose |
| --- | --- |
| `nocterm-hub-model` | identifiers, permissions and the signed proof-of-possession messages |
| `nocterm-hub-proto` | protobuf schema (`proto/`) compiled to prost messages, plus its descriptor set |
| `nocterm-hub-grpc` | tonic client and server stubs generated from the descriptor set |
| `nocterm-hub-client` | hub client: certificate probe and pinning, signed requests, password and OIDC sign-in, the account keyset, relayed streams, token rotation, resumable terminals |
| `nocterm-keys` | device keys (Ed25519), login and unlock key derivation, the key hierarchy, recovery keys, sealed grants |
| `nocterm-keys-wasm` | wasm-bindgen bindings for the web panel: unlock an account (login or vault password), derive the login value (`loginAuth`), seal an agent definition to a pool key, pool fingerprint, runner attestation check |
| `nocterm-link` | pure state machines of the terminal Link: output rings, resume points, exactly-once input |

The protobuf schema is compiled with [protox](https://crates.io/crates/protox), so no system
`protoc` is needed.

## Using it

```toml
[dependencies]
nocterm-hub-client = { git = "https://github.com/cu-e/nocterm-contract", rev = "<commit>" }
```

Pin a commit: the contract is pre-1.0 and changes together with its consumers.

## Compatibility

`nocterm.hub.v1` evolves additively: fields and messages are added, never renumbered or
reused. A breaking change gets a new package version. The client refuses a hub whose protocol
version it does not speak (`ClientError::UpgradeRequired`). The protocol version is 2.

A new service is additive and does not change the protocol version. A hub that lacks one answers
`UNIMPLEMENTED`, which the client reads as "not supported" (for example
`RelayError::Unsupported`). `NodeService.Tunnel` and `RelayService` are such additions;
`SignerService` is reserved for a later release and has no schema yet.

## Keys

The password never leaves the device. Sign-in derives, with Argon2id (64 MiB, 3 passes, 4 lanes)
over a salt bound to the hub and the user name, one master secret and splits it with HKDF-SHA256
under separate labels:

- `auth`, sent to the hub in place of the password;
- `unlock`, which stays on the device and opens the account key.

Accounts that sign in through an identity provider derive `unlock` from a separate vault password
with a random salt. The keyset records which of the two applies (`unlock_kind`), and the client
chooses the derivation from that record. The account key is generated once; it wraps the
account's X25519 private key and the keys of its collections. A recovery key (shown once, 128
bits) wraps a copy of the account key so a forgotten password does not lose the data. All sealed
values are XChaCha20-Poly1305 with the purpose and context in the authenticated data; secrets are
zeroized and never printed. The KDF parameters a hub sends must lie between 64 MiB / 3 passes /
4 lanes and 1 GiB / 16 passes / 16 lanes.

### What the password protects

The hub sees `auth` in clear on every sign-in and uses it as a verifier. A hub, or anyone who
reads its database or traffic, can therefore test password guesses offline at the cost of one
Argon2id run per guess, and a found password yields `unlock`. There is no second stage: against
the hub, the vault is exactly as strong as the password. Use a long password or passphrase; the
minimum length only catches mistakes. The recovery key does not depend on the password. The
hub identifier is reported by the hub itself, so the separation between hubs holds for honest
hubs only.

### Collection keys and trust in other accounts

A personal collection is sealed by the account's own key; a hub cannot substitute it, and the
client opens it only with `Keyset::open_own_collection_key`. An organization collection reaches
a member as a grant: an authenticated box from the granter's static X25519 key and a fresh
ephemeral key to the recipient's public key, with the collection, the recipient and the
granter's key fingerprint in the authenticated data. A grant opens only under the key of the
granter the recipient expects, so the hub cannot make one, and it cannot move one to another
collection or recipient. A grant is not a signature: only the recipient can check it.

Which key belongs to which account is decided by the client: trust on first use with a
fingerprint. The first time a key is met, a person compares its full fingerprint out of band and
the client pins it (`PinnedKeys`); a different key for the account afterwards is an error.
A hub that substitutes a key when it is first met, and is not noticed, controls that account's
grants from then on, so confirm the fingerprint. After the first pin the hub cannot swap the
key, neither of a granter nor of a recipient: `HubClient::grant` and
`Keyset::open_granted_collection_key` accept only a pinned `TrustedKey`.

### Cloud command boxes

`nocterm_hub_model::cloud` defines bounded canonical command headers and device signatures;
`nocterm_keys::cloud::{seal_command, open_command}` authenticates them from the account's
existing X25519 pair to a pinned runner encryption key. The command box uses purpose 8,
a separate HKDF label and authenticated route/key coordinates. Existing collection-grant
bytes and proof-of-possession messages keep their formats.

Runner setup pins the expected account public key on the runner and its encryption/event
keys in the account's own sealed descriptor. A hub directory is not that initial trust.
`hub_namespace_id` derives the routing namespace from the original authenticated instance
id and retained authority fingerprint; display addresses and aliases never enter it.
A later device can use the same account key flow and its own device signature. No shared
command signing key or new device certificate is introduced. As with authenticated grants,
the trusted recipient can forge a box; it is not a third-party account signature.

The entire plaintext, including framing and device signature, is capped at 32 MiB;
identity text is capped at 128 UTF-8 bytes and never normalized. Opened plaintext is
zeroized on drop and omitted from `Debug`. Payload bytes are authenticated without
reserialization, but remain semantically untrusted: a caller must decode the command's
kind, enforce its actual grants/deadlines and durably admit its id before any effect.
Cryptographic opening does not provide replay protection, fresh admission, runner setup,
transport or persisted receipts. `validate_admission_time` is separate so an expired
redelivery can still be matched to an existing journal receipt without repeating work.

The recipient is a purpose-specific `cloud::RunnerEncryptionKey`, restored from
its zeroizing seed in the runner's private identity storage. Restoring it needs
no account root material. A separate fresh instance can be an in-memory boot
recipient; persisting its seed would defeat that boot-only lifetime.

Independent fixed vectors and their Python generator are in `fixtures/cloud-command-v1/`.

### Finite session startup

The optional `CLOUD_FEATURE_SESSION_START` flag (value 32) negotiates additive semantic
command 9 `BeginSession`, event 12 `AuthenticationRequested` and event 13
`SessionState`. Existing command 6 `AnswerSshConsent` and all existing canonical
bytes keep their layouts. The command/event/snapshot labels remain v1 and the
service protocol remains 2; a missing feature or unknown semantic tag refuses
explicitly. Consumers must support the new observation variants before enabling
this feature, including snapshot retention and inverse projection.

`BeginSession` selects Local or SSH and authorizes at most one connection within
the device-issued original run/attempt/nonce window of 1..60 seconds. Startup mode
`ConnectOnly` requests Connection capability; `Terminal` also requests Execution.
A transport that cannot connect without starting a shell refuses ConnectOnly.
Read-only access does not start a connection or PTY. This finite startup request
is separate from session-bound tool grants: it carries no fabricated pre-login
receipt, and successful authentication does not install a tool grant. Local has
no SSH key/proof fields. SSH reuses the exact binding and proof codec from
AnswerSshConsent, with ≤1024-byte public key/host signature fields, ≤4096-byte
userauth and ≤128-byte answer signatures. The native device authorizer must
verify the pinned host's actual initial-session proof and exact userauth action;
wire decoding alone proves neither consent nor target authority.

The original run must already exist. Device consent supplies the attempt/nonce
before the handshake; the runner publishes the actual proof request under that
same run, and the existing signed answer 6 resolves only that original attempt.
`SessionState` describes Established, Lost or Refused with a closed reason and,
where applicable, the actual original session reference. Its target/authentication
must match the original attempt. Historical state never restores a live session,
approval or grant. `seal_payload` also rejects startup expiry beyond the actual
captured device session's hard refresh deadline. Independent additive vectors are
in `fixtures/cloud-session-v1/`; the old Answer6 vectors remain unchanged.

### Per-chat material, records and the native journal

`cloud::ChatKey` generates independent content material for one chat generation.
Its account wrap (purpose9) opens through the normal account root. Its runner
grant (purpose10) uses the account-authenticated static/ephemeral construction
with a distinct HKDF label and the installed account/runner pins. The runner
receives this chat key without account root or vault material. Both bind the
exact namespace, account, runner/key epoch, chat and chat-key epoch.

`seal_event`/`seal_snapshot` and their openers use distinct purposes11/12. The
encrypted plaintext includes the canonical record header, body and Ed25519
signature from the separately pinned `RunnerSigningKey`. Knowing a chat key
does not allow another account device to forge a runner record. Opening checks
the signature, body length/digest, record kind and repeated expected context.
The context distinguishes delivered event sequence, local journal sequence,
transaction revision, writer epoch, event ID and optional run/epoch. Payload
digests remain inside encryption. Keys and opened plaintext omit their contents
from `Debug`; the plaintext owner zeroizes on drop.

`ChatKey::{seal_journal,open_journal}` (purpose13) protects bounded native codec
values, separately binding their storage class, slot ID, journal position,
transaction revision and writer epoch. It is not a network event format.
Classes are closed: header1, record2, command-receipt3, checkpoint4, snapshot5,
outbox6, background-command7, effect8, run-head9. The entire native sealed slot is capped
at 32 MiB + 64 KiB; the entire signed network plaintext is capped at 32 MiB.

These APIs supply neither replay suppression, durable commit, grant enforcement,
key rotation nor antirollback state. Clients must retain trusted heads and
validate gaps/epochs before projection; a freshly signed-in device without a
trusted current runner head cannot establish historical freshness from the hub
alone. A valid older database remains cryptographically valid. Account-level
runner setup, key delivery/storage and record semantic decoders are consumers.
Independent vectors are in `fixtures/cloud-material-v1/`.

## Managed agents

`AgentService` lists, edits and runs agents that execute on pool hosts. The hub stores an
`AgentListing` (name, resources, access, availability) and an opaque envelope per pool; the
definition itself, `nocterm_keys::agents::AgentDefinitionV1`, is sealed by the owner to the
pool's encryption key and opened only on the host. Writes are compare-and-swap on the version
(`AgentError::Conflict` carries the current one); a refused start carries a typed
`RefusalReason`. A pool is pinned by the fingerprint of its two keys
(`nocterm_hub_model::agents::check_pool_keys`); a runner setup document is trusted only with a
host attestation signed by the pinned pool key (`nocterm_hub_client::agents::verify_instance_setup`).
Real provider keys reach only the host's credential broker; the runner holds a virtual token
(`nocterm_keys::agents::VirtualToken`). Servers trust the user's SSH CA through one
`authorized_keys` line (`CaLine`) and receive short-lived `SshCaGrant`s. See
[ADR 0001](docs/adr/0001-managed-agents.md) for the formats and their reasons.

All of it is additive: a hub without `AgentService` answers `UNIMPLEMENTED`, read as
`AgentError::Unsupported`. Receipt reclaim (`retry_until_ms`, capability bit 64, chat deletion
tombstone) is additive too. `CloudClient`/`CloudRunner::supports_receipt_reclaim` reads bit 64;
`begin_publication_with_retry_until` sets the horizon (validated by `validate_retry_until`;
`begin_publication` keeps `0`, no horizon); `CloudRunner::sign_chat_deletion` produces a
`SignedChatDeletion` and `retire_chat` announces it, answering `ChatRetirement { compacted }` or a
typed `RetireChatError` (`Unsupported`, `Namespace`, `Retired`, `Bounds`). The tombstone signature
authenticates the call; no runner session proof is attached.

Access is bound to the chat ([ADR 0002](docs/adr/0002-chat-bound-agent-access.md)):
`StartLease.chat_id`, `NodeDown.chat_access` (`ChatAccess` issues or revokes a chat's broker
token; identifiers only), `NodeHello.agents.running_leases`, and a `model` on `InstanceUsage`
and `UsageRow`.

## Relays

`RelayService.Open` carries a byte stream from the client to a TCP target through the hub, and
`NodeService.Tunnel` carries it from the hub to a fleet node. Frames are at most 32 KiB and each
stream is buffered by 16 frames, so a slow reader slows its writer instead of growing memory.
The caller's `close` is a half-close; the hub's `closed` ends the whole relay, and the writer
then refuses to send. Empty data frames are never sent and are skipped when received, so the end
of the bytes is always explicit.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --target wasm32-unknown-unknown -p nocterm-keys-wasm
```

Minimum supported Rust version: 1.89.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Contributions are accepted under the same terms.

### Opaque Cloud delivery and runner access

The additive `CloudService` keeps protocol 2's existing services intact. Old hubs return
`CloudError::Unsupported`; clients do not reinterpret this as local history. Fresh nonce-bound
capabilities prove possession of the offered authority key. `CloudOffer::accept` requires
an independently retained stable-authority pin; an offered replacement is never trusted
automatically. The hub namespace binds the raw instance id and SHA256 of that authority.

`CloudClient` captures the actual SDK sign-in generation. Logout or replacement login fences
old handles, including returning to the same account; ordinary token rotation keeps them.
`command_invocation()` captures the actual current issuer and hard refresh deadline once.
Its prepared command retains the original signature, nonce and access-token digest on retries.
The historical digest attributes that command; it is not a liveness check against a later bearer.

Delivery streams use a canonical routing-only binding and transport publication id, chunks
of at most16 KiB, a queue of8 frames, explicit finish plus EOF and a ciphertext digest. Logical
envelopes are bounded by32 MiB+78bytes, individual protobuf messages by32 KiB. Delivery ACKs
prove storage at the hub, not runner admission or effects. Borrowed replay records validate
length/digest/end markers before advancing the transport cursor; abandoning a record poisons
that stream. Chat purge atomically requires a durable Snapshot in the same account,
runner/key epoch and chat at exactly `through_cursor + 1`; it becomes the first retained
cursor and gap pointer. Missing, foreign, stale or non-Snapshot anchors cannot change
retention. Recover a chat gap with `Replay(after=retained_from-1, max_records=1)`, check
that first Snapshot's publication ID/context and pinned runner signature, then install the
verified baseline before ACK. RunnerInbox gaps have no snapshot and require durable inbox
recovery or an explicit error. Watch messages are lossy hints.

`CloudRunner` redeems a one-use account-issued ticket with its own proof key. It owns separate
rotating runner tokens and exposes only Cloud relay, heartbeat and retention operations. Its
request signatures use a closed RPC set and a distinct purpose from account-device proofs.
It has no account key, ordinary device session or Store API. Device logout does not stop this
principal; explicit local revoke fences all clones and pending refreshes. Servers must enforce
runner scope and current tokens, consume durable nonces/tickets, reserve upload quotas and
commit receipt/idempotency state; codecs and SDK fixtures do not supply these server duties.
Independent canonical/signature vectors are in `fixtures/cloud-relay-v1/`.

`RunnerSession::from_stored_response` restores private runner storage with live refresh
credentials even after access expires. It preserves the original subject and token bounds;
`from_response` still requires fresh access. Restore never refreshes implicitly: call
`CloudRunner::refresh` explicitly, then durably save that exact returned rotation before
admitting more work. A failed native write must retry persistence rather than rotate again.

`CloudRunner::begin_publication_with_residency` retains the same opaque caller allocation
owner in the upload, actual RPC task and transferred request stream/body, including
asynchronous cancellation when Tonic/Tower retains the body after its response future.
`CloudUpload::buffer_work_bytes(ciphertext_bytes)` bounds SDK-owned logical queue data,
routing/framing scratch and the receipt before starting an upload; callers separately own
their original ciphertext and the retained runtime/connection, Tonic, HTTP/2, TLS and allocator
baseline. It is not a total RSS bound. Use `max_frame_bytes()` from the upload's signed
negotiated limit when producing chunks.

Unary retention has the same ownership requirement: `CloudRunner::purge_with_residency`
retains the caller's allocation in the actual encoded request body, including background
channel queuing after response cancellation. The existing `purge` API remains available.

Both runner and device Cloud clients expose `replay_with_residency` and
`acknowledge_with_residency`. The allocation follows encoded request and response bodies;
the replay object also retains it until its decoded stream state drops. Charge assembled
ciphertext, opened plaintext and native DTOs separately from `CloudReplay::buffer_work_bytes()`.
`cloud::acknowledgement_work_bytes()` describes the guarded unary ACK working bound without
an upload queue. Guarded device signing rejects tokens over1024bytes and hub/device IDs
over128bytes under the same lock used for signing, before cloning them. Existing unguarded
signing policy is unchanged. These are logical SDK buffer bounds, not process RSS or the
Tonic/HTTP2/TLS/runtime/allocator baseline.

### Memory-only provider grants

`RunnerBootKey` creates a fresh non-restorable X25519 recipient. Its API has no seed export,
restore or generic decryption method. The pinned stable `RunnerSigningKey` attests a finite
`BootDescriptor`; verification returns a `VerifiedBootDescriptor` before a device can seal
a provider grant. Purpose 14 uses the existing account-authenticated static+ephemeral box,
with separate HKDF and associated-data labels, exact boot/provider-reference/lease-id/expiry
context and at most16 KiB of secret bytes. The boot key opens it only into a zeroizing owner.
A new boot cannot open a saved ciphertext. This authenticates the account to its trusted
recipient, not to third parties. Native authority still checks replay, clock rollback, grant
revocation and provider/model policy before using the secret. Optional persistent secret
storage is a separate explicit runner policy. Independent vectors are in
`fixtures/cloud-provider-v1/`.

### Semantic commands and approval fingerprints

`cloud::payload::CloudCommandPayload` is the sole canonical semantic codec for all eight
Cloud command purposes. Its closed tags, explicit options, list bounds and one aggregate
plaintext bound apply before content is copied. The decoder borrows prompt/image/capsule
bodies; validation uses the same encoder with a counting sink. Unknown tags, suffixes,
wrong-purpose bodies, zero epochs and mismatched original run/issuer bindings are refused.
Decoding does not verify account trust, consume a grant or durably accept a command.

`CloudCommandInvocation::seal_payload` captures actual SDK attribution, checks header/body
consistency and rejects new authority beyond its captured hard refresh deadline or finite
task window. Inference and terminal grants require an exact run. A boot-bound provider
installation may precede a run; using it still needs a separate inference grant. SSH consent
answers retain their exact attempt, nonce, finite deadline, target, selected key and proof.
The codec bounds standard SSH blobs; the native SSH verifier checks their complete protocol
structure, host signature and permitted purpose before reading a private key.

`cloud::tool_arguments::ToolArguments` hashes the exact typed arguments for the existing
eight terminal tools under a separate canonical purpose. It preserves literal argv
boundaries, ordering, nullable timing/stdin fields and the tool name without depending
on JSON map order. The digest does not replace checking original full arguments, target,
session, run and grant epochs at dispatch. Execution validation belongs to the terminal
catalog. Independent payload/argument vectors are in `fixtures/cloud-payload-v1/`.

### Native account catalog integrity

`cloud::account_catalog::AccountCatalogCoordinate` binds a native catalog to its
known namespace, account, account-key fingerprint, runner, key epoch and positive catalog revision.
`NativeCatalogKey::for_runner` derives a separate metadata key from the exact
runner identity seed, with its own HKDF purpose. Purpose 15 seals at most 2 MiB
under that context; it needs neither an account root nor any chat content key.
Deleting a chat therefore does not require keeping its content key as a catalog
anchor. Independent vectors are in `fixtures/cloud-catalog-v1/`.

Authentication of a catalog does not prove completeness, freshness or database
initialization. Its native owner must explicitly distinguish create-new from
open-existing, require the existing root, atomically maintain membership with
chat creation, compare the full physical row set and retain a high-water mark.
A coherent historical authenticated state after restart cannot be detected
without a separately trusted head. The cipher does not supply that head.

The sole native catalog object may also commit the ordered hashes of protected
per-chat head cells. Its owner must bump and reseal that catalog in the same SQL
transaction as every visible head change, preserving complete row-set checks.
This requires a bounded digest/rewrite of up to 2 MiB per mutation initially;
actual benchmark and deployment limits remain native responsibilities. A second
object must never reuse the same catalog purpose/context for a different root.

`cloud::native_chat_head::NativeChatHeadCoordinate` binds a real chat ID to that
known account/runner source, optional actual current writer and positive metadata
revision. `NativeChatHeadKey::for_runner` derives a distinct native metadata key
from the persisted R identity using purpose18 and a separate HKDF label. Its only
operations seal/open one nonempty head cell of at most 8 KiB; opening returns a
zeroizing owner. It needs neither ChatKey nor the account's private/root key.
The actual installed content-key epoch is an authenticated native plaintext fact;
it must never be copied from the separate R epoch or guessed by a read selector.
Independent context/key/box vectors are in `fixtures/cloud-native-head-v1/`.

The native owner atomically protects current writer/control/tombstone and exact
original event/snapshot anchors, checks configured source pins before constructing
coordinates, and retains metadata high-water marks before content-key or payload
purge. A valid old cell is not proof of current authority. This bounded head cell
does not embed an unbounded lifetime receipt ledger or implement its separate
retention/encryption policy. Missing metadata or a missing requested chat is an
honest refusal/deadline; it must never become a fabricated empty ChatHead.

Anchors carry no separate content-key epoch. A native rotation must publish and
durably retain a signed snapshot encrypted under the new generation before
flipping the active chat-key epoch. It cannot relabel an old anchor as belonging
to a new key. These primitives alone do not implement that atomic rotation.

### Chat-key material bootstrap

Relay binding tag4 routes a purpose10 chat-key envelope through the runner inbox,
separately from all eight command purposes. The additive capability bit 8 must be
offered before the SDK prepares or publishes material; the original version1
feature set7 remains valid for existing peers. Material is limited to256bytes,
not the32MiB command allowance. A runner cannot publish device key grants.

`CloudClient::prepare_chat_key_grant` seals one chat key to the separately pinned
runner from the captured account keyset. Persist the exact coordinates, publication
ID and ciphertext in the authenticated account-owned collection/outbox before
sending. `stage_chat_key_grant` captures a new sign-in for that unchanged envelope;
its caller must first authenticate the account-owned record. It does not verify
the encrypted key. The runner alone opens purpose10 against its configured account
pin and exact chat/key epoch, then conditionally installs material. Material does
not accept a prompt, spend tokens, open SSH or grant execution authority. The hub
cannot read the chat key, and the runner never needs the account root/Store client.

These SDK methods provide transport and encryption, not the native collection
store, key-cache durability or rotation policy. A missing key must stop command
admission before its receipt/run/effects. Repeated installed coordinates must
reuse their original sealed blob; a different blob or key epoch must not silently
replace an active journal key. Native app composition and explicit retirement/
rotation remain consumer responsibilities.

### Semantic runner observations and snapshots

`cloud::events::CloudEvent` is the sole event-body codec. It carries the original
control revision, publication time and one of eleven closed semantic observations;
`CloudEventPayload` is their descriptive vocabulary. Native transaction revision
remains in `RecordContext` and must not replace control revision. A background
observation can advance delivery and journal positions without changing control.
Publication time comes once from an injected producer clock before signing, is
within 1..=i64::MAX milliseconds since the epoch, and is reused on outbox retries.
It is neither command issue time nor a job's creation/deadline. Text progress
keeps an optional real model StepId; a missing identity stays absent.

Decoding borrows text, JSON and image bodies, checks closed tags and exact EOF,
and shares one 32 MiB aggregate bound. Text fields are at most 1 MiB, JSON fields
at most 4 MiB, and a snapshot contains at most 4096 observations. JSON remains
presentation, while tool identities/digests come from the existing eight-tool
canonical arguments. Background observations bind their exact original intent
and execution run. Unknown usage/cost remains absent, separately from zero.

A snapshot carries its own current control/time head, even if its display window
is empty. Included observations have nondecreasing control/time no newer than
that head. Their historical runs can differ from the outer snapshot record's
current run; they never supply new execution authority. `omitted_earlier` states
that history was trimmed. Consumers still verify the pinned runner, expected
chat/key/writer context, retained head and replay order before replacing a
projection. This codec neither publishes snapshots nor implements recovery.

The version1 semantic layout is additive to the existing opaque Event/Snapshot
record framing and protocol 2 services; existing required capability bits are
unchanged. Peers that do not implement these semantic labels must refuse them
explicitly. Independent public vectors are in `fixtures/cloud-events-v1/`;
they do not contain native Postcard or private server data.

Accepted-prompt observations use `AcceptedPrompt`: bounded content, model and
optional original target/session only. They do not repeat inference budgets or
restore grant authority. Full command `PromptPayload` retains its independently
signed calls, turns, byte/token limits, spend and task deadline.

Approval choice5, `ReconcileKnown { result_digest }`, preserves the exact original
result fingerprint as a signed declaration. It neither supplies a missing result
body nor proves an observed success. Legacy choices3/4 retain their old bytes;
consumers supporting fingerprint reconciliation must explicitly refuse those
boolean declarations instead of inventing a digest or ToolResult.

Event tag11 is `BackgroundLifecycle`: the original job/intent/execution, actual
step, arguments digest, mutation classification, dispatch writer and per-run
revision, plus Retained, ObservedExit(status) or Unknown. The current publication
writer/position are separate, so a cleanup observation keeps its original run.
It needs no fabricated call/display/output and restores no DispatchPermit. Its
optional job window is present only when real native timing was supplied.


### Fresh read-only runner heads

Optional capability 16 enables `ProbeHead`, `NextHeadProbe` and `ReplyHeadProbe`.
Required capability bits 7 and chat-material bit 8 are unchanged; an older hub
returns explicit unsupported. Only a normally authenticated device sends a probe;
R request proofs allow its two receive/reply methods, never device or Store access.
The hub routes bounded opaque messages and never creates the witnessed metadata.

`cloud::head` defines separate version1 query/witness purposes. The original query
binds exact namespace, account/R encryption and signing pins, actual device issuer,
OS-generated 16-byte probe ID, 32-byte challenge, finite window and a closed target:
account catalog page, exact chat head, or exact original CommandId/digest receipt.
A capability proof or self-signed directory entry establishes none of these pins.
The caller supplies independently retained pins; first trust remains explicit.

R opens the account-authenticated, device-signed query and obtains actual native
authenticated metadata through a read-only port. `RunnerSigningKey::attest_head`
signs only the dedicated witness layout. Purpose 16 seals queries account-to-R;
purpose 17 seals signed witnesses R-to-account using existing static+ephemeral
X25519/HKDF/XChaCha20-Poly1305. Replies use the account public key, not a ChatKey,
so deletion can retain a verifiable tombstone after chat-content key retirement.
No generic signing or decryption API, grant, journal append, model call, SSH login
or control-revision increment is part of this exchange.

Cold history starts with the actual complete account catalog: its revision/root,
total count, sorted page and continuation cursor are bound by R's signature.
Subsequent pages repeat that exact root/revision and count; a changed catalog
requires a fresh pagination attempt. The native producer must authenticate the
full membership and current/deleted per-chat metadata independently of content
keys. A catalog digest is not an event-tail hash relabelled as a Merkle root.
A coherent rollback of R's own authoritative storage still needs an independently
trusted anchor; these witnesses address a hostile relay serving old device history.

`ChatHead` separates current writer from last-event writer and preserves actual
last-record and retained-snapshot IDs, positions and ciphertext digests. Empty
chats have no invented event; deleted heads never authorize resurrection. A
consumer verifies complete catalog pages, the exact retained snapshot anchor and
contiguous signed events through the witnessed head before publishing a cold
projection. A witness does not itself supply that baseline, material or history.
Command-receipt targets are closed read-only NotFound/Accepted/Conflict/Unknown
observations from R's original durable ledger, without admitting another command.

`CloudClient::head_probes` captures the actual original SDK login before waiting.
Prepared probes are one-shot, with real random ID/challenge and a monotonic hard
deadline; the completed owner repeats source/deadline checks before and after
opening against the exact pending query. The wait retains no account keyset.
A replacement login, old nonce, altered scope/key or backwards/expired device
clock cannot publish a witness. Native callers inject their actual clock and
repeat their own retained membership fence before projection publication.

`head_probes_with_residency` on device and runner ports retains a caller's actual
pre-admitted allocation through request/response Body ownership and through
Prepared/Incoming/Completed destruction. `open_resident` returns borrow-only
`ResidentHeadQuery`/`ResidentHeadWitness` owners with the same allocation last;
there is no consuming unguarded extraction, Deref or Clone on those owners.
The existing `open` refuses a guarded object; default unguarded ports retain their
original behavior. Explicit clones of borrowed contents and native publication
remain separately admitted generations with their own source checks.

Before creating a guarded port, admit one operation's `head_query_work_bytes()` +
`head_reply_work_bytes()` + `head_decoded_metadata_bytes()`. These name concrete
logical SDK canonical/signature/AAD/body buffers and bounded decoded metadata;
they exclude caller original ciphertext/native clones, witness signing/sealing,
curve/hash stack and Tonic/HTTP2/TLS/runtime/allocator/connection baseline. They
are not process RSS bounds. Each concurrent operation needs its own admission;
an opaque shared Arc proves retention, not capacity. Guarded device attribution
and request signing bound actual metadata under their credential read locks
before cloning, retaining the same original membership across conditional refresh.

Canonical bodies are at most 2 KiB(query)/30 KiB(witness), including bounded 64-chat
pages. Signed framing adds 68 bytes; authenticated boxes add 74 bytes. SDK transport
also counts canonical scope and a conservative 128 bytes for complete protobuf
framing/ID/window against 4 KiB(query)/32 KiB(reply). The existing 32 KiB tonic message
cap remains unchanged. The hub must enforce 32 pending probes/account, 256 global,
10 seconds maximum lifetime, bounded polls and cancellation cleanup. These public
SDK/codec primitives do not implement production server policy or native storage.
Independent canonical/signature/box/tamper vectors are in `fixtures/cloud-head-v1/`.

### Loading an exact durable command

`CloudClient::stage_stored_command` captures a fresh actual SDK source around an
unchanged command publication loaded from an authenticated native outbox. It
checks command-only route, current namespace, ciphertext length and SHA-256. The
native caller must first authenticate its persisted account/R/chat binding and
original metadata; the SDK cannot open R's encrypted command. The semantic digest
is exactly SHA256(CommandHeader.canonical_bytes()), matching native acceptance;
it is neither a ciphertext digest nor a hash of the entire signed message. The
caller must authenticate this value with the native outbox. Staging never
re-signs/reseals M, changes its issuer/deadline, replaces its original IDs or turns
a delivery ACK into R admission. Persist the exact publication before sending,
then retry those same bytes or query the same original ID/digest. Expired new
admission and previously accepted idempotent receipt lookup remain R's duties.

`CloudEvent` and `CloudSnapshotPayload` expose `canonical_len()` for preflight and
`canonical_bytes_exact(length)` to encode into an admitted single output buffer.
Nested tool arguments reuse that sink without another encoded buffer; JSON
validation may still use parser scratch, so this is not an allocation-free API.


### Guarded acquisition and account Store

`HubClient::cloud_offer_with_residency` checks actual bounded account/device/token
metadata under the credential lock before attribution cloning and uses the sole
resident channel for request and response bodies. Its generated client has a
closed 1 KiB protobuf limit before decoding the at-most 512-byte canonical claim
and 64-byte signature. Source generation, original nonce and pinned acceptance
rules are unchanged. Legacy `cloud_offer` retains its original behavior.

Pre-admit `cloud::capability_work_bytes()` before fetching. The returned CloudOffer
retains that owner last; default `accept` preserves it in CloudClient. Native
callers can pre-admit `cloud::capability_resident_bytes()` and use
`accept_with_residency(pin, small_owner)` before namespace/subject copies. The old
work owner stays on the offer and any outstanding actual body until Drop; the
small owner follows the returned immutable Arc-backed metadata and every shallow
CloudClient clone; the final clone drops that one physical metadata generation
before releasing its owner. Explicit descriptor/value clones are separately
admitted caller generations. No consuming unguarded
extraction or accepted pin derived from the offered directory key is added.

`HubClient::store_with_residency(owner, max_message_bytes)` returns the generated
`ResidentStoreClient` using the same body-retaining channel and bounded original
source signer. Both encoding and decoding use the explicit limit, from 1 byte to
4 MiB. Its signer permits only the closed unary Store RPC set; WatchChanges and
other services are refused. The public channel/signer names only make the service
alias usable; their constructors are private and no generic signer is exposed.
Default `store()` remains available with its prior policy.

`store_work_bytes(limit)` names body/proof/fixed SDK work. The caller validates
request encoded length before RPC and separately admits original request values,
protobuf decoded containers, native crypto and outputs, retaining the exact same
guard through those generations. A small wire limit is not a decoded object-count
limit: repeated empty records still allocate their typed container/slot capacity.
These logical SDK bounds exclude Tonic/HTTP2/TLS/runtime/allocator/connection
baseline and do not promise process RSS. No implicit credential refresh is hidden
in either factory; a captured native auth owner separately owns refresh policy.

HubClient shares immutable HubInfo through Arc, so cloning does not duplicate its
OIDC/provider rows. `require_cloud_metadata` performs a no-copy current metadata
check; `account_subject` clones only bounded account/device IDs under one session
read lock, never bearer or refresh tokens. Neither descriptive check establishes
native membership or remote authorization. Native callers retain their original
membership, reject replacement sources after awaits and never replace a read-lock
bound with a check-then-unbounded `session()` token clone.

### Guarded runner status and scheduling

`CloudRunner::heartbeat_with_residency` and
`CloudClient::runner_status_with_residency` use the existing bounded signed RPC
transport. Reserve `cloud::status_work_bytes()` from the caller's actual finite
pool before creating the request. This names logical proof/body/decoded-status
working memory, not total Tonic/HTTP2/TLS/runtime RSS. Status bytes are at most
4096; the guarded wire ceiling is applied before protobuf response decoding.
The returned `ResidentRunnerStatus` exposes borrowed data and retains that same
owner until its actual final drop. Copying borrowed status requires separate
caller admission. `received_at_ms` is a hub diagnostic, never signed freshness.

`CloudRunner::credential_deadlines` reads only current access/refresh deadlines
under the credential lock. It clones no session or token and grants no RPC
permission. Expired access can still be observed for explicit refresh planning;
a locally retired or refresh-expired source refuses. Heartbeat/status operations
still recheck their captured source after awaits; no automatic refresh or device
session authority is added to a runner.
