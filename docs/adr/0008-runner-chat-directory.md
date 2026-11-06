# 0008. A runner chat directory of signed summaries

Status: superseded by [0015](0015-trusted-hub-runs-agents.md).

Extends [0007](0007-device-flows-resumable-reader-and-freshness.md) (its `ListChats` flow) and
[0006](0006-cloud-chats-on-a-browser-device.md).

## Context

A device lists chats from the runner's catalog witness (ADR 0007): fresh heads and control
revisions, no title, no time, no model, no state. Everything a person recognises a chat by is
inside the encrypted records, so the web panel replayed every chat once to find its title, and
the native client named rows `"{host} · {id}"` without a time. A sleeping seat answers no probe
at all, so its chats were not even listed.

Only the runner sees a chat's plaintext and orders its events; the hub sees ciphertext and
routing. Metadata for a list must therefore come from the runner, readable by the account's
devices and not by the hub, and must not need any chat key or replay.

## Decision

**A summary per chat, signed by the runner and sealed to the account.**
`nocterm_hub_model::cloud::summary::ChatSummary` (format 1) carries the newest record (head
sequence and ciphertext digest), the control revision, created and last-activity times, a title
(the first non-empty line of the first accepted prompt, at most 120 bytes cut at a character
boundary, `title_from_prompt`), the host (`Managed{agent_id}` or `Own`), the last model
`{provider, model}`, a closed state (`idle`, `running`, `waiting_approval`, `needs_grant`,
`needs_provider`, `needs_ssh`, `failed`, `deleted`), the pending approval count, up to 16 bound
servers `{host, port, user, state, valid_before_ms}` (empty until per-chat SSH binding, ADR
0009) and runner feature bits (1 SSH binding, 2 own provider lease; readers ignore unknown bits).
It is signed under a `SummaryContext{chat coordinate (namespace, runner, chat, key epoch),
revision}`: the signed body is at most 2048 bytes, the label `nocterm/cloud-chat-summary/v1`.
`RunnerSigningKey::attest_summary` signs; `nocterm_keys::cloud::seal_summary` seals the signed
framing with the existing static+ephemeral box from the runner encryption key to the account
public key (purpose 22, HKDF info `nocterm-cloud-chat-summary-v1/auth`, the context as
associated data, at most 2190 bytes); `open_summary` opens it under the device's runner pins and
the routing context, and checks the signature and that the runner signed exactly that context.
No chat key is involved, so a deleted chat's summary stays readable. The title is derived by the
runner; there is no rename and no new command purpose. Chats from before a runner publishes
summaries are backfilled by it.

**A directory stream on the hub (capability bit 256).** `CloudSelector.directory = 5`
(`CloudRunnerDirectory{}`) names a runner's directory; relay kind 5 `Summary` carries the
`SummaryContext` in clear routing; the publication id is
`SummaryContext::publication_id` (SHA-256 of a label and the context, first 16 bytes), so a
retry of a revision is idempotent. Only the exact runner publishes summaries, only to its own
directory; devices replay and watch, never publish or acknowledge. The hub keeps the summary
with the highest revision per (directory, chat) and marks every other one purged, so storage is
O(chats) and replay has cursor holes, never a gap. A runner publishes only to a hub that offers
`CLOUD_FEATURE_CHAT_DIRECTORY` (256); an old hub refuses the unknown selector or kind.

**Listing: directory rows, catalog confirmation, no replay.** `ListChats` replays each runner's
directory from the cursor of its sealed checkpoint (`VerifiedDirectory`, a `CheckpointKey` under
`nocterm/cloud-device-directory/v1` and the runner's coordinate and pins) and probes its catalog
at the same time. A directory record is read only from the pinned runner's publisher identity,
for this runner generation and namespace, with the announced length and digest; otherwise the
round ends and the cursor stays. Records are independent, so a summary that does not open from
the pinned runner to this account under its routing, an older revision than the one held
(`Rollback`: the hub replayed an old summary) or a second summary at a held revision
(`SummaryConflict`) is skipped, never applied, and reported. Rows merge as: `Current` when the
summary reaches the runner's fresh witness (same key epoch, sequence and control revision not
behind, the same digest at an equal sequence); `Stale` when the witness is newer;
`Unsummarized` for a witnessed chat without a summary; and for a summary the runner did not
witness, `Pending` while the probe is out, `AsOf` (shown as of its last activity) when the
runner did not answer, and `Unlisted` when its complete catalog does not list the chat. A
watching listing keeps a Watch on each directory and reads new summaries live; the catalog is
never probed periodically. Without bit 256 the rows are the catalog's alone (`Chat · 02c073`).

## Consequences

- A list needs one directory replay of new summaries and one catalog probe per runner; no chat
  is replayed, and a sleeping seat's chats are listed with their last known state, labelled.
- The hub learns chat ids and when their summaries change, which it already sees from stream
  activity (`ListStreams`), and nothing of their content.
- The hub can withhold summaries or serve older ones: an older revision never replaces a newer
  one a device verified, and while the runner is awake the catalog witness shows a withheld or
  stale summary as `Unsummarized` or `Stale`. A summary proves nothing beyond what its runner
  signed and grants nothing.
- A new chat or server state needs summary format 2; format 1 readers refuse it and fall back to
  the catalog row.
- The runner (desktop P5) derives, coalesces and publishes summaries; the hub (server P4) keeps
  the latest per chat; both build on this contract revision.
- Independent vectors and their generator are in `fixtures/cloud-summary-v1/`.
