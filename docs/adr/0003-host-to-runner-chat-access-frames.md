# 0003. Host-to-runner chat access frames

Status: accepted

## Context

ADR 0002 binds a runner's provider access to a chat: the hub sends `ChatAccess` ISSUE or
REVOKE (identifiers only) and the host's credential broker mints or revokes that chat's
virtual token (`nvt1_…`, ADR 0001). The runner learns its configuration from a boot document
it reads once from standard input when the host starts it. A chat that starts after the
runner, or a token revoked while the runner keeps serving other chats, cannot reach it that
way. The token must not touch the disk of the host or the runner, must never pass through the
hub, and the private host (writer) and the public runner (reader) are built from different
repositories, so the bytes between them need one contract definition.

## Decision

**A control channel next to the boot document.** The host starts the runner with a second,
private byte channel (a pipe or an inherited descriptor, chosen by the consumer's runner
interface) that stays open for the runner's life. The boot document stays one-shot; every
later chat access travels as a frame on the control channel. The channel is local to the
host's sandbox boundary, created in memory and never backed by a file.

**One canonical frame** (`nocterm_hub_model::agents::ChatAccessFrame`):

```text
u32 BE  body length, at most MAX_CHAT_ACCESS_FRAME_BYTES - 4 (256 bytes per frame in all)
u8      version = 1 (CHAT_ACCESS_FRAME_VERSION)
u8      op: 1 = issue, 2 = revoke
[u8;16] chat id (the bytes behind the hex `chat_id` of the hub messages)
issue only: u16 BE token length (1..=MAX_ACCESS_TOKEN_BYTES = 128), token text
```

A revoke carries no token. The reader refuses with a typed `ChatAccessFrameError` a length
over the limit (before buffering the body), an unknown version or operation, a token that is
not `nvt1_` followed by base64url, a truncated frame and bytes after the last field. After an
error the decoder stays failed and the runner closes the channel: a stream that lost its
framing is not resynchronised by guessing. `ChatAccessDecoder` buffers at most one frame in a
buffer allocated once at its bound and wiped after each frame; `ChatAccessToken` is zeroized on
drop and redacted in `Debug`; `encode` returns a zeroizing buffer.

**Semantics.** ISSUE replaces any token the runner holds for that chat; the runner uses it
only for that chat's requests to the broker. REVOKE makes the runner forget the chat's token
at once; the broker has already stopped honouring it, so a lost or late REVOKE cannot extend
access. Revocation is enforced by the broker, the frame only frees the runner's copy. Stopping
a lease ends the runner and closes the channel, which revokes every token without a frame.
Frames are idempotent: a repeated ISSUE or a REVOKE of an unknown chat is not an error.

## Consequences

- Chats can start and end while a runner keeps running, without a restart and without a
  token on disk or through the hub.
- A future change of layout is a new version byte; a reader that does not know it refuses the
  frame instead of misreading it. The version is not negotiated: a host writes a version its
  runner reads, and a runner that meets another one closes the channel.
- The contract defines bytes and bounds only. Creating the channel, its descriptor number and
  the runner's use of the token belong to the consumers (the desktop runner's managed
  interface and the private host).
