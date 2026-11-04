# Cloud device account records, version 1

`desktop-*.txt` are `key=value` vectors produced by the native client's own encoders (the
`nocterm-hub-io` codecs of hub trust, the runner registry, chat material and chat grants at
nocterm commit `9280052`), run once from a throwaway test that is not part of either repository.
All inputs are public repeated-byte test values; the wrapped key and grant ciphertext are opaque
filler, since these vectors pin the layouts, not the cryptography.

`nocterm-cloud-device` re-implements the layouts from the format (ADR 0006) and its record tests
must reproduce every output byte for byte:

- `desktop-hub-trust.txt`: context, collection id and plaintext of `hub-authority-v1`, and the
  derived namespace and authority fingerprint;
- `desktop-runner-registry.txt`: context, collection id and plaintext of `trusted-runners-v1`
  with two runners (one non-ASCII label) at version 2;
- `desktop-chat-material.txt`: the chat coordinate, the material and grant collection ids, the
  shared object id, and the material and grant plaintexts.

Changing any of these bytes is a format change for every client.

`web-session.json` is a recorded browser session over the device flows (ADR 0007) for the
bindings (`nocterm-keys-wasm` `cloud`) and the web panel's tests of the real wasm module. It
belongs to the panel's public test keyset (`acc-1`, login password `correct horse battery` of
`alice` on `hub-1`) and holds what an effect executor needs to replay the session without any
key but the device seed: the Store rows (`collections` with their wrapped keys and `objects`:
two hub-trust records, one for another hub; the registry with one seeded runner; the chat's
wrapped key), the capability proof answering the seeded nonce (`capabilities`, by nonce),
the runner's sealed witnesses (`probeReplies`, by probe id), and the chat's six sealed event
records (the device's prompt, run status, assistant text, the public `approval` vector of
`cloud-events-v1`, usage and waiting status) with one `later` record that arrives by Watch.

Probe ids and the capability nonce come from `nonceSeed` (a `testing` build's
`CloudDevice.connectSeeded`), so a replay must start the flows in the recorded `order`:
`connectSeeded(rawHub, null, nonceSeed)`, `listChats()`, `openChat(chat.chatId)`, then
`openChat(chat.chatId, checkpoint)` with the first open's checkpoint. A probe whose id has no
recorded reply is answered `unavailable` (a sleeping seat: the read is `unconfirmed`).
Collection, account-material and chat keys are random and the file is regenerated whole
(`cargo test -p nocterm-keys-wasm write_web_session_fixture -- --ignored`); the panel then
takes a copy. Nothing in it is a secret.
