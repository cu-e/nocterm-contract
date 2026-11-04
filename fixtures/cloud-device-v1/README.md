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

`web-session.json` is a recorded browser session for the bindings (`nocterm-keys-wasm` `cloud`)
and the web panel's tests of the real wasm module. It belongs to the panel's public test keyset
(`acc-1`, login password `correct horse battery` of `alice` on `hub-1`) and holds: two hub-trust
records (one for another hub), a capability proof by a seeded authority key, the registry with one
seeded runner, a catalog and a chat witness answering probes with fixed probe ids and challenges
at a fixed time (`now`), the chat's wrapped key and six sealed event records (the device's
prompt, run status, assistant text, the public `approval` vector of `cloud-events-v1`, usage and
waiting status). Collection, account-material and chat keys are random and the file is
regenerated whole (`cargo test -p nocterm-keys-wasm write_web_session_fixture -- --ignored`);
the panel then takes a copy. Nothing in it is a secret.
