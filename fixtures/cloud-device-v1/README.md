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
