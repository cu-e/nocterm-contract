# Independent chat summary vectors

Run `python3 generate.py` with Python cryptography and pycryptodomex. It uses no Rust or
private server implementation. All repeated-byte seeds and fixed test nonces are public fixture
inputs; production sealing uses operating-system randomness for ephemeral keys and box nonces.

The 10 files cover a `SummaryContext` (revision 7 of chat `81…` at key epoch 4, runner `02…`
at key epoch 3, namespace `hub`/`acc-1`), its publication id and relay binding (kind 5); a full
summary (head, model, managed host, waiting approval, two bound servers, both feature bits) and
a minimal one (no records, own runner, idle), each as signing bytes and as signed framing under
the runner signing key `0x51…`; and three purpose 22 boxes from runner encryption key `0x41…` to
account key `0x31…`: the full summary, an older revision (6) sealed under revision 7's routing,
and a summary signed by another key (`0x52…`). Existing purposes 1..21 and fixture families keep
their bytes.

Canonical fields are big-endian with u32 byte-length prefixes, 0/1 option flags, closed numeric
tags and exact EOF (ADR 0008). The signed framing is field(signing bytes) ‖ Ed25519 signature.
Boxes reuse the existing version 1 static+ephemeral X25519 construction: HKDF salt is
ephemeral-public ‖ sender-public ‖ recipient-public, IKM the two shared secrets, info
`nocterm-cloud-chat-summary-v1/auth`; XChaCha20-Poly1305 associated data is
`nocterm/v1/cloud-chat-summary` ‖ u32-length hex of the canonical context.
