# Cloud material v1 fixed vectors

Generate with `python3 fixtures/cloud-material-v1/generate.py` using Python
`cryptography` and `pycryptodomex`. Rust tests consume only the hexadecimal files.
Public deterministic seeds, keys and nonces exist only for independent tests;
production obtains fresh randomness for every key, ephemeral pair and nonce.

The fixtures pin canonical chat/slot contexts, the purpose9 account-root wrap,
purpose10 account-authenticated runner grant (distinct HKDF label), and purpose13
native journal encryption. Coordinates bind namespace/account/runner/chat and key
generations; the journal also binds storage class, slot ID, sequence, transaction
revision and writer epoch. Public context bytes contain no plaintext payload.

Event/snapshot fixtures additionally pin purposes11/12 and the canonical
runner-signed record. Negative fixtures have valid AEAD but an invalid signature,
altered body or mismatched repeated context/kind, so possession of a content key
alone cannot forge a pinned runner record. The payload digest is encrypted.

These are encryption/authentication vectors. They establish neither first-pin
trust, replay admission, storage durability nor protection from restoring an
older valid database. Journal slots and network records remain separate purposes.
