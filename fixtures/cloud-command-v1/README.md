# Cloud command box v1 fixed vectors

Generated independently with Python `cryptography` (X25519, Ed25519, HKDF-SHA256)
and PyCryptodome (`pycryptodomex`, XChaCha20-Poly1305). Regenerate with
`python3 fixtures/cloud-command-v1/generate.py`; the Rust tests read only the
committed hexadecimal fixtures and do not require Python packages.

All deterministic seeds and nonces are public test data. Account seed starts at
0x10, runner at 0x40, ephemeral at 0x60, device at 0xa0; each contains 32
consecutive bytes. The nonce is 24 consecutive bytes from 0x80. Alternative
negative fixtures intentionally reuse those test inputs. Production sealing
always obtains a fresh random ephemeral secret and nonce.

`header.hex` and `plaintext.hex` pin the exact canonical layout and device
signature. `valid.hex` pins the complete account-authenticated box. Negative
fixtures have correctly computed account boxes but invalid device signatures,
payload binding or repeated inner identities, or intentionally use an old KDF
label/wrong associated-data purpose. They establish that successful AEAD
opening alone cannot substitute for the inner validation.

`namespace.hex` pins the full authenticated hub namespace hash; its raw instance
id is `hub-1` and its trusted authority fingerprint is 32 bytes of 0x31.

These vectors do not establish replay admission, execution grants, origin-token
liveness or semantic command payload validity.
