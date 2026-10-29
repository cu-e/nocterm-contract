# Independent native chat-head vectors

Run `python3 generate.py` with Python cryptography and pycryptodomex. The eight
vectors come from an independent Python implementation. All fixed seeds, keys,
plaintext and nonces are explicitly public fixture data. Production sealing uses
fresh operating-system randomness through the existing seal primitive.

`context` and `context-no-writer` use exact known namespace/account fingerprint,
real chat ID, R coordinate and positive metadata revision. Optional current writer
has a strict 0/1 flag, with a positive u64 only when present. All integers are big
endian; text has u32 byte-length prefixes; a suffix or unknown flag is refused.
The complete canonical context is bounded by 512 bytes.

The root key is HKDF-SHA256 over the exact public test R identity seed. Salt is
SHA256(canonical coordinate || actual R encryption public key), and info is
`nocterm-cloud-native-chat-head-key-v1`. The existing XChaCha20-Poly1305 seal format
uses purpose18, label `cloud-native-chat-head`, and the hex context as its single
length-prefixed associated-data part. `wrong-purpose` is a valid purpose15 box
under the head-derived key/context, demonstrating strict purpose separation.

The nonempty opaque plaintext is a test string, not a public serializer for any
private native format. Content key epoch, actual head anchors and state belong
in the separately versioned native cell supplied by its owner. No ChatKey or
account root/private key is required. None of these vectors establishes storage
freshness, complete catalog membership, an acquired writer or execution authority.
