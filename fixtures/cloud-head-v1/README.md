# Independent read-only head vectors

Run `python3 generate.py` with Python cryptography and pycryptodomex. It uses no
Rust or private server implementation. All repeated-byte seeds and fixed test
nonces are public fixture inputs; production SDK/crypto use operating-system
randomness for one-shot probe IDs, challenges, ephemeral keys and box nonces.

The 28 files cover scope; all three closed query targets and a catalog continuation;
original device signatures; empty/first/final catalog pages; a live chat, deleted
chat and Accepted/Unknown original command receipts; R signatures; both purpose 16
query and purpose 17 reply boxes; and authenticated boxes containing a wrong inner
challenge or invalid inner signature. Existing purposes 1..15 and fixture families
retain their original bytes.

Canonical fields are big-endian with u32 byte-length prefixes, strict optional
flags, closed numeric tags and exact EOF. Scope embeds account/R keys plus known
namespace and runner/key epoch. Queries embed that scope, actual device issuer,
16-byte probe ID,32-byte challenge, i64 finite window and a target. Witnesses embed
the complete original query, observation time and the closed answer. Signatures
are Ed25519 over exact purpose-prefixed body; signed framing is field(body) + 64 bytes.

Catalog root/revision/total, sorted chat IDs, continuation count and exact after
cursor are signed. Head writer is independent of last-event writer. Anchor IDs,
positions, original run and ciphertext digests are descriptive real observations;
a zero-event chat has no anchor. Deleted heads preserve metadata without ChatKey.
No signature or box authorizes an execution effect or produces a fresh catalog.

Boxes reuse the existing version1 static+ephemeral X25519 construction. HKDF salt
is ephemeral-public || sender-public || recipient-public and IKM is the two shared
secrets. Distinct info labels are nocterm-cloud-head-{query,witness}-v1/auth.
Associated data binds the purpose and hex canonical context: scope+probeID for
query, complete original query for witness. Reply encryption reverses sender and
recipient, using R encryption identity and the account public key. The fixture
with another inner challenge still uses the original outer AAD to ensure a valid
box cannot bypass exact pending-query verification.
