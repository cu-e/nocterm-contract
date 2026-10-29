"""Independent public native head vectors. All seeds/nonces are PUBLIC test data."""
from hashlib import sha256
from pathlib import Path
from struct import pack
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Cryptodome.Cipher import ChaCha20_Poly1305

ROOT = Path(__file__).parent
SEED = bytes([0x41]) * 32
RUNNER = X25519PrivateKey.from_private_bytes(SEED)
PUBLIC = RUNNER.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
PLAINTEXT = b"public native chat-head metadata fixture"
NONCE = bytes(range(24))


def field(value):
    return pack(">I", len(value)) + value


def coordinate(writer):
    return (field(b"nocterm/cloud-native-chat-head/v1") + field(b"hub") + field(b"account")
            + bytes([7]) * 32 + bytes([2]) * 16 + pack(">Q", 3) + bytes([0x81]) * 16
            + (b"\x00" if writer is None else b"\x01" + pack(">Q", writer)) + pack(">Q", 9))


def derive(context):
    return HKDF(hashes.SHA256(), 32, sha256(context).digest(), b"nocterm-cloud-native-chat-head-key-v1").derive(SEED)


def seal(context, key, kind=18):
    label = b"cloud-native-chat-head" if kind == 18 else b"cloud-native-account-catalog"
    cipher = ChaCha20_Poly1305.new(key=key, nonce=NONCE)
    cipher.update(b"nocterm/v1/" + label + field(context.hex().encode()))
    body, tag = cipher.encrypt_and_digest(PLAINTEXT)
    return bytes([1, kind]) + NONCE + body + tag


vectors = {"plaintext": PLAINTEXT}
for suffix, writer in [("", 3), ("-no-writer", None)]:
    coord = coordinate(writer)
    context = coord + PUBLIC
    key = derive(context)
    vectors["context" + suffix] = coord
    vectors["derived-key" + suffix] = key
    vectors["head" + suffix] = seal(context, key)
vectors["wrong-purpose"] = seal(coordinate(3) + PUBLIC, derive(coordinate(3) + PUBLIC), 15)
for name, value in vectors.items():
    (ROOT / (name + ".hex")).write_text(value.hex() + "\n")
print(f"Generated {len(vectors)} independent native chat-head vectors")
