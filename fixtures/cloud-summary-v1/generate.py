"""Independent chat summary vectors (ADR 0008). All seeds and nonces are PUBLIC test inputs."""
from hashlib import sha256
from pathlib import Path
from struct import pack
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Cryptodome.Cipher import ChaCha20_Poly1305

ROOT = Path(__file__).parent


def field(value):
    return pack(">I", len(value)) + value


def text(value):
    return field(value.encode())


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


account = X25519PrivateKey.from_private_bytes(bytes([0x31]) * 32)
runner = X25519PrivateKey.from_private_bytes(bytes([0x41]) * 32)
signer = Ed25519PrivateKey.from_private_bytes(bytes([0x51]) * 32)
other_signer = Ed25519PrivateKey.from_private_bytes(bytes([0x52]) * 32)

chat = (field(b"nocterm/cloud-chat-coordinate/v1") + text("hub") + text("acc-1")
        + bytes([2]) * 16 + pack(">Q", 3) + bytes([0x81]) * 16 + pack(">Q", 4))


def context(revision):
    return field(b"nocterm/cloud-summary-context/v1") + field(chat) + pack(">Q", revision)


def summary(revision, full):
    out = field(b"nocterm/cloud-chat-summary/v1") + field(context(revision))
    if full:
        out += b"\x01" + pack(">Q", 5) + bytes([0x84]) * 32
        out += pack(">Q", 11) + pack(">q", 100_000) + pack(">q", 100_500)
        out += text("Deploy the cache — fix ünïcode")
        out += b"\x01" + text("agent-1")
        out += b"\x01" + text("managed") + text("claude-x")
        out += b"\x03" + pack(">H", 2)
        out += b"\x02"
        out += text("db.example.org") + pack(">H", 22) + text("deploy") + b"\x01" + b"\x01" + pack(">q", 200_000)
        out += text("10.0.0.5") + pack(">H", 2222) + text("root") + b"\x02" + b"\x00"
        out += pack(">I", 3)
    else:
        out += b"\x00" + pack(">Q", 0) + pack(">q", 100_000) + pack(">q", 100_000)
        out += field(b"") + b"\x02" + b"\x00" + b"\x01" + pack(">H", 0) + b"\x00" + pack(">I", 0)
    return out


def signed(body, key=signer):
    return field(body) + key.sign(body)


def box(sender, recipient, aad_context, plaintext, ephemeral_byte, nonce_byte):
    ephemeral = X25519PrivateKey.from_private_bytes(bytes([ephemeral_byte]) * 32)
    salt = public(ephemeral) + public(sender) + public(recipient)
    ikm = ephemeral.exchange(recipient.public_key()) + sender.exchange(recipient.public_key())
    key = HKDF(hashes.SHA256(), 32, salt, b"nocterm-cloud-chat-summary-v1/auth").derive(ikm)
    nonce = bytes([nonce_byte]) * 24
    aad = b"nocterm/v1/cloud-chat-summary" + text(aad_context.hex())
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return bytes([1, 22]) + public(ephemeral) + nonce + ciphertext + tag


vectors = {
    "context": context(7),
    "publication-id": sha256(field(b"nocterm/cloud-summary-publication/v1") + context(7)).digest()[:16],
    "binding": field(b"nocterm/cloud-relay-binding/v1") + b"\x05" + field(context(7)),
    "summary-full": summary(7, True),
    "summary-minimal": summary(7, False),
}
vectors["signed-full"] = signed(vectors["summary-full"])
vectors["signed-minimal"] = signed(vectors["summary-minimal"])
vectors["sealed-full"] = box(runner, account, context(7), vectors["signed-full"], 0x95, 0x96)
# The routing says revision 7, the runner signed revision 6: a replayed older summary.
vectors["sealed-older-inside"] = box(runner, account, context(7), signed(summary(6, True)), 0x95, 0x96)
# Signed by a key that is not the pinned runner signing key.
vectors["sealed-other-signer"] = box(runner, account, context(7), signed(summary(7, True), other_signer), 0x95, 0x96)
for name, data in vectors.items():
    (ROOT / f"{name}.hex").write_text(data.hex() + "\n")
print(f"Generated {len(vectors)} independent public summary vectors")
