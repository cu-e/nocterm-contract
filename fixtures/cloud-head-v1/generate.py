"""Independent canonical/crypto head witnesses. All seeds are PUBLIC test inputs."""
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
device = Ed25519PrivateKey.from_private_bytes(bytes([0x61]) * 32)
scope = (field(b"nocterm/cloud-head-scope/v1") + text("hub") + text("acc-1")
         + bytes([2]) * 16 + pack(">Q", 3) + public(account) + public(runner) + public(signer))
probe = bytes([0x71]) * 16
challenge = bytes([0x72]) * 32


def query(target, nonce=challenge):
    return (field(b"nocterm/cloud-head-query/v1") + scope + text("dev-1") + public(device)
            + sha256(b"access").digest() + probe + nonce + pack(">qq", 100_000, 110_000) + target)


def signed_query(raw):
    return field(raw) + device.sign(raw)


def signed_witness(raw_query, value):
    raw = field(b"nocterm/cloud-head-witness/v1") + field(raw_query) + pack(">q", 100_001) + value
    return raw, field(raw) + signer.sign(raw)


def anchor():
    return (b"\x01" + pack(">QQQQ", 2, 5, 7, 9) + bytes([0x82]) * 16
            + b"\x01" + bytes([0x83]) * 16 + pack(">Q", 2) + bytes([0x84]) * 32)


def head(chat=0x81, deleted=False):
    return (bytes([chat]) * 16 + pack(">Q", 4) + b"\x01" + pack(">Q", 4 if deleted else 3)
            + pack(">Q", 12 if deleted else 11) + bytes([deleted]) + b"\x01" + anchor()
            + pack(">Q", 6 if deleted else 1) + b"\x00")


def box(kind, sender, recipient, context, plaintext, ephemeral_byte, nonce_byte):
    ephemeral = X25519PrivateKey.from_private_bytes(bytes([ephemeral_byte]) * 32)
    salt = public(ephemeral) + public(sender) + public(recipient)
    ikm = ephemeral.exchange(recipient.public_key()) + sender.exchange(recipient.public_key())
    suffix = "query" if kind == 16 else "witness"
    key = HKDF(hashes.SHA256(), 32, salt, f"nocterm-cloud-head-{suffix}-v1/auth".encode()).derive(ikm)
    nonce = bytes([nonce_byte]) * 24
    aad = b"nocterm/v1/cloud-read-only-head-" + suffix.encode() + text(context.hex())
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return bytes([1, kind]) + public(ephemeral) + nonce + ciphertext + tag


targets = {
    "catalog": b"\x01\x00",
    "chat": b"\x02" + bytes([0x81]) * 16 + pack(">Q", 4),
    "receipt": b"\x03" + bytes([0x81]) * 16 + pack(">Q", 4) + bytes([0x85]) * 16 + bytes([0x86]) * 32 + pack(">Q", 10),
    "catalog-next": b"\x01\x01" + pack(">Q", 7) + bytes([0x80]) * 32 + bytes([0x81]) * 16 + pack(">I", 1),
}
values = {
    "empty": b"\x01" + pack(">Q", 7) + bytes([0x80]) * 32 + pack(">I", 0) + b"\x00" + pack(">H", 0) + b"\x00",
    "catalog-first": b"\x01" + pack(">Q", 7) + bytes([0x80]) * 32 + pack(">I", 2) + b"\x00" + pack(">H", 1) + head() + b"\x01",
    "catalog-last": b"\x01" + pack(">Q", 7) + bytes([0x80]) * 32 + pack(">I", 2) + targets["catalog-next"][1:] + pack(">H", 1) + head(0x91, True) + b"\x00",
    "chat": b"\x02" + head(),
    "deleted": b"\x02" + head(deleted=True),
    "receipt": b"\x03\x02" + pack(">Q", 11),
    "receipt-unknown": b"\x03\x04",
}
vectors = {"scope": scope}
for name, target in targets.items():
    raw = query(target)
    vectors[f"query-{name}"] = raw
    vectors[f"signed-query-{name}"] = signed_query(raw)
for name, value in values.items():
    target = "chat" if name in ["chat", "deleted"] else "receipt" if name.startswith("receipt") else "catalog-next" if name == "catalog-last" else "catalog"
    raw_query = query(targets[target])
    raw, signed = signed_witness(raw_query, value)
    vectors[f"witness-{name}"] = raw
    vectors[f"signed-witness-{name}"] = signed
vectors["sealed-query"] = box(16, account, runner, scope + probe, signed_query(query(targets["chat"])), 0x91, 0x92)
chat_query = query(targets["chat"])
vectors["sealed-witness"] = box(17, runner, account, chat_query, vectors["signed-witness-chat"], 0x93, 0x94)
vectors["sealed-deleted"] = box(17, runner, account, chat_query, vectors["signed-witness-deleted"], 0x93, 0x94)
raw, wrong_inner = signed_witness(query(targets["chat"], bytes([0x73]) * 32), values["chat"])
vectors["wrong-inner-challenge"] = box(17, runner, account, chat_query, wrong_inner, 0x93, 0x94)
bad_signature = vectors["signed-witness-chat"][:-1] + bytes([vectors["signed-witness-chat"][-1] ^ 1])
vectors["bad-inner-signature"] = box(17, runner, account, chat_query, bad_signature, 0x93, 0x94)
for name, data in vectors.items():
    (ROOT / f"{name}.hex").write_text(data.hex() + "\n")
print(f"Generated {len(vectors)} independent public head vectors")
