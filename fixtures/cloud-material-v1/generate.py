"""Independent public test vectors, Python cryptography + PyCryptodome.
Deterministic secrets/nonces below are test inputs only, never production values.
"""
from pathlib import Path
from hashlib import sha256
from struct import pack
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Cryptodome.Cipher import ChaCha20_Poly1305

ROOT = Path(__file__).parent

def field(data):
    return pack(">I", len(data)) + data

def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def encrypt(key, purpose, label, context, plaintext):
    nonce = bytes(range(24))
    aad = b"nocterm/v1/" + label + field(context.hex().encode())
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    body, tag = cipher.encrypt_and_digest(plaintext)
    return bytes([1, purpose]) + nonce + body + tag

chat = (field(b"nocterm/cloud-chat-coordinate/v1") + field(b"hub") + field(b"account")
        + bytes([2])*16 + pack(">Q", 3) + bytes([4])*16 + pack(">Q", 5))
slot = (field(b"nocterm/cloud-journal-slot/v1") + chat + bytes([2]) + bytes([6])*16
        + pack(">QQQ", 7, 8, 9))
account = X25519PrivateKey.from_private_bytes(bytes([0x11])*32)
runner = X25519PrivateKey.from_private_bytes(bytes([0x22])*32)
ephemeral = X25519PrivateKey.from_private_bytes(bytes([0x33])*32)
A, R, E = public(account), public(runner), public(ephemeral)
chat_key = bytes([0x44])*32
root_key = bytes([0x55])*32
dh = ephemeral.exchange(runner.public_key()) + account.exchange(runner.public_key())
grant_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=E+A+R,
                info=b"nocterm-cloud-chat-runner-key-v1/auth").derive(dh)
grant = encrypt(grant_key, 10, b"cloud-chat-runner-key", chat+A+R, chat_key)
grant = grant[:2] + E + grant[2:]
vectors = {
    "chat-context.hex": chat,
    "slot-context.hex": slot,
    "account-wrap.hex": encrypt(root_key, 9, b"cloud-chat-account-key", chat, chat_key),
    "runner-grant.hex": grant,
    "journal.hex": encrypt(chat_key, 13, b"cloud-native-journal", slot, b"independent journal fixture"),
}
signer = Ed25519PrivateKey.from_private_bytes(bytes([0x66])*32)
body = b"private signed transcript"

def record_context(event_id=bytes([0x77])*16):
    return (field(b"nocterm/cloud-record-context/v1") + field(chat)
            + pack(">QQQQ", 9, 10, 11, 12) + event_id + b"\x01"
            + bytes([0x88])*16 + pack(">Q", 13))

def signed_record(kind, context, payload=body, signature=None):
    header = (field(b"nocterm/cloud-record/v1") + bytes([kind]) + field(context)
              + public(signer) + pack(">I", len(body)) + sha256(body).digest())
    signature = signer.sign(header) if signature is None else signature
    return field(header) + field(payload) + signature

context = record_context()
vectors.update({
    "event.hex": encrypt(chat_key, 11, b"cloud-runner-event", context, signed_record(1, context)),
    "snapshot.hex": encrypt(chat_key, 12, b"cloud-runner-snapshot", context, signed_record(2, context)),
    "event-invalid-signature.hex": encrypt(chat_key, 11, b"cloud-runner-event", context,
                                            signed_record(1, context, signature=bytes(64))),
    "event-altered-payload.hex": encrypt(chat_key, 11, b"cloud-runner-event", context,
                                         signed_record(1, context, payload=b"altered signed transcript")),
    "event-wrong-inner-context.hex": encrypt(chat_key, 11, b"cloud-runner-event", context,
                                             signed_record(1, record_context(bytes([0x99])*16))),
    "event-wrong-inner-kind.hex": encrypt(chat_key, 11, b"cloud-runner-event", context,
                                          signed_record(2, context)),
})
for name, data in vectors.items():
    (ROOT/name).write_text(data.hex()+"\n")
print("Generated", len(vectors), "independent Cloud material vectors")
