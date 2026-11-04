"""Independent per-chat SSH binding vectors (contract ADR 0009). All seeds are PUBLIC test inputs."""
from hashlib import sha256
from pathlib import Path
from struct import pack
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parent


def field(value):
    return pack(">I", len(value)) + value


def text(value):
    return field(value.encode())


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


ca = Ed25519PrivateKey.from_private_bytes(bytes([0x91]) * 32)
subject = Ed25519PrivateKey.from_private_bytes(bytes([0x55]) * 32)

chat = (field(b"nocterm/cloud-chat-coordinate/v1") + text("hub") + text("acc-1")
        + bytes([2]) * 16 + pack(">Q", 3) + bytes([0x81]) * 16 + pack(">Q", 4))
ISSUED = 1_800_000_000_000
DAY = 24 * 60 * 60 * 1000
HOUR = 60 * 60 * 1000
db = sha256(b"profile-db").digest()[:16]
cache = sha256(b"profile-cache").digest()[:16]

binding = (field(b"nocterm/cloud-ssh-binding/v1") + field(chat)
           + bytes([0x33]) * 16 + pack(">Q", ISSUED)
           + pack(">q", ISSUED) + pack(">q", ISSUED + 7 * DAY)
           + public(ca) + b"\x02"
           + db + text("db.example.org") + pack(">H", 22) + text("deploy") + bytes([0xa1]) * 32
           + cache + text("10.0.0.5") + pack(">H", 2222) + text("root") + bytes([0xa2]) * 32)
signed = field(binding) + ca.sign(binding)
request = (field(b"nocterm/cloud-ssh-request/v1") + bytes([0x44]) * 16 + field(signed)
           + public(subject) + b"\x02" + text("203.0.113.7/32") + text("2001:db8::1")
           + b"\x01" + db + pack(">q", ISSUED + 8 * HOUR))
access = (field(b"nocterm/cloud-ssh-access/v1") + bytes([0x33]) * 16 + pack(">Q", ISSUED)
          + b"\x02" + bytes([0x44]) * 16 + pack(">q", ISSUED + 8 * HOUR)
          + b"\x02" + db + b"\x01" + cache + b"\x02")

for name, value in {
    "ca-public": public(ca),
    "subject-public": public(subject),
    "server-db": db,
    "binding": binding,
    "signed-binding": signed,
    "request": request,
    "access-active": access,
}.items():
    (ROOT / f"{name}.hex").write_text(value.hex() + "\n")
