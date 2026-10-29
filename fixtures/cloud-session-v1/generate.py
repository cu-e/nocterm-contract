"""Independent session-v1 additive vectors, reusing existing public Answer6 bytes."""
from pathlib import Path
from struct import pack

ROOT = Path(__file__).parent


def field(value):
    return pack(">I", len(value)) + value


def command(kind, body):
    return field(b"nocterm/cloud-command-payload/v1") + pack(">H", kind) + body


def event(kind, body):
    return field(b"nocterm/cloud-event-payload/v1") + pack(">QQB", 12, 120000, kind) + body


# Existing independent RFC4252/KEX vector, not a private/native implementation.
answer = bytes.fromhex((ROOT.parent / "cloud-payload-v1/ssh-approve.hex").read_text())
prefix = field(b"nocterm/cloud-command-payload/v1") + pack(">H", 6)
assert answer.startswith(prefix)
body = answer[len(prefix):]
# run24 + target(host32,route32,principal-field9,workspace32,auth64) + attempt16,
# nonce32 + window16. Its user-key field and all proof fields remain exact.
common_length = 24 + 32 + 32 + 4 + len(b"alice") + 32 + 64 + 16 + 32 + 16
common = body[:common_length]
user_length = int.from_bytes(body[common_length:common_length + 4], "big")
binding_length = common_length + 4 + user_length
ssh_binding = body[:binding_length]
proof_end = binding_length
for _ in range(3):
    size = int.from_bytes(body[proof_end:proof_end + 4], "big")
    proof_end += 4 + size
proof = body[binding_length:proof_end]
assert body[proof_end] == 1
session = bytes([6]) * 16 + pack(">Q", 7) + common[24:common_length - 64]
local_access = (bytes([0xA1]) * 32 + bytes([0xA2]) * 32 + field(b"local")
                + bytes([0xA3]) * 32 + bytes([0xA4]) * 32 + bytes([0xA5]) * 32)
local_common = common[:24] + local_access + common[-64:]
vectors = {
    "begin-local": command(9, b"\x01\x02" + local_common),
    "begin-ssh": command(9, b"\x02\x02" + ssh_binding),
    "begin-connect-only": command(9, b"\x02\x01" + ssh_binding),
    "authentication-requested": event(12, b"\x02" + ssh_binding + proof),
    "session-established": event(13, common + b"\x01" + session),
    "session-lost": event(13, common + b"\x02" + session + b"\x08"),
    "session-refused": event(13, common + b"\x03\x01"),
}
for name, value in vectors.items():
    (ROOT / f"{name}.hex").write_text(value.hex() + "\n")
print("Generated", len(vectors), "additive session vectors; Answer6 unchanged")
