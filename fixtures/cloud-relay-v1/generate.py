"""Independent canonical relay/auth vectors; public deterministic test inputs only."""
from pathlib import Path
from hashlib import sha256
from struct import pack
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parent
def field(value):
    return pack(">I", len(value)) + value
def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

authority = Ed25519PrivateKey.from_private_bytes(bytes([0x91])*32)
runner = Ed25519PrivateKey.from_private_bytes(bytes([0x72])*32)
namespace = sha256(field(b"nocterm/cloud-hub-namespace/v1") + field(b"hub-test") + sha256(public(authority)).digest()).hexdigest().encode()
subject = field(b"hub-test") + field(namespace) + field(b"acc-1") + bytes([2])*16 + public(runner)
route = field(namespace) + field(b"acc-1") + bytes([2])*16 + pack(">Q",3) + bytes([4])*16 + bytes([5])*16
capabilities = (field(b"nocterm/cloud-hub-capabilities/v1") + field(b"hub-test") + public(authority)
                + pack(">IIIQ", 1, 16384, 32*1024*1024+78, 7) + bytes([3])*16 + pack(">qq", 100000, 160000))
vectors = {
    "capabilities.hex": capabilities,
    "capabilities-signature.hex": authority.sign(capabilities),
    "binding-command.hex": field(b"nocterm/cloud-relay-binding/v1") + b"\x01" + field(route),
}
chat = field(b"nocterm/cloud-chat-coordinate/v1") + field(namespace) + field(b"acc-1") + bytes([2])*16 + pack(">Q",3) + bytes([4])*16 + pack(">Q",5)
vectors["binding-key-grant.hex"] = field(b"nocterm/cloud-relay-binding/v1") + b"\x04" + field(chat)
for purpose, token in [("redeem",b"fixture-ticket"),("refresh",b"runner-refresh")]:
    claim = field(f"nocterm/cloud-runner-{purpose}/v1".encode()) + subject + field(token) + bytes([3])*16 + pack(">q",100000)
    vectors[f"{purpose}.hex"] = claim
    vectors[f"{purpose}-signature.hex"] = runner.sign(claim)
request = field(b"nocterm/cloud-runner-request/v1") + subject + field(b"Publish") + sha256(b"runner-access").digest() + bytes([3])*16 + pack(">q",100000)
vectors["request.hex"] = request
vectors["request-signature.hex"] = runner.sign(request)
for name, value in vectors.items():
    (ROOT/name).write_text(value.hex()+"\n")
print("Generated",len(vectors),"independent Cloud relay vectors")
