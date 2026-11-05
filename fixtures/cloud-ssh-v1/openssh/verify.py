"""Independent check of agent-cert.pub (contract ADR 0009): parses the OpenSSH certificate
(PROTOCOL.certkeys) and verifies its Ed25519 signature under the CA of ../ca-public.hex.
Run `python3 verify.py` with Python cryptography; `ssh-keygen -L -f agent-cert.pub` prints the
same fields (agent-cert.txt)."""
import base64
from hashlib import sha256
from pathlib import Path
from struct import unpack
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).parent


class Reader:
    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, n):
        value = self.data[self.at:self.at + n]
        assert len(value) == n
        self.at += n
        return value

    def u32(self):
        return unpack(">I", self.take(4))[0]

    def u64(self):
        return unpack(">Q", self.take(8))[0]

    def string(self):
        return self.take(self.u32())


def strings(blob):
    reader, out = Reader(blob), []
    while reader.at < len(blob):
        out.append(reader.string())
    return out


kind, encoded = (ROOT / "agent-cert.pub").read_text().split()[:2]
blob = base64.b64decode(encoded)
r = Reader(blob)
assert r.string() == b"ssh-ed25519-cert-v01@openssh.com" == kind.encode()
nonce = r.string()
subject = r.string()
serial = r.u64()
cert_type = r.u32()
key_id = r.string()
principals = strings(r.string())
valid_after, valid_before = r.u64(), r.u64()
options = strings(r.string())
extensions = strings(r.string())
assert r.string() == b""  # reserved
signer = Reader(r.string())
signed_end = r.at
signature = Reader(r.string())
assert r.at == len(blob)

ca = bytes.fromhex((ROOT.parent / "ca-public.hex").read_text().strip())
assert signer.string() == b"ssh-ed25519" and signer.string() == ca
assert signature.string() == b"ssh-ed25519"
Ed25519PublicKey.from_public_bytes(ca).verify(signature.string(), blob[:signed_end])

assert subject == bytes.fromhex((ROOT.parent / "subject-public.hex").read_text().strip())
assert len(nonce) == 32 and cert_type == 1 and serial == 0x0102030405060708
tag = sha256(ca).hexdigest()[:16]
server = (ROOT.parent / "server-db.hex").read_text().strip()[:16]
assert principals == [f"nocterm-agent-{tag}-{server}".encode()]
assert key_id == b"nocterm-chat-" + b"81" * 16 + b"-" + b"44" * 16
assert options == [b"source-address", b"\x00\x00\x00\x1a203.0.113.7/32,2001:db8::1"]
assert extensions == [b"permit-pty", b""]
assert valid_after == 1_800_000_000 - 60 and valid_before == 1_800_000_000 + 8 * 3600
print("agent-cert.pub: signature, principal, options and validity verified")
