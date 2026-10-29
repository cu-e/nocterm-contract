"""Independent fixed vectors: Python cryptography + PyCryptodome, not Rust code.
All deterministic key seeds/nonces here are public test data, never production keys.
Run from any directory after installing cryptography and pycryptodomex.
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

def seed(first):
    return bytes(range(first, first + 32))

def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

account = X25519PrivateKey.from_private_bytes(seed(0x10))
runner = X25519PrivateKey.from_private_bytes(seed(0x40))
ephemeral = X25519PrivateKey.from_private_bytes(seed(0x60))
device = Ed25519PrivateKey.from_private_bytes(seed(0xa0))
A, R, E = public(account), public(runner), public(ephemeral)
namespace = sha256(field(b"nocterm/cloud-hub-namespace/v1") + field(b"hub-1") + bytes([0x31])*32).hexdigest().encode()
route = field(namespace) + field(b"account-2") + bytes([0x21])*16 + pack(">Q",3) + bytes([0x23])*16 + bytes([0x24])*16
payload = b"fixture secret\n\x00payload"
nonce = bytes(range(0x80, 0x98))

def header(account_key=A, runner_key=R, signed_route=route, signing_key=public(device)):
    return (field(b"nocterm/cloud-command/v1") + signed_route + account_key + runner_key
            + field(b"device-1") + signing_key + sha256(b"fixture-token").digest()
            + bytes([0x25])*16 + pack(">Q",9) + b"\x01" + bytes([0x26])*16 + pack(">Q",7)
            + pack(">HqqI",1,1700000000000,1700000060000,len(payload)) + sha256(payload).digest())

M = header()
AD = field(b"nocterm/cloud-command-box/v1") + route + A + R
IKM = ephemeral.exchange(runner.public_key()) + account.exchange(runner.public_key())

def envelope(message=M, body=payload, signature=None, info=b"nocterm-cloud-command-v1/auth", aad=AD):
    signature = device.sign(message) if signature is None else signature
    plain = field(message) + field(body) + signature
    key = HKDF(algorithm=hashes.SHA256(),length=32,salt=E+A+R,info=info).derive(IKM)
    cipher = ChaCha20_Poly1305.new(key=key,nonce=nonce)
    cipher.update(aad)
    c,tag = cipher.encrypt_and_digest(plain)
    encrypted = c + tag
    return b"\x01\x08" + E + nonce + pack(">I",len(encrypted)) + encrypted

vectors = {
    "header.hex": M,
    "plaintext.hex": field(M) + field(payload) + device.sign(M),
    "valid.hex": envelope(),
    "bad-device-signature.hex": envelope(signature=bytes([device.sign(M)[0]^1])+device.sign(M)[1:]),
    "bad-device-key.hex": envelope(message=header(signing_key=public(Ed25519PrivateKey.from_private_bytes(seed(0xb0)))),signature=device.sign(M)),
    "bad-payload.hex": envelope(body=bytes([payload[0]^1])+payload[1:],signature=device.sign(M)),
    "wrong-inner-account.hex": envelope(message=header(account_key=public(X25519PrivateKey.from_private_bytes(seed(0x30))))),
    "wrong-inner-runner.hex": envelope(message=header(runner_key=public(X25519PrivateKey.from_private_bytes(seed(0x30))))),
    "wrong-inner-route.hex": envelope(message=header(signed_route=route[:-16]+bytes([0x55])*16)),
    "wrong-kdf-purpose.hex": envelope(info=b"nocterm-grant-v1/auth"),
    "wrong-aad-purpose.hex": envelope(aad=field(b"nocterm/v1/collection-grant")+route+A+R),
}
for name,data in vectors.items():
    (ROOT/name).write_text(data.hex()+"\n")
(ROOT/"namespace.hex").write_text(namespace.decode()+"\n")
print("Generated",len(vectors),"fixed vectors; header",len(M),"bytes; envelope",len(vectors["valid.hex"]),"bytes")
