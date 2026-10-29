"""Public deterministic fixture for a non-restorable boot's provider-secret box."""
from pathlib import Path
from struct import pack
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Cryptodome.Cipher import ChaCha20_Poly1305
ROOT=Path(__file__).parent
def field(value): return pack(">I",len(value))+value
def public(key): return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
account=X25519PrivateKey.from_private_bytes(bytes([0x11])*32)
boot=X25519PrivateKey.from_private_bytes(bytes([0x22])*32)
ephemeral=X25519PrivateKey.from_private_bytes(bytes([0x33])*32)
signer=Ed25519PrivateKey.from_private_bytes(bytes([0x66])*32)
A,B,E=public(account),public(boot),public(ephemeral)
descriptor=(field(b"nocterm/cloud-provider-boot/v1")+field(b"hub")+field(b"account")+bytes([2])*16+pack(">Q",3)
            +bytes([4])*16+B+pack(">qq",100000,160000))
context=field(b"nocterm/cloud-provider-lease-context/v1")+field(descriptor)+field(b"openai")+bytes([5])*16+pack(">q",150000)
dh=ephemeral.exchange(boot.public_key())+account.exchange(boot.public_key())
key=HKDF(algorithm=hashes.SHA256(),length=32,salt=E+A+B,info=b"nocterm-cloud-provider-lease-v1/auth").derive(dh)
nonce=bytes(range(24))
cipher=ChaCha20_Poly1305.new(key=key,nonce=nonce)
cipher.update(b"nocterm/v1/cloud-provider-lease"+field((context+A+B).hex().encode()))
body,tag=cipher.encrypt_and_digest(b"public-fixture-api-key")
vectors={"boot.hex":descriptor,"boot-signature.hex":signer.sign(descriptor),"context.hex":context,"lease.hex":bytes([1,14])+E+nonce+body+tag}
for name,value in vectors.items(): (ROOT/name).write_text(value.hex()+"\n")
print("Generated",len(vectors),"independent provider lease vectors")
