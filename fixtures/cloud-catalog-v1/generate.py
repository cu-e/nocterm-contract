"""Independent public fixture for a runner-owned native account catalog."""
from pathlib import Path
from hashlib import sha256
from struct import pack
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Cryptodome.Cipher import ChaCha20_Poly1305
ROOT=Path(__file__).parent
def field(value): return pack(">I",len(value))+value
seed=bytes([0x22])*32
runner=X25519PrivateKey.from_private_bytes(seed)
public=runner.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
coordinate=field(b"nocterm/cloud-native-account-catalog/v1")+field(b"hub")+field(b"account")+bytes([7])*32+bytes([2])*16+pack(">QQ",3,4)
context=coordinate+public
key=HKDF(algorithm=hashes.SHA256(),length=32,salt=sha256(context).digest(),info=b"nocterm-cloud-native-account-catalog-key-v1").derive(seed)
nonce=bytes(range(24))
cipher=ChaCha20_Poly1305.new(key=key,nonce=nonce)
cipher.update(b"nocterm/v1/cloud-native-account-catalog"+field(context.hex().encode()))
body,tag=cipher.encrypt_and_digest(b"public catalog fixture")
for name,value in {"context.hex":coordinate,"catalog.hex":bytes([1,15])+nonce+body+tag}.items(): (ROOT/name).write_text(value.hex()+"\n")
print("Generated2 independent native catalog vectors")
