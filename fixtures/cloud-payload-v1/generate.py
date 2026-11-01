"""Independent semantic payload/tool fingerprints. All keys are public fixture inputs."""
from pathlib import Path
from hashlib import sha256
from struct import pack
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ROOT=Path(__file__).parent
def field(value): return pack(">I",len(value))+value
def text(value): return field(value.encode())
def public(key): return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def optional(value): return b"\x00" if value is None else b"\x01"+pack(">Q",value)
def payload(kind,body=b""): return field(b"nocterm/cloud-command-payload/v1")+pack(">H",kind)+body
def tool(kind,body=b""): return field(b"nocterm/cloud-tool-arguments/v1")+bytes([kind])+body
host=Ed25519PrivateKey.from_private_bytes(bytes([9])*32)
user=Ed25519PrivateKey.from_private_bytes(bytes([4])*32)
host_blob=text("ssh-ed25519")+field(public(host))
user_blob=text("ssh-ed25519")+field(public(user))
target=sha256(host_blob).digest()+bytes([2])*32+text("alice")+bytes([3])*32+sha256(user_blob).digest()+bytes([5])*32
session=bytes([6])*16+pack(">Q",7)+target
run=bytes([8])*16+pack(">Q",9)
grant=bytes([10])*16+pack(">Q",11)
model=text("openai")+text("model")+text("pricing")
limits=pack(">IIQQQQq",1,2,1024,2048,4096,5000,150000)
window=pack(">qq",100000,160000)
execution=run+session+grant
approval=bytes([11])*16+bytes([12])*32+execution
H=bytes([0xab])*32
host_signature=text("ssh-ed25519")+field(host.sign(H))
userauth=(field(H)+b"\x32"+text("alice")+text("ssh-connection")+text("publickey")+b"\x01"+text("ssh-ed25519")+field(user_blob))
signature=text("ssh-ed25519")+field(user.sign(userauth))
consent=(run+target+bytes([13])*16+bytes([14])*32+pack(">QQ",100000,150000)+field(user_blob)
         +field(host_blob)+field(host_signature)+field(userauth))
provider_context=bytes.fromhex((ROOT.parent/"cloud-provider-v1/context.hex").read_text())
provider_capsule=bytes.fromhex((ROOT.parent/"cloud-provider-v1/lease.hex").read_text())
vectors={
    "prompt":payload(1,model+b"\x01"+target+b"\x01"+session+limits+pack(">H",2)+b"\x01"+text("public fixture prompt")+b"\x02\x01"+field(b"public image fixture")),
    "stop":payload(2),
    "approval":payload(3,approval+b"\x01"),
    "reconcile":payload(3,approval+b"\x03"),
    "reconcile-failed":payload(3,approval+b"\x04"),
    "reconcile-known":payload(3,approval+b"\x05"+bytes([0x13])*32),
    "inference":payload(4,b"\x01"+grant+model+window+limits),
    "tools":payload(4,b"\x02"+grant+session+window+pack(">I",5)+b"\x0f"),
    "provider":payload(4,b"\x03"+grant+field(provider_context)+b"\x01"+text("model")+field(provider_capsule)),
    "revoke":payload(5,b"\x02"+grant),
    "ssh-approve":payload(6,consent+b"\x01"+field(signature)),
    "ssh-deny":payload(6,consent+b"\x00"),
    "delete":payload(7),
    "issuer":payload(8,text("device")+bytes([15])*32+pack(">Q",12)+b"\x01\x02"+grant),
}
tools={
    "list":tool(1),"open":tool(2,text("server")),
    "read":tool(3,text("terminal")+optional(10)+optional(None)),
    "input":tool(4,text("terminal")+text("literal input")+b"\x01"),
    "run":tool(5,text("terminal")+text("pwd")+optional(1000)+optional(None)),
    "exec":tool(6,text("terminal")+text("/bin/printf")+pack(">H",2)+text("%s")+text("$(literal); *")+b"\x01"+text("")+optional(None)+optional(0)),
    "read-command":tool(7,text("terminal")+text("command")+optional(50)),
    "cancel":tool(8,text("terminal")+text("command")),
    "transfer":tool(9,text("terminal")+pack(">H",2)+text("/srv/a")+text("/srv/dir b")+text("terminal-2")+text("/home/alice/in")+b"\x00"+optional(1000)),
    "read-transfer":tool(10,text("0a0b0c0d-0e0f-1011-1213-141516171819")+optional(None)),
    "cancel-transfer":tool(11,text("0a0b0c0d-0e0f-1011-1213-141516171819")),
}
for name,value in vectors.items(): (ROOT/f"{name}.hex").write_text(value.hex()+"\n")
for name,value in tools.items():
    (ROOT/f"tool-{name}.hex").write_text(value.hex()+"\n")
    (ROOT/f"tool-{name}.sha256").write_text(sha256(value).hexdigest()+"\n")
print("Generated",len(vectors),"payloads and",len(tools),"tool fingerprints")
