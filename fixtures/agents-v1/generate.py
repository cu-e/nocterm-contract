#!/usr/bin/env python3
"""Independent generator of the agents-v1 vectors (standard library only).

Reproduces the canonical host attestation and the receipt-reclaim tombstone hashes without
using the Rust code, so a layout drift on either side fails the tests.
"""
import hashlib
import pathlib
import struct

here = pathlib.Path(__file__).parent


def lp(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


pool, host, instance = bytes([1] * 16), bytes([2] * 16), bytes([3] * 16)
digest = bytes([4] * 32)
issued = 1_700_000_000_123

attestation = (
    lp(b"nocterm/agents-host-runner-attestation/v1")
    + lp(pool)
    + lp(host)
    + lp(instance)
    + lp(digest)
    + lp(struct.pack(">q", issued))
)
(here / "attestation.hex").write_text(attestation.hex() + "\n")

account, runner, chat = "account-1", bytes([5] * 16), bytes([6] * 16)
retired = hashlib.sha256(
    lp(b"nocterm/cloud-retired-stream/v1")
    + lp(account.encode())
    + lp(runner)
    + lp(struct.pack(">Q", 7))
    + lp(chat)
).digest()
(here / "retired-stream.hex").write_text(retired.hex() + "\n")

revoked = hashlib.sha256(
    lp(b"nocterm/cloud-revoked-runner/v1") + lp(account.encode()) + lp(runner)
).digest()
(here / "revoked-runner.hex").write_text(revoked.hex() + "\n")

# Broker virtual token: HMAC-SHA256 over the canonical claims, text form nvt1_<b64url(id|tag)>.
import base64
import hmac

token_id = bytes([9] * 16)
claims = (
    lp(b"nocterm/agents-broker-virtual-token/v1")
    + lp(token_id)
    + lp(bytes([3] * 16))
    + lp(b"chat-1")
    + lp(struct.pack(">Q", 2))
    + lp(b"gpt")
    + lp(b"mini")
    + lp(struct.pack(">Q", 5_000_000))
    + lp(struct.pack(">q", 2_000))
)
tag = hmac.new(bytes([1] * 32), claims, hashlib.sha256).digest()
text = "nvt1_" + base64.urlsafe_b64encode(token_id + tag).decode().rstrip("=")
(here / "broker-token.txt").write_text(text + "\n")

# SSH CA grant canonical bytes. The CA public key is the one of seed [8]*32: computed by the
# Rust test through DeviceKey, so the vector takes it as input from ca-public.hex.
ca_hex = (here / "ca-public.hex").read_text().strip()
grant = (
    lp(b"nocterm/agents-ssh-ca-grant/v1")
    + lp(bytes([3] * 16))
    + lp(b"nocterm-agent-abc")
    + lp(bytes.fromhex(ca_hex))
    + lp(bytes([6] * 32))
    + lp(struct.pack(">Q", 7))
    + lp(struct.pack(">q", 1_000))
    + lp(struct.pack(">q", 1_000 + 24 * 3600 * 1000))
    + lp(struct.pack(">Q", 2))
    + lp(b"203.0.113.7/32")
    + lp(b"2001:db8::1")
)
(here / "ssh-ca-grant.hex").write_text(grant.hex() + "\n")
