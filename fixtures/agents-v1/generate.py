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
