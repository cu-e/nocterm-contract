# Independent per-chat SSH binding vectors

Run `python3 generate.py` with Python cryptography. It uses no Rust or private server
implementation. All repeated-byte seeds are public fixture inputs.

The files cover the CA public key (seed `0x91…`), a runner subject key (seed `0x55…`), the
server id of connection profile `profile-db` (the first 16 bytes of its SHA-256, registry object
`srv-<hex>`), an `SshBinding` of chat `81…` at key epoch 4 (runner `02…` at key epoch 3,
namespace `hub`/`acc-1`) with grant `33…` at epoch 1800000000000, a seven-day window and two
targets, its signed framing under the CA key, a certificate request `44…` for the first server
from two source addresses for eight hours, and an `SshAccessUpdate` that reports the request
active with one admitted and one unreachable server.

`target-route-db`, `target-workspace-db` and `target-credential` are the session access of the
first bound server (contract ADR 0011): its route and workspace fingerprints and the binding's
credential revision, each a SHA-256 over a labelled layout (see `generate.py`).

Canonical fields are big-endian with u32 byte-length prefixes, u8 counts, closed numeric tags
and exact EOF (contract ADR 0009). The signed framing is field(signing bytes) ‖ Ed25519
signature by the CA key.

`openssh/` holds OpenSSH certificates `nocterm-keys` issues from these values, checked with
`ssh-keygen -L` (see its README).
