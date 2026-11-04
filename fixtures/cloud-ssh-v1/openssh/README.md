# OpenSSH certificate vectors

`agent-cert.pub` is the certificate `nocterm_keys::agents::ssh_ca::UserCa::issue` makes from CA
seed `0x91…` for subject `0x55…` (`../subject-public.hex`): the principal of `profile-db` only,
`source-address 203.0.113.7/32,2001:db8::1`, `permit-pty` only, eight hours from
1800000000000 ms with the 60 s backdate, serial `0102030405060708`, nonce `0x66…`. `ca.pub` is
the CA public key line.

- `agent-cert.txt` is `ssh-keygen -L -f agent-cert.pub` (OpenSSH 9.6p1).
- `python3 verify.py` (Python cryptography) parses the certificate independently and verifies
  its Ed25519 signature under `../ca-public.hex`, its principal, options, extensions and
  validity.
- `../ca-document.json` is the format 1 `agent_ssh_trust` CA document (seed `0x93…`, retired CA
  `0x91…`), byte for byte what the native client writes.

The Rust tests compare against these files. Regenerate them after a deliberate format change with
`cargo test -p nocterm-keys write_openssh_fixtures -- --ignored`, then rerun both checks.
