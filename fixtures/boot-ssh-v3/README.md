# Boot v3 SSH section vectors

`ssh-section.json` is the SSH part of a managed runner's boot document, format 3 (contract
ADR 0011): `version`, `ssh_targets` and `ssh_egress`. The rest of a boot document (identity,
provider, policy) belongs to the runner and the node and is left out. The first target states a
host key (an Ed25519 key whose 32 public bytes are all `0x5a`, a public fixture value) and every
session field; the second states neither, so it is listed but never admitted for a binding.

`db-host-key-sha256.hex` is the SHA-256 of the first target's host key blob, the
`host_key_sha256` a binding of that server must carry to be admitted.
