# 0009. Per-chat SSH binding and certificates

Status: accepted

Extends [0007](0007-device-flows-resumable-reader-and-freshness.md) (device flows) and
[0008](0008-runner-chat-directory.md) (its bound servers). Takes over the account SSH CA of the
native client's ADR 0119 and replaces its single agent principal with per-server principals.

## Context

The native client keeps a personal SSH CA: an Ed25519 seed in the account's end-to-end
encrypted `agent_ssh_trust` collection (object `ca`) and one trust record per server
(`srv-<hex>`) whose `authorized_keys` holds a `cert-authority` line for the CA. Its certificate
issuer was never called; "bound to servers" was a browser-local note. A Cloud chat must reach the
servers the person chose for it, with credentials no hub can mint, that a compromised runner
cannot stretch to other servers, and that lapse on their own when no device of the person is
online. The browser and the native client must decide this with one implementation.

## Decision

**A binding signed by the account CA.** `nocterm_hub_model::cloud::ssh::SshBinding` (format 1)
names the chat coordinate, a grant `{id, epoch}`, a window (at most 30 days, 7 by default), the
CA public key and up to 16 targets `{server, host, port, user, host key SHA-256}`. A server is
`SshServerId` = the first 16 bytes of SHA-256 of the connection profile id, which is also its
registry object id (`srv-<hex>`). `UserCa::sign_binding` signs the binding with the CA key
(label `nocterm/cloud-ssh-binding/v1`); `SignedSshBinding` verifies under the key it names and
`require_ca` decides whether that is the account's CA. A device builds targets only from trust
records that are `Trusted` under the current CA (host, user and host key from the record; the
person's profile supplies the port) and delivers `IssueGrant(GrantPayload::SshBinding)` (payload
tag 4). One binding per chat: a binding with the same grant id and a higher epoch replaces it.
`RevokeGrant(GrantClass::SshBinding)` (class 4) ends it. Both are chat-scoped: a header naming a
run is refused, and a binding must name the chat the command is routed to.

**The runner asks, any unlocked account device answers.** The runner keeps a per-chat Ed25519
key and publishes `SshCertificateRequested` (event tag 14): a request id, the signed binding it
holds (echoed, so a device that never saw the binding command checks it), the subject key, its
stated egress as source addresses (at most 8), the bound servers it can reach and the end it asks
for. It reports `SshAccessState` (event tag 15): pending, active until a time for a request,
refused (no source address, no reachable server, invalid), revoked or expired, and per-server
reach. Both events are chat-scoped and a request is valid only in its binding's chat. The device
core (`nocterm-cloud-device`) reduces them into `ChatSsh` (per grant only the highest epoch; the
first request of an epoch fixes the subject key) and `OpenChat` reports an answerable request
once (`ChatUpdate::SshRequest`). `SshAnswer` answers only when all of this holds:

- the request is in the verified transcript (pinned runner, its chat, in order);
- its binding is the current epoch, not revoked, refused, expired or withdrawn by this device,
  contains the time, and the request names the binding's first subject key;
- the binding is signed by the account's current CA (read from `agent_ssh_trust/ca` now);
- each certified server is requested, bound, and still `Trusted` under that CA with the bound
  host, user and host key; servers that are not are left out, and none left is a refusal.

The certificate (`UserCa::issue`) is an OpenSSH user certificate valid until the request's end,
at most 24 hours (8 by default) and never past the binding, backdated 60 seconds, with the
principals of the certified servers only, the runner's addresses as the mandatory
`source-address` and `permit-pty` as the only extension; its key id names the chat and the
request. It travels as `IssueGrant(GrantPayload::SshCertificate{grant, request, certificate})`
(payload tag 5, at most 4 KiB). The runner re-requests before expiry; with no device online,
access lapses at expiry. Refusals are typed (`SshRefusal`), never a runner's or hub's statement.

**Per-server principals.** `principal_for(ca, server)` is
`nocterm-agent-<first 8 bytes of SHA-256(CA) in hex>-<first 8 bytes of the server id in hex>`;
the line of `authorized_keys` line version 2 (`CaLine::for_server`) admits only it. Line version
1 (ADR 0119's `nocterm-agent-<ca>`, `agent_principal`) is named by no certificate, so such a
server needs a CA update: `server_line` tells the forms apart, `SshTrustRecord` records the
form as `CaLineForm` (schema 2 for a per-server line; a shared line keeps the schema 1 bytes),
and a binding reports which bound servers still need it.

**The CA lives in the contract.** `nocterm_keys::agents::ssh_ca` holds `UserCa`,
`CertificateSpec`, `CertificateFacts` (checks a certificate is exactly such an agent
certificate of a CA), `CaDocument` (format 1 JSON, byte for byte what the native client writes)
and the principals. Certificates are built with `ssh-key` 0.7.0-rc.11, the version the native
client pins, which builds for wasm32. The CA signs only these two kinds of value; a certificate
blob starts with its length-prefixed key type and a binding with its length-prefixed label, so
neither can be taken for the other. The browser opens the CA seed inside WebAssembly while the
keys are unlocked, as it opens the vault and account keys; it never crosses into JavaScript
(`openSshTrust` shows a CA as its fingerprint).

## Consequences

- No hub can mint access: it relays sealed commands and events and records no SSH grant.
- A compromised runner reaches only the servers bound to its chats, from its stated addresses,
  until its certificates expire; it cannot widen a binding (the CA signs it) or swap its key
  unnoticed (the first subject key of an epoch is fixed). Hiding a revocation report delays the
  stop only until the binding window ends or the person removes the server from the registry,
  which every answering device rereads.
- Any unlocked account device answers automatically inside a window the person signed (up to
  30 days); a person who wants no unattended issuance uses short windows.
- Servers with a line version 1 work again after one native reconnect rewrites their line.
- Readers ship first: an older reader refuses event tags 14 and 15 and payload tags 4 and 5, so
  runners emit SSH events only in chats that hold a binding, and only new devices bind.
- Reducer version 2 of the device checkpoint carries the bindings; older checkpoints replay.
- Independent vectors in `fixtures/cloud-ssh-v1/` (Python), OpenSSH certificates checked with
  `ssh-keygen -L` and an independent signature check (`fixtures/cloud-ssh-v1/openssh/`).
