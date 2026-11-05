# 0011. Bound servers as session targets, the SSH journal class, boot v3 targets and summary servers

Status: accepted

Extends [0009](0009-per-chat-ssh-binding-and-certificates.md) (per-chat SSH binding): a bound
server becomes something a prompt can run against, and the formats around it (native journal,
managed boot document, chat summary) gain what a runner needs to keep, reach and list it.

## Context

With ADR 0009 a device binds a chat to CA-trusted servers and answers the runner's certificate
requests, and the native runner signs in to a configured target with the chat's certificate. The
runner side (native client ADR 0137) found four gaps in the contract:

- The runner seals its per-chat SSH row (binding, open request, certificate, subject-key seed)
  with the chat's journal cipher, but `JournalClass` had no purpose for it. The runner borrowed
  `Effect` with a reserved slot id, so the purpose byte in the authenticated data did not say
  what the row is.
- A device could bind a chat but not ask for anything to run on a bound server.
  `SubmitPrompt.target` is a `TargetAccess` (host key, route, principal and workspace
  fingerprints, authentication key and credential revision), and nothing defined these values
  for a bound server, so a device could not name one and a runner could not recognise one.
- A managed runner's boot targets carry host, port and user only. Without a host key it cannot
  verify the server, and without terminal settings it cannot start a session, so a boot target
  could be admitted for a binding but never signed in to.
- `ChatSummary.servers` existed with feature bit 1 but no runner filled it: a summary server had
  no server id (a device could not join it with its trust record to show "needs CA update"),
  nothing derived its state from the binding, and sixteen servers did not fit the 2048-byte
  summary bound.

## Decision

**A bound server's session access is derived from the CA-signed binding.**
`SshBinding::target_access(server)` is the `TargetAccess` that names one server entry:

- host key: the entry's `host_key_sha256`;
- route: SHA-256 of field(`nocterm/cloud-ssh-target-route/v1`) ‖ server id ‖ field(host) ‖ port ‖
  field(user) ‖ host key;
- principal: the login user;
- workspace: SHA-256 of field(`nocterm/cloud-ssh-target-workspace/v1`) ‖ server id ‖ field(user)
  ‖ host key (the account on the server, whatever address reaches it);
- authentication key: the binding's CA key; credential revision: SHA-256 of
  field(`nocterm/cloud-ssh-target-credential/v1`) ‖ grant id ‖ grant epoch ‖ CA key.

A device sends it as `SubmitPrompt.target` with no `existing_session`. The runner selects with
`SshBinding::target_of_access`: the bound server of the binding it admitted whose access is equal,
else nothing. A newer binding epoch or another CA changes the credential revision, so an access
built for an older binding selects nothing. Signing in still needs the runner's active
certificate for that server; without one the run waits for a device. `BeginSession` is not used
for bound servers: the runner opens the session when the run needs it.

On the device, `ChatSsh::session_targets(now)` lists the servers of the current binding that the
runner admitted (its latest `SshAccessState` names them admitted; before a report, its open
request asks for them), inside the binding window, with whether a certificate is active.
`ChatAction::Prompt { server }` builds the prompt through `PromptPolicy::with_target`; a server
that is not selectable is `SshRefusal::NotSelectable`, a chat without a binding `NotBound`.

**The SSH row has its own journal class.** `JournalClass::SshAccess = 10`, slot id
`SSH_ACCESS_SLOT` (the id native journals used under `Effect`). Classes 1 to 9 are class set 1;
set 2 (`JOURNAL_CLASS_SET`) adds class 10. The slot layout stays `nocterm/cloud-journal-slot/v1`.
A native journal that writes class 10 bumps its own format version and re-seals rows it sealed
under `Effect`; a row never opens under another class.

**Boot v3 states each target's host key and session settings.**
`hub_model::agents::boot_ssh` fixes the SSH part of a managed boot document (`version`,
`ssh_targets`, `ssh_egress`, JSON). v2: no egress, targets with host, user and port only. v3: one
to eight egress addresses or CIDRs (`cloud::ssh::is_source_address`), and each target may add
`host_public_key` (one OpenSSH line, at most 2048 bytes, a known algorithm whose blob names it)
and `session` (terminal type, 2–240 columns, 1–120 rows, connection timeout up to 60 s, optional
program, up to 64 arguments and directory, 16 KiB of strings, no environment); targets are unique
by host, port and user. `check_boot_ssh` refuses everything else with a typed `BootSshError`.
`BootSshTarget::admits` admits a bound server only with equal host, port and user and a binding
host key equal to the SHA-256 of the target's key blob: a boot target without a host key is
listed but never admitted. The rest of the boot document stays the runner's and the node's.

**Summaries list bound servers by id.** A summary server entry is server id ‖ host ‖ port ‖ user ‖
state ‖ valid before; each server appears once. `summary::bound_servers(binding, update, now)`
gives the runner the list: admitted servers `Active` until the certificate's end or
`AwaitingDevice`, every other one `Unreachable`, none once the binding is revoked or expired.
`MAX_SUMMARY_BYTES` grows to 6144 so sixteen servers with the longest names fit. A runner that
takes bindings sets `SUMMARY_FEATURE_SSH_BINDING`; `NeedsCaUpdate` stays a device's derivation
from the trust record. No runner had set the bit or listed a server, so the entry changes under
format 1.

## Consequences

- A device can run a prompt on a bound server, and the runner recognises it by recomputation,
  never by constructing a target from the prompt.
- A runner's SSH row says what it is in its authenticated data; old rows need a one-time
  re-seal.
- A host that writes host keys into boot v3 lets a managed runner sign in to its targets; until
  then managed bindings stay admitted-but-unusable only for targets the node stated without one.
- Lists show each bound server with its state, and the web joins them with trust records.
- Breaking for clients: `JournalClass::SshAccess`, `BoundServer.server`, the summary server
  layout and bound, `ChatAction::Prompt.server`, `SshRefusal::NotSelectable`, and the wasm
  `WireServer.serverId` and prompt `server`. Vectors: `fixtures/cloud-ssh-v1/target-*.hex`,
  `fixtures/boot-ssh-v3/`, regenerated `fixtures/cloud-summary-v1/` and
  `fixtures/cloud-device-v1/web-session.json`.
