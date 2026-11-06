# 0015. The hub is trusted to run agents; only the vault is end-to-end encrypted

Status: accepted. Supersedes 0001–0014.

## Context

ADRs 0001–0014 made the hub blind to agents: definitions were sealed to pool hosts the hub
did not own, chats were runner-signed records sealed to the account, a device core verified
every record, and every unit of work (a model call, an SSH certificate, a provider lease) needed
a signature from an unlocked device that had the chat open. The consequences were the opposite
of what the product needs:

- an agent stops as soon as no device is online and unlocked (certificates last at most
  24 hours, model grants 10 minutes), so agents cannot work with every client closed;
- titles, deletion and lists depend on runner-signed summaries the hub cannot read, so chats
  show as `Chat · <id>` and cannot be deleted;
- the protocol needed about 53,000 lines (device core, journals, head probes, receipts,
  tombstones, pool keys, attestation) for a self-hosted hub whose operator runs the agents
  anyway.

## Decision

- The hub is trusted to run agents. It stores agents, chats, attachments, provider keys and
  each account's agent SSH key (secrets encrypted at rest with the hub's key) and runs agents
  on its own workers. Clients show and steer; closing them does not stop an agent.
- The vault stays end-to-end encrypted: the keyset and collections (saved connections,
  passwords, keys) are sealed on the device as before (`nocterm-keys`), and the hub never
  receives a key that opens them. The account X25519 pair and collection grants are removed
  with organizations.
- New package `nocterm.hub.v2`, `PROTOCOL_VERSION = 3`: `AuthService` (with `Setup`),
  `AccountService`, `VaultService`, `RelayService`, `AgentService`, `ServerService`,
  `ChatService`. Organizations, roles, nodes, terminals (Link), sessions, fleet, audit and the
  Cloud service are removed.
- A chat is an ordered log of `ChatItem`s numbered by `seq`; one `Watch` stream per client
  carries chat list changes, items of up to 8 open chats and the text an agent is still writing
  (`Draft`, never stored). Tools are namespaced (`server.run`) and their results are content
  parts, so new tool sources (for example MCP) need no protocol change.
- Servers are connected to an account's agents by writing the account's agent key into
  `authorized_keys` — by the desktop over its own session, or by a hub worker once with
  credentials the person types and the hub never stores — with the host key recorded and
  checked on every connection. There are no certificates and no expiry.
- Responses carry the hub's clock (`x-nocterm-time`, `HubInfo.server_time_ms`) and clients sign
  with it, so a skewed device clock does not end a session.

## Consequences

- Whoever controls the hub and its key can use providers' keys and reach servers connected to
  agents; the vault remains closed to it.
- The contract shrinks from about 68,000 to about 6,000 lines; `nocterm-cloud-device` and
  `nocterm-link` are deleted.
- Clients and hubs of protocol 2 refuse each other (`UpgradeRequired`); nothing is migrated.
