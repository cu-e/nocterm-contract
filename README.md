# nocterm-contract

The protocol and client contract of the [Nocterm](https://github.com/cu-e/nocterm) hub: the wire
format, its generated stubs and the client every Nocterm application uses to talk to a hub.
Clients and hubs depend on this repository, pinned to a commit, so both sides read one definition.

| Crate | Purpose |
| --- | --- |
| `nocterm-hub-model` | identifiers, the bounds of what people type and send (`limits`), the protocol version and the signed proof-of-possession messages (`pop`) |
| `nocterm-hub-proto` | protobuf schema (`proto/`, package `nocterm.hub.v2`) compiled to prost messages, plus its descriptor set |
| `nocterm-hub-grpc` | tonic client and server stubs generated from the descriptor set, and the metadata names |
| `nocterm-hub-client` | hub client: certificate probe and pinning, signed requests (with the hub's clock), password, invite, setup and OIDC sign-in, token rotation, sign-out, the account keyset, relayed streams, and signed clients of the account, vault, agent, server and chat services |
| `nocterm-keys` | device keys (Ed25519), login and unlock key derivation, the vault key hierarchy, recovery keys and the sealed formats of keys, names and objects |
| `nocterm-keys-wasm` | wasm-bindgen bindings of the vault for the web panel: derive the login value (`loginAuth`), create an account's first keyset, unlock an account and read its saved server profiles (`openCollection`, `WebCollectionKey.openObject` for kind `profile` only) |

The services (see [ADR 0015](docs/adr/0015-trusted-hub-runs-agents.md)):

| Service | What it does |
| --- | --- |
| `AuthService` | hub information, first setup, password, invite and OIDC sign-in, device registration, refresh |
| `AccountService` | who am I, devices, sign-out |
| `VaultService` | the end-to-end encrypted keyset and collections (saved connections, passwords, keys) |
| `RelayService` | one TCP stream the hub dials (an SSH route step) |
| `AgentService` | model providers (server-wide or the account's) and agents |
| `ServerService` | the account's agent key and the SSH servers connected to its agents |
| `ChatService` | chats with agents: list, messages, approvals, files, one `Watch` stream |

The protobuf schema is compiled with [protox](https://crates.io/crates/protox), so no system
`protoc` is needed.

## Using it

```toml
[dependencies]
nocterm-hub-client = { git = "https://github.com/cu-e/nocterm-contract", rev = "<commit>" }
```

Pin a commit: the contract is pre-1.0 and changes together with its consumers.

## Compatibility

`nocterm.hub.v2` evolves additively: fields and messages are added, never renumbered or
reused. A breaking change gets a new package version. The client refuses a hub whose protocol
version it does not speak (`ClientError::UpgradeRequired`). The protocol version is 3.

A new service is additive and does not change the protocol version. A hub that lacks one answers
`UNIMPLEMENTED`, which the client reads as "not supported" (for example
`RelayError::Unsupported`).

## Keys

The password never leaves the device. Sign-in derives, with Argon2id (64 MiB, 3 passes, 4 lanes)
over a salt bound to the hub and the user name, one master secret and splits it with HKDF-SHA256
under separate labels:

- `auth`, sent to the hub in place of the password;
- `unlock`, which stays on the device and opens the account key.

Accounts that sign in through an identity provider derive `unlock` from a separate vault password
with a random salt. The keyset records which of the two applies (`unlock_kind`), and the client
chooses the derivation from that record. The account key is generated once; it wraps the keys of
the account's collections. A recovery key (shown once, 128
bits) wraps a copy of the account key so a forgotten password does not lose the data. All sealed
values are XChaCha20-Poly1305 with the purpose and context in the authenticated data; secrets are
zeroized and never printed. The KDF parameters a hub sends must lie between 64 MiB / 3 passes /
4 lanes and 1 GiB / 16 passes / 16 lanes.

### What the password protects

The hub sees `auth` in clear on every sign-in and uses it as a verifier. A hub, or anyone who
reads its database or traffic, can therefore test password guesses offline at the cost of one
Argon2id run per guess, and a found password yields `unlock`. There is no second stage: against
the hub, the vault is exactly as strong as the password. Use a long password or passphrase; the
minimum length only catches mistakes. The recovery key does not depend on the password. The
hub identifier is reported by the hub itself, so the separation between hubs holds for honest
hubs only.

## Relays

`RelayService.Open` carries a byte stream from the client to a TCP target through the hub, and
`NodeService.Tunnel` carries it from the hub to a fleet node. Frames are at most 32 KiB and each
stream is buffered by 16 frames, so a slow reader slows its writer instead of growing memory.
The caller's `close` is a half-close; the hub's `closed` ends the whole relay, and the writer
then refuses to send. Empty data frames are never sent and are skipped when received, so the end
of the bytes is always explicit.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --target wasm32-unknown-unknown -p nocterm-keys-wasm
```

Minimum supported Rust version: 1.89.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Contributions are accepted under the same terms.
