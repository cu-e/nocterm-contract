# nocterm-contract

The protocol and client contract of the [Nocterm](https://github.com/cu-e/nocterm) hub: the wire
format, its generated stubs and the client every Nocterm application uses to talk to a hub.
Clients and hubs depend on this repository, pinned to a commit, so both sides read one definition.

| Crate | Purpose |
| --- | --- |
| `nocterm-hub-model` | identifiers, permissions and the signed proof-of-possession messages |
| `nocterm-hub-proto` | protobuf schema (`proto/`) compiled to prost messages, plus its descriptor set |
| `nocterm-hub-grpc` | tonic client and server stubs generated from the descriptor set |
| `nocterm-hub-client` | hub client: certificate probe and pinning, signed requests, password and OIDC sign-in, the account keyset, relayed streams, token rotation, resumable terminals |
| `nocterm-keys` | device keys (Ed25519), login and unlock key derivation, the key hierarchy, recovery keys, sealed grants |
| `nocterm-link` | pure state machines of the terminal Link: output rings, resume points, exactly-once input |

The protobuf schema is compiled with [protox](https://crates.io/crates/protox), so no system
`protoc` is needed.

## Using it

```toml
[dependencies]
nocterm-hub-client = { git = "https://github.com/cu-e/nocterm-contract", rev = "<commit>" }
```

Pin a commit: the contract is pre-1.0 and changes together with its consumers.

## Compatibility

`nocterm.hub.v1` evolves additively: fields and messages are added, never renumbered or
reused. A breaking change gets a new package version. The client refuses a hub whose protocol
version it does not speak (`ClientError::UpgradeRequired`). The protocol version is 2.

A new service is additive and does not change the protocol version. A hub that lacks one answers
`UNIMPLEMENTED`, which the client reads as "not supported" (for example
`RelayError::Unsupported`). `NodeService.Tunnel` and `RelayService` are such additions;
`SignerService` is reserved for a later release and has no schema yet.

## Keys

The password never leaves the device. Sign-in derives, with Argon2id (64 MiB, 3 passes, 4 lanes)
over a salt bound to the hub and the user name, one master secret and splits it with HKDF-SHA256
under separate labels:

- `auth`, sent to the hub in place of the password;
- `unlock`, which stays on the device and opens the account key.

Accounts that sign in through an identity provider derive `unlock` from a separate vault password
with a random salt. The account key is generated once; it wraps the account's X25519 private key
and the keys of its collections. A collection key reaches another member sealed to that member's
public key and bound to the collection and account. A recovery key (shown once, 128 bits) wraps a
copy of the account key so a forgotten password does not lose the data. All sealed values are
XChaCha20-Poly1305 with the purpose and context in the authenticated data; secrets are zeroized
and never printed.

## Relays

`RelayService.Open` carries a byte stream from the client to a TCP target through the hub, and
`NodeService.Tunnel` carries it from the hub to a fleet node. Frames are at most 32 KiB and each
stream is buffered by 16 frames, so a slow reader slows its writer instead of growing memory.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Minimum supported Rust version: 1.89.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Contributions are accepted under the same terms.
