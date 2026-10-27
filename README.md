# nocterm-contract

The protocol and client contract of the [Nocterm](https://github.com/cu-e/nocterm) hub: the wire
format, its generated stubs and the client every Nocterm application uses to talk to a hub.
Clients and hubs depend on this repository, pinned to a commit, so both sides read one definition.

| Crate | Purpose |
| --- | --- |
| `nocterm-hub-model` | identifiers, permissions and the signed proof-of-possession messages |
| `nocterm-hub-proto` | protobuf schema (`proto/`) compiled to prost messages, plus its descriptor set |
| `nocterm-hub-grpc` | tonic client and server stubs generated from the descriptor set |
| `nocterm-hub-client` | hub client: certificate probe and pinning, signed requests, password and OIDC sign-in, token rotation, resumable terminals |
| `nocterm-keys` | device keys (Ed25519), key derivation and sealing |
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
version it does not speak (`ClientError::UpgradeRequired`).

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
