//! Compiles `proto/` with protox (no system `protoc`) into prost messages and an encoded
//! descriptor set that transport crates feed to `tonic-prost-build`.

use std::path::PathBuf;

use prost::Message;

const FILES: &[&str] = &[
    "nocterm/hub/v2/common.proto",
    "nocterm/hub/v2/auth.proto",
    "nocterm/hub/v2/account.proto",
    "nocterm/hub/v2/vault.proto",
    "nocterm/hub/v2/relay.proto",
    "nocterm/hub/v2/agents.proto",
    "nocterm/hub/v2/servers.proto",
    "nocterm/hub/v2/chats.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    let descriptors = protox::compile(FILES, ["proto"])?;
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    std::fs::write(
        out.join("hub_v2_descriptor.bin"),
        descriptors.encode_to_vec(),
    )?;
    prost_build::Config::new()
        // Secrets a person types must not end up in logs through `Debug`.
        .skip_debug([
            ".nocterm.hub.v2.SshCredential",
            ".nocterm.hub.v2.ProviderInput",
            ".nocterm.hub.v2.SetupRequest",
            ".nocterm.hub.v2.PasswordLoginRequest",
            ".nocterm.hub.v2.RedeemInviteRequest",
        ])
        .compile_fds(descriptors)?;
    Ok(())
}
