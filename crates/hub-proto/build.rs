//! Compiles `proto/` with protox (no system `protoc`) into prost messages and an encoded
//! descriptor set that transport crates feed to `tonic-prost-build`.

use std::path::PathBuf;

use prost::Message;

const FILES: &[&str] = &[
    "nocterm/hub/v1/common.proto",
    "nocterm/hub/v1/auth.proto",
    "nocterm/hub/v1/directory.proto",
    "nocterm/hub/v1/store.proto",
    "nocterm/hub/v1/sessions.proto",
    "nocterm/hub/v1/link.proto",
    "nocterm/hub/v1/relay.proto",
    "nocterm/hub/v1/fleet.proto",
    "nocterm/hub/v1/audit.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    let descriptors = protox::compile(FILES, ["proto"])?;
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    std::fs::write(
        out.join("hub_v1_descriptor.bin"),
        descriptors.encode_to_vec(),
    )?;
    prost_build::Config::new().compile_fds(descriptors)?;
    Ok(())
}
