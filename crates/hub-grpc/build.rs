//! Generates tonic client and server stubs from the descriptor set of `nocterm-hub-proto`;
//! messages are not regenerated but referenced through `extern_path`.

use prost::Message;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds = prost_types::FileDescriptorSet::decode(nocterm_hub_proto::FILE_DESCRIPTOR_SET)?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        // Clients build their own channel (pinned TLS), and `NodeService.Connect` would
        // collide with the generated `connect` constructor.
        .build_transport(false)
        .extern_path(".nocterm.hub.v1", "::nocterm_hub_proto::v1")
        .compile_fds(fds)?;
    Ok(())
}
