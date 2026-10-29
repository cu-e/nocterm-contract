//! Public routing and incremental ciphertext integrity; never execution admission.
mod binding;
mod upload;

pub use binding::{RelayBinding, RelayKind};
pub use upload::{PublicationMetadata, PublicationVerifier, VerifiedPublication};

pub const MAX_RELAY_FRAME_BYTES: usize = 16 * 1024;
pub const MAX_RELAY_WIRE_BYTES: usize = 32 * 1024;
pub const MAX_RELAY_BINDING_BYTES: usize = 4096;
/// A key envelope is tiny; it cannot consume the 32MiB command allowance.
pub const MAX_RELAY_KEY_MATERIAL_BYTES: u32 = 256;
pub const MAX_RELAY_QUEUE_FRAMES: usize = 8;
pub const MAX_RELAY_PAGE_RECORDS: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RelayFormatError {
    #[error("malformed or unsupported Cloud relay routing")]
    Malformed,
    #[error("the Cloud relay framing exceeds its limit")]
    Capacity,
    #[error("a Cloud relay authority epoch must be nonzero")]
    ZeroEpoch,
    #[error("the Cloud relay upload frame is out of order")]
    FrameOrder,
    #[error("the Cloud relay upload length or ciphertext digest differs")]
    Integrity,
    #[error("Cloud relay route framing is invalid")]
    Command(#[from] super::CommandError),
    #[error("Cloud relay record framing is invalid")]
    Record(#[from] super::RecordError),
    #[error("Cloud key material routing is invalid")]
    Material(#[from] super::MaterialError),
}
