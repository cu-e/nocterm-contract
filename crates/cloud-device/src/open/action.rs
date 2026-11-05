//! Captured requests of one open chat, including inline prompt image admission.
use nocterm_hub_model::cloud::{payload::ImageMime, ssh::SshServerId};
use std::{fmt, sync::Arc};

/// At most eight images and twenty MiB of image bytes belong to one prompt.
pub const MAX_PROMPT_IMAGES: usize = 8;
pub const MAX_PROMPT_IMAGE_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_PROMPT_IMAGE_TOTAL_BYTES: usize = 20 * 1024 * 1024;

/// Immutable inline bytes. Debug reports only their length.
#[derive(Clone, PartialEq, Eq)]
pub struct PromptImage {
    pub mime: ImageMime,
    pub bytes: Arc<[u8]>,
}
impl fmt::Debug for PromptImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PromptImage")
            .field("mime", &self.mime)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// A model a prompt names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelChoice {
    pub provider: String,
    pub model: String,
}

/// What the person asks of an open chat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatAction {
    /// A prompt; without a model, the latest run's. With a `server`, it runs against that bound
    /// server ([`crate::transcript::ChatSsh::session_targets`]); without one, at the runner's
    /// default destination.
    Prompt {
        text: String,
        model: Option<ModelChoice>,
        server: Option<SshServerId>,
    },
    /// Inline images use the protocol's existing prompt image parts.
    PromptWithImages {
        text: String,
        model: Option<ModelChoice>,
        server: Option<SshServerId>,
        images: Vec<PromptImage>,
    },
    /// Stop a run; without one, the active run.
    Stop {
        run: Option<[u8; 16]>,
    },
    /// The model grant of a run this device prompted, with that run's model.
    Allow {
        run: [u8; 16],
    },
    Answer {
        intent: [u8; 16],
        approve: bool,
    },
}

impl ChatAction {
    pub(crate) fn images(&self) -> &[PromptImage] {
        match self {
            Self::PromptWithImages { images, .. } => images,
            _ => &[],
        }
    }
}
