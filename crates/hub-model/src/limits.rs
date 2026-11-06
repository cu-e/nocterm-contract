//! Bounds every client and the hub apply to what people type and send.

/// Longest name of an agent, provider, server or chat title, in bytes.
pub const MAX_NAME_BYTES: usize = 200;
/// Longest agent instructions, in bytes.
pub const MAX_INSTRUCTIONS_BYTES: usize = 32 * 1024;
/// Longest message a person sends, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Most attachments of one message.
pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 10;
/// Most servers one chat or agent may use.
pub const MAX_SERVERS_PER_CHAT: usize = 32;
/// Most models one provider or agent lists.
pub const MAX_MODELS: usize = 64;
/// Largest part of an upload, in bytes.
pub const UPLOAD_PART_BYTES: usize = 1024 * 1024;
/// Most chats one `Watch` follows.
pub const MAX_WATCHED_CHATS: usize = 8;
/// Largest page of chats or items one call returns.
pub const MAX_PAGE: u32 = 200;
/// Default SSH port.
pub const DEFAULT_SSH_PORT: u16 = 22;

/// One named bound, for clients that render the limits into another language (the web panel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    pub name: &'static str,
    pub value: usize,
}

/// Every bound above, by name.
pub const ALL: &[Limit] = &[
    Limit {
        name: "max_name_bytes",
        value: MAX_NAME_BYTES,
    },
    Limit {
        name: "max_instructions_bytes",
        value: MAX_INSTRUCTIONS_BYTES,
    },
    Limit {
        name: "max_message_bytes",
        value: MAX_MESSAGE_BYTES,
    },
    Limit {
        name: "max_attachments_per_message",
        value: MAX_ATTACHMENTS_PER_MESSAGE,
    },
    Limit {
        name: "max_servers_per_chat",
        value: MAX_SERVERS_PER_CHAT,
    },
    Limit {
        name: "max_models",
        value: MAX_MODELS,
    },
    Limit {
        name: "upload_part_bytes",
        value: UPLOAD_PART_BYTES,
    },
    Limit {
        name: "max_watched_chats",
        value: MAX_WATCHED_CHATS,
    },
];
