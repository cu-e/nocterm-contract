//! How a listing merges a runner's directory with its fresh catalog witness. Rows are never
//! replayed: a summary says what the chat is, the witness says whether that is still so.
//!
//! - summary and witness: [`RowStatus::Current`] when the summary reaches the witnessed head
//!   (the same key epoch, head sequence and control revision not behind the witness, the same
//!   record digest at an equal sequence, deleted when the witness says so), otherwise
//!   [`RowStatus::Stale`]. A summary ahead of the witness is current: the runner signed it
//!   after the witness;
//! - witness only: [`RowStatus::Unsummarized`] (the hub withholds the summary or the runner has
//!   not published one yet);
//! - summary only: [`RowStatus::Pending`] while the catalog probe is out,
//!   [`RowStatus::Unlisted`] when the runner's complete catalog does not list the chat, and
//!   [`RowStatus::AsOf`] when the runner did not answer, its answer was refused or its catalog
//!   was not read to the end (the summary as of its last activity).
use super::RunnerDirectory;
use crate::context::ChatRef;
use nocterm_hub_model::cloud::{
    head::ChatHead,
    summary::{ChatState, ChatSummary, SignedChatSummary},
};

/// How far a listed row is confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowStatus {
    /// The runner's fresh witness confirms the summary.
    Current,
    /// The runner witnessed a newer head than the summary: open the chat for its state.
    Stale,
    /// The runner witnessed the chat, the directory holds no summary of it.
    Unsummarized,
    /// The summary waits for the runner's catalog.
    Pending,
    /// The runner did not confirm the summary: shown as of its last activity.
    AsOf,
    /// The runner's complete catalog does not list the chat.
    Unlisted,
}

/// One listed chat. Plain data: the witnessed fields when the runner witnessed the chat,
/// otherwise the summary's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedChat {
    pub chat: ChatRef,
    /// The runner's verified summary, when the directory holds one.
    pub summary: Option<ChatSummary>,
    pub status: RowStatus,
    pub control_revision: u64,
    /// The sequence of the newest record, `None` for a chat without records.
    pub head_sequence: Option<u64>,
    pub deleted: bool,
    /// When the runner witnessed the chat in this listing.
    pub witnessed_at_ms: Option<i64>,
}

/// One chat of a runner's catalog witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WitnessedChat {
    pub(crate) head: ChatHead,
    pub(crate) at_ms: i64,
}

/// What the runner's catalog said in this listing.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Catalog<'a> {
    /// The probe is out.
    Pending,
    /// The runner answered; `complete` when every page was read.
    Answered {
        chats: &'a [WitnessedChat],
        complete: bool,
    },
    /// The runner did not answer, or its answer was refused.
    Unanswered,
}

/// The rows of one runner: summarized chats by last activity (newest first), then witnessed
/// chats without a summary, each group in chat id order where equal.
pub(crate) fn merge(
    runner: [u8; 16],
    directory: Option<&RunnerDirectory>,
    catalog: Catalog<'_>,
) -> Vec<ListedChat> {
    let witnessed: &[WitnessedChat] = match catalog {
        Catalog::Answered { chats, .. } => chats,
        Catalog::Pending | Catalog::Unanswered => &[],
    };
    let find = |chat_id: [u8; 16]| witnessed.iter().find(|seen| seen.head.chat_id == chat_id);
    let mut rows: Vec<ListedChat> = directory
        .into_iter()
        .flat_map(RunnerDirectory::rows)
        .map(|row| {
            let context = row.summary().context();
            let summary = row.summary().summary();
            let chat = context.chat();
            match find(chat.chat_id()) {
                Some(seen) => witnessed_row(runner, Some(row.summary()), seen),
                None => ListedChat {
                    chat: ChatRef {
                        runner,
                        chat_id: chat.chat_id(),
                        key_epoch: chat.key_epoch(),
                    },
                    summary: Some(summary.clone()),
                    status: unwitnessed(catalog),
                    control_revision: summary.control_revision,
                    head_sequence: summary.head.map(|head| head.sequence),
                    deleted: summary.state == ChatState::Deleted,
                    witnessed_at_ms: None,
                },
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        let at = |row: &ListedChat| row.summary.as_ref().map(|s| s.last_activity_ms);
        at(b).cmp(&at(a)).then(a.chat.chat_id.cmp(&b.chat.chat_id))
    });
    let mut bare: Vec<ListedChat> = witnessed
        .iter()
        .filter(|seen| directory.is_none_or(|d| d.row(&seen.head.chat_id).is_none()))
        .map(|seen| witnessed_row(runner, None, seen))
        .collect();
    bare.sort_by_key(|row| row.chat.chat_id);
    rows.extend(bare);
    rows
}

fn unwitnessed(catalog: Catalog<'_>) -> RowStatus {
    match catalog {
        Catalog::Pending => RowStatus::Pending,
        Catalog::Answered { complete: true, .. } => RowStatus::Unlisted,
        Catalog::Answered {
            complete: false, ..
        }
        | Catalog::Unanswered => RowStatus::AsOf,
    }
}

fn witnessed_row(
    runner: [u8; 16],
    summary: Option<&SignedChatSummary>,
    seen: &WitnessedChat,
) -> ListedChat {
    let head = &seen.head;
    ListedChat {
        chat: ChatRef {
            runner,
            chat_id: head.chat_id,
            key_epoch: head.chat_key_epoch,
        },
        summary: summary.map(|signed| signed.summary().clone()),
        status: summary.map_or(RowStatus::Unsummarized, |signed| confirm(signed, head)),
        control_revision: head.control_revision,
        head_sequence: head.head.as_ref().map(|anchor| anchor.position.sequence),
        deleted: head.deleted,
        witnessed_at_ms: Some(seen.at_ms),
    }
}

fn confirm(signed: &SignedChatSummary, head: &ChatHead) -> RowStatus {
    let summary = signed.summary();
    let summarized = summary.head.map(|h| (h.sequence, h.ciphertext_digest));
    let witnessed = head
        .head
        .as_ref()
        .map(|anchor| (anchor.position.sequence, anchor.ciphertext_digest));
    let sequence = |head: Option<(u64, [u8; 32])>| head.map_or(0, |(sequence, _)| sequence);
    let behind = signed.context().chat().key_epoch() != head.chat_key_epoch
        || sequence(summarized) < sequence(witnessed)
        || summary.control_revision < head.control_revision
        || (sequence(summarized) == sequence(witnessed) && summarized != witnessed)
        || (head.deleted && summary.state != ChatState::Deleted);
    if behind {
        RowStatus::Stale
    } else {
        RowStatus::Current
    }
}
