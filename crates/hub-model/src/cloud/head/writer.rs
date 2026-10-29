use super::{
    CatalogHeadCursor, CatalogHeadPage, ChatHead, HeadProbeError, HeadProbeScope, HeadQuery,
    HeadRecordAnchor, HeadTarget, HeadValue, HeadWitness, MAX_HEAD_CATALOG_CHATS,
    MAX_HEAD_CATALOG_PAGE, MAX_HEAD_QUERY_BYTES, MAX_HEAD_WITNESS_BYTES, ReceiptOutcome,
};
use crate::cloud::{RecordKind, RunCoordinate, codec::BoundedWriter};

pub(super) const SCOPE: &[u8] = b"nocterm/cloud-head-scope/v1";
pub(super) const QUERY: &[u8] = b"nocterm/cloud-head-query/v1";
pub(super) const WITNESS: &[u8] = b"nocterm/cloud-head-witness/v1";

pub(super) fn scope(value: &HeadProbeScope) -> Result<Vec<u8>, HeadProbeError> {
    let mut out = HeadWriter(BoundedWriter::buffer(MAX_HEAD_QUERY_BYTES));
    out.scope(value)?;
    Ok(out.0.into_bytes()?)
}
pub(super) fn validate_query(value: &HeadQuery) -> Result<(), HeadProbeError> {
    HeadWriter(BoundedWriter::counter(MAX_HEAD_QUERY_BYTES)).query(value)
}
pub(super) fn query(value: &HeadQuery) -> Result<Vec<u8>, HeadProbeError> {
    let mut out = HeadWriter(BoundedWriter::buffer(MAX_HEAD_QUERY_BYTES));
    out.query(value)?;
    Ok(out.0.into_bytes()?)
}
pub(super) fn validate_witness(value: &HeadWitness) -> Result<(), HeadProbeError> {
    HeadWriter(BoundedWriter::counter(MAX_HEAD_WITNESS_BYTES)).witness(value)
}
pub(super) fn witness(value: &HeadWitness) -> Result<Vec<u8>, HeadProbeError> {
    let mut out = HeadWriter(BoundedWriter::buffer(MAX_HEAD_WITNESS_BYTES));
    out.witness(value)?;
    Ok(out.0.into_bytes()?)
}
pub(super) fn signed(
    body: &[u8],
    signature: &[u8; 64],
    maximum: usize,
) -> Result<Vec<u8>, HeadProbeError> {
    let mut out = BoundedWriter::buffer(maximum);
    out.field(body)?;
    out.extend(signature)?;
    Ok(out.into_bytes()?)
}
struct HeadWriter(BoundedWriter);
impl HeadWriter {
    fn raw(&mut self, value: &[u8]) -> Result<(), HeadProbeError> {
        Ok(self.0.extend(value)?)
    }
    fn field(&mut self, value: &[u8]) -> Result<(), HeadProbeError> {
        Ok(self.0.field(value)?)
    }
    fn flag(&mut self, value: bool) -> Result<(), HeadProbeError> {
        self.raw(&[u8::from(value)])
    }
    fn number(&mut self, value: u64) -> Result<(), HeadProbeError> {
        self.raw(&value.to_be_bytes())
    }
    fn scope(&mut self, value: &HeadProbeScope) -> Result<(), HeadProbeError> {
        if value.runner.key_epoch == 0 {
            return Err(HeadProbeError::Value);
        }
        self.field(SCOPE)?;
        self.field(value.namespace.hub_instance_id.as_str().as_bytes())?;
        self.field(value.namespace.account_id.as_str().as_bytes())?;
        self.raw(&value.runner.id)?;
        self.number(value.runner.key_epoch)?;
        self.raw(&value.keys.account)?;
        self.raw(&value.keys.runner_encryption)?;
        self.raw(&value.keys.runner_signing)
    }
    fn cursor(&mut self, value: &CatalogHeadCursor) -> Result<(), HeadProbeError> {
        if value.revision == 0 || value.seen == 0 || value.seen > MAX_HEAD_CATALOG_CHATS {
            return Err(HeadProbeError::Position);
        }
        self.number(value.revision)?;
        self.raw(&value.digest)?;
        self.raw(&value.after)?;
        self.raw(&value.seen.to_be_bytes())
    }
    fn query(&mut self, value: &HeadQuery) -> Result<(), HeadProbeError> {
        self.field(QUERY)?;
        self.scope(&value.scope)?;
        self.field(value.issuer.device_id.as_str().as_bytes())?;
        self.raw(&value.issuer.signing_key)?;
        self.raw(&value.issuer.access_token_digest)?;
        self.raw(&value.probe_id)?;
        self.raw(&value.challenge)?;
        self.raw(&value.window.issued_at_ms.to_be_bytes())?;
        self.raw(&value.window.expires_at_ms.to_be_bytes())?;
        self.target(&value.target)
    }
    fn target(&mut self, value: &HeadTarget) -> Result<(), HeadProbeError> {
        match value {
            HeadTarget::Catalog { after } => {
                self.raw(&[1])?;
                self.flag(after.is_some())?;
                if let Some(cursor) = after {
                    self.cursor(cursor)?;
                }
                Ok(())
            }
            HeadTarget::Chat {
                chat_id,
                chat_key_epoch,
            } => {
                self.raw(&[2])?;
                self.chat_key(chat_id, *chat_key_epoch)
            }
            HeadTarget::CommandReceipt {
                chat_id,
                chat_key_epoch,
                command_id,
                semantic_digest,
                expected_control_revision,
            } => {
                self.raw(&[3])?;
                self.chat_key(chat_id, *chat_key_epoch)?;
                self.raw(command_id)?;
                self.raw(semantic_digest)?;
                self.number(*expected_control_revision)
            }
        }
    }
    fn chat_key(&mut self, id: &[u8; 16], epoch: u64) -> Result<(), HeadProbeError> {
        if epoch == 0 {
            return Err(HeadProbeError::Value);
        }
        self.raw(id)?;
        self.number(epoch)
    }
    fn optional_number(&mut self, value: Option<u64>) -> Result<(), HeadProbeError> {
        if value == Some(0) {
            return Err(HeadProbeError::Position);
        }
        self.flag(value.is_some())?;
        if let Some(value) = value {
            self.number(value)?;
        }
        Ok(())
    }
    fn run(&mut self, value: Option<RunCoordinate>) -> Result<(), HeadProbeError> {
        self.flag(value.is_some())?;
        if let Some(run) = value {
            if run.expected_epoch == 0 {
                return Err(HeadProbeError::Value);
            }
            self.raw(&run.id)?;
            self.number(run.expected_epoch)?;
        }
        Ok(())
    }
    fn anchor(&mut self, value: &HeadRecordAnchor) -> Result<(), HeadProbeError> {
        let pos = value.position;
        if [
            pos.writer_epoch,
            pos.sequence,
            pos.journal_sequence,
            pos.revision,
        ]
        .contains(&0)
        {
            return Err(HeadProbeError::Position);
        }
        self.raw(&[value.kind as u8])?;
        for number in [
            pos.writer_epoch,
            pos.sequence,
            pos.journal_sequence,
            pos.revision,
        ] {
            self.number(number)?;
        }
        self.raw(&value.id)?;
        self.run(value.run)?;
        self.raw(&value.ciphertext_digest)
    }
    fn optional_anchor(&mut self, value: Option<&HeadRecordAnchor>) -> Result<(), HeadProbeError> {
        self.flag(value.is_some())?;
        if let Some(value) = value {
            self.anchor(value)?;
        }
        Ok(())
    }
    fn head(&mut self, value: &ChatHead) -> Result<(), HeadProbeError> {
        validate_head(value)?;
        self.chat_key(&value.chat_id, value.chat_key_epoch)?;
        self.optional_number(value.current_writer)?;
        self.number(value.control_revision)?;
        self.flag(value.deleted)?;
        self.optional_anchor(value.head.as_ref())?;
        self.number(value.retained_from)?;
        self.optional_anchor(value.snapshot.as_ref())
    }
    fn page(&mut self, value: &CatalogHeadPage) -> Result<(), HeadProbeError> {
        validate_page(value)?;
        self.number(value.revision)?;
        self.raw(&value.digest)?;
        self.raw(&value.total_chats.to_be_bytes())?;
        self.flag(value.after.is_some())?;
        if let Some(cursor) = &value.after {
            self.cursor(cursor)?;
        }
        self.raw(
            &u16::try_from(value.chats.len())
                .map_err(|_| HeadProbeError::Bounds)?
                .to_be_bytes(),
        )?;
        for head in &value.chats {
            self.head(head)?;
        }
        self.flag(value.has_more)
    }
    fn receipt(&mut self, value: ReceiptOutcome) -> Result<(), HeadProbeError> {
        match value {
            ReceiptOutcome::NotFound => self.raw(&[1]),
            ReceiptOutcome::Accepted { control_revision } => {
                if control_revision == 0 {
                    return Err(HeadProbeError::Position);
                }
                self.raw(&[2])?;
                self.number(control_revision)
            }
            ReceiptOutcome::Conflict => self.raw(&[3]),
            ReceiptOutcome::Unknown => self.raw(&[4]),
        }
    }
    fn witness(&mut self, value: &HeadWitness) -> Result<(), HeadProbeError> {
        self.field(WITNESS)?;
        self.field(&value.query.canonical_bytes()?)?;
        self.raw(&value.observed_at_ms.to_be_bytes())?;
        match &value.value {
            HeadValue::Catalog(page) => {
                self.raw(&[1])?;
                self.page(page)
            }
            HeadValue::Chat(head) => {
                self.raw(&[2])?;
                self.head(head)
            }
            HeadValue::CommandReceipt(value) => {
                self.raw(&[3])?;
                self.receipt(*value)
            }
        }
    }
}
fn validate_head(value: &ChatHead) -> Result<(), HeadProbeError> {
    let Some(head) = &value.head else {
        return if value.control_revision == 0
            && !value.deleted
            && value.retained_from == 0
            && value.snapshot.is_none()
        {
            Ok(())
        } else {
            Err(HeadProbeError::Position)
        };
    };
    if value
        .current_writer
        .is_none_or(|writer| head.position.writer_epoch > writer)
        || value.retained_from == 0
        || (value.retained_from > head.position.sequence
            && !(value.deleted
                && value.snapshot.is_none()
                && head.position.sequence.checked_add(1) == Some(value.retained_from)))
    {
        return Err(HeadProbeError::Position);
    }
    if let Some(snapshot) = &value.snapshot {
        if snapshot.kind != RecordKind::Snapshot
            || snapshot.position.sequence != value.retained_from
            || snapshot.position.sequence > head.position.sequence
            || value
                .current_writer
                .is_none_or(|writer| snapshot.position.writer_epoch > writer)
            || (snapshot.position.sequence == head.position.sequence && snapshot != head)
        {
            return Err(HeadProbeError::Position);
        }
    } else if !value.deleted && value.retained_from > 1 {
        return Err(HeadProbeError::Position);
    }
    Ok(())
}
fn validate_page(value: &CatalogHeadPage) -> Result<(), HeadProbeError> {
    if value.revision == 0
        || value.chats.len() > MAX_HEAD_CATALOG_PAGE
        || value.total_chats > MAX_HEAD_CATALOG_CHATS
    {
        return Err(HeadProbeError::Bounds);
    }
    let mut previous = value.after.as_ref().map(|cursor| cursor.after);
    let seen = value.after.as_ref().map_or(0, |cursor| cursor.seen);
    if value
        .after
        .as_ref()
        .is_some_and(|cursor| cursor.revision != value.revision || cursor.digest != value.digest)
    {
        return Err(HeadProbeError::Position);
    }
    for head in &value.chats {
        if previous.is_some_and(|id| head.chat_id <= id) {
            return Err(HeadProbeError::Position);
        }
        previous = Some(head.chat_id);
    }
    let through = seen
        .checked_add(u32::try_from(value.chats.len()).map_err(|_| HeadProbeError::Bounds)?)
        .ok_or(HeadProbeError::Bounds)?;
    if through > value.total_chats
        || value.has_more != (through < value.total_chats)
        || (value.has_more && value.chats.is_empty())
    {
        return Err(HeadProbeError::Position);
    }
    Ok(())
}
