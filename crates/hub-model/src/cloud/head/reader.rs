use super::{
    CatalogHeadCursor, CatalogHeadPage, ChatHead, HeadProbeError, HeadProbeKeys, HeadProbeScope,
    HeadQuery, HeadRecordAnchor, HeadTarget, HeadValue, HeadWitness, MAX_HEAD_CATALOG_PAGE,
    MAX_HEAD_QUERY_BYTES, MAX_HEAD_WITNESS_BYTES, ReceiptOutcome, writer,
};
use crate::cloud::{
    CloudNamespace, CommandIssuer, RecordKind, RecordPosition, RunCoordinate, RunnerCoordinate,
    capabilities::CapabilityWindow, codec::Reader,
};

pub(super) fn scope(bytes: &[u8]) -> Result<HeadProbeScope, HeadProbeError> {
    if bytes.len() > MAX_HEAD_QUERY_BYTES {
        return Err(HeadProbeError::Bounds);
    }
    let mut input = HeadReader(Reader::new(bytes));
    let value = input.scope()?;
    input.0.finish()?;
    value.canonical_bytes()?;
    Ok(value)
}
pub(super) fn query(bytes: &[u8]) -> Result<HeadQuery, HeadProbeError> {
    if bytes.len() > MAX_HEAD_QUERY_BYTES {
        return Err(HeadProbeError::Bounds);
    }
    let mut input = HeadReader(Reader::new(bytes));
    let value = input.query()?;
    input.0.finish()?;
    value.validate()?;
    Ok(value)
}
pub(super) fn witness(bytes: &[u8]) -> Result<HeadWitness, HeadProbeError> {
    if bytes.len() > MAX_HEAD_WITNESS_BYTES {
        return Err(HeadProbeError::Bounds);
    }
    let mut input = HeadReader(Reader::new(bytes));
    if input.0.field(64)? != writer::WITNESS {
        return Err(HeadProbeError::Value);
    }
    let query = HeadQuery::from_canonical_bytes(input.0.field(MAX_HEAD_QUERY_BYTES)?)?;
    let observed_at_ms = i64::from_be_bytes(input.0.array()?);
    let value = match input.tag()? {
        1 => HeadValue::Catalog(Box::new(input.page()?)),
        2 => HeadValue::Chat(Box::new(input.head()?)),
        3 => HeadValue::CommandReceipt(input.receipt()?),
        _ => return Err(HeadProbeError::Value),
    };
    input.0.finish()?;
    let result = HeadWitness {
        query,
        observed_at_ms,
        value,
    };
    result.validate()?;
    Ok(result)
}
pub(super) fn signed(bytes: &[u8], maximum: usize) -> Result<(&[u8], [u8; 64]), HeadProbeError> {
    if bytes.len() > maximum {
        return Err(HeadProbeError::Bounds);
    }
    let mut input = Reader::new(bytes);
    let body = input.field(maximum)?;
    let signature = input.array()?;
    input.finish()?;
    Ok((body, signature))
}
struct HeadReader<'a>(Reader<'a>);
impl HeadReader<'_> {
    fn tag(&mut self) -> Result<u8, HeadProbeError> {
        Ok(self.0.array::<1>()?[0])
    }
    fn flag(&mut self) -> Result<bool, HeadProbeError> {
        match self.tag()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(HeadProbeError::Value),
        }
    }
    fn number(&mut self) -> Result<u64, HeadProbeError> {
        Ok(u64::from_be_bytes(self.0.array()?))
    }
    fn scope(&mut self) -> Result<HeadProbeScope, HeadProbeError> {
        if self.0.field(64)? != writer::SCOPE {
            return Err(HeadProbeError::Value);
        }
        Ok(HeadProbeScope {
            namespace: CloudNamespace {
                hub_instance_id: self.0.text()?,
                account_id: self.0.text()?,
            },
            runner: RunnerCoordinate {
                id: self.0.array()?,
                key_epoch: self.number()?,
            },
            keys: HeadProbeKeys {
                account: self.0.array()?,
                runner_encryption: self.0.array()?,
                runner_signing: self.0.array()?,
            },
        })
    }
    fn cursor(&mut self) -> Result<CatalogHeadCursor, HeadProbeError> {
        Ok(CatalogHeadCursor {
            revision: self.number()?,
            digest: self.0.array()?,
            after: self.0.array()?,
            seen: u32::from_be_bytes(self.0.array()?),
        })
    }
    fn optional_cursor(&mut self) -> Result<Option<CatalogHeadCursor>, HeadProbeError> {
        if self.flag()? {
            Ok(Some(self.cursor()?))
        } else {
            Ok(None)
        }
    }
    fn query(&mut self) -> Result<HeadQuery, HeadProbeError> {
        if self.0.field(64)? != writer::QUERY {
            return Err(HeadProbeError::Value);
        }
        Ok(HeadQuery {
            scope: self.scope()?,
            issuer: CommandIssuer {
                device_id: self.0.text()?,
                signing_key: self.0.array()?,
                access_token_digest: self.0.array()?,
            },
            probe_id: self.0.array()?,
            challenge: self.0.array()?,
            window: CapabilityWindow {
                issued_at_ms: i64::from_be_bytes(self.0.array()?),
                expires_at_ms: i64::from_be_bytes(self.0.array()?),
            },
            target: self.target()?,
        })
    }
    fn target(&mut self) -> Result<HeadTarget, HeadProbeError> {
        Ok(match self.tag()? {
            1 => HeadTarget::Catalog {
                after: self.optional_cursor()?,
            },
            2 => HeadTarget::Chat {
                chat_id: self.0.array()?,
                chat_key_epoch: self.number()?,
            },
            3 => HeadTarget::CommandReceipt {
                chat_id: self.0.array()?,
                chat_key_epoch: self.number()?,
                command_id: self.0.array()?,
                semantic_digest: self.0.array()?,
                expected_control_revision: self.number()?,
            },
            _ => return Err(HeadProbeError::Value),
        })
    }
    fn run(&mut self) -> Result<Option<RunCoordinate>, HeadProbeError> {
        if self.flag()? {
            Ok(Some(RunCoordinate {
                id: self.0.array()?,
                expected_epoch: self.number()?,
            }))
        } else {
            Ok(None)
        }
    }
    fn anchor(&mut self) -> Result<HeadRecordAnchor, HeadProbeError> {
        let kind = match self.tag()? {
            1 => RecordKind::Event,
            2 => RecordKind::Snapshot,
            _ => return Err(HeadProbeError::Value),
        };
        Ok(HeadRecordAnchor {
            kind,
            position: RecordPosition {
                writer_epoch: self.number()?,
                sequence: self.number()?,
                journal_sequence: self.number()?,
                revision: self.number()?,
            },
            id: self.0.array()?,
            run: self.run()?,
            ciphertext_digest: self.0.array()?,
        })
    }
    fn optional_anchor(&mut self) -> Result<Option<HeadRecordAnchor>, HeadProbeError> {
        if self.flag()? {
            Ok(Some(self.anchor()?))
        } else {
            Ok(None)
        }
    }
    fn head(&mut self) -> Result<ChatHead, HeadProbeError> {
        Ok(ChatHead {
            chat_id: self.0.array()?,
            chat_key_epoch: self.number()?,
            current_writer: if self.flag()? {
                Some(self.number()?)
            } else {
                None
            },
            control_revision: self.number()?,
            deleted: self.flag()?,
            head: self.optional_anchor()?,
            retained_from: self.number()?,
            snapshot: self.optional_anchor()?,
        })
    }
    fn page(&mut self) -> Result<CatalogHeadPage, HeadProbeError> {
        let revision = self.number()?;
        let digest = self.0.array()?;
        let total_chats = u32::from_be_bytes(self.0.array()?);
        let after = self.optional_cursor()?;
        let count = usize::from(u16::from_be_bytes(self.0.array()?));
        if count > MAX_HEAD_CATALOG_PAGE {
            return Err(HeadProbeError::Bounds);
        }
        let chats = (0..count)
            .map(|_| self.head())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CatalogHeadPage {
            revision,
            digest,
            total_chats,
            after,
            chats,
            has_more: self.flag()?,
        })
    }
    fn receipt(&mut self) -> Result<ReceiptOutcome, HeadProbeError> {
        Ok(match self.tag()? {
            1 => ReceiptOutcome::NotFound,
            2 => ReceiptOutcome::Accepted {
                control_revision: self.number()?,
            },
            3 => ReceiptOutcome::Conflict,
            4 => ReceiptOutcome::Unknown,
            _ => return Err(HeadProbeError::Value),
        })
    }
}
