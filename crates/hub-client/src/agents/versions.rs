//! The version history of an agent's public listing.
use nocterm_hub_model::AccountId;
use nocterm_hub_model::agents::{AgentListing, limits};
use nocterm_hub_proto::{WireError, v1};

/// One written version of an agent's listing. Public fields only: the hub never returns
/// envelopes or anything sealed in the history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentVersion {
    /// The version, equal to `listing.version`.
    pub version: u64,
    /// The listing as it was written for this version. Its availability says nothing.
    pub listing: AgentListing,
    /// When the version was written, in milliseconds since the Unix epoch.
    pub updated_at_ms: i64,
    /// The account that wrote it.
    pub updated_by: AccountId,
}

/// One page of an agent's versions, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentVersionPage {
    /// The versions of this page.
    pub versions: Vec<AgentVersion>,
    /// Cursor of the next page; `None` after the last one.
    pub next: Option<String>,
}

impl TryFrom<&v1::AgentVersion> for AgentVersion {
    type Error = WireError;

    fn try_from(wire: &v1::AgentVersion) -> Result<Self, WireError> {
        let listing = AgentListing::try_from(
            wire.listing
                .as_ref()
                .ok_or(WireError::Field("version.listing"))?,
        )?;
        if listing.version != wire.version {
            return Err(WireError::Field("version.version"));
        }
        let updated_by = wire
            .updated_by_account_id
            .parse()
            .map_err(|_| WireError::Id("version.updated_by_account_id"))?;
        Ok(Self {
            version: wire.version,
            listing,
            updated_at_ms: wire.updated_at_ms,
            updated_by,
        })
    }
}

impl TryFrom<&v1::AgentVersionList> for AgentVersionPage {
    type Error = WireError;

    fn try_from(wire: &v1::AgentVersionList) -> Result<Self, WireError> {
        if wire.versions.len() > limits::MAX_PAGE_ENTRIES {
            return Err(WireError::Field("versions"));
        }
        if wire.next.len() > MAX_CURSOR_BYTES {
            return Err(WireError::Field("next"));
        }
        Ok(Self {
            versions: wire
                .versions
                .iter()
                .map(AgentVersion::try_from)
                .collect::<Result<_, _>>()?,
            next: (!wire.next.is_empty()).then(|| wire.next.clone()),
        })
    }
}

/// Longest page cursor the protocol allows.
pub(super) const MAX_CURSOR_BYTES: usize = 256;
