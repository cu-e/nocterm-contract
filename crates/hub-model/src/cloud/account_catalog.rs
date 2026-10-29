//! Native catalog context is account/runner scoped and never invents a chat identity.
use super::{
    CloudNamespace, CommandError, RunnerCoordinate,
    codec::{self, Reader},
};
pub const MAX_ACCOUNT_CATALOG_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountCatalogCoordinate {
    namespace: CloudNamespace,
    account_key_fingerprint: [u8; 32],
    runner: RunnerCoordinate,
    revision: u64,
}
impl AccountCatalogCoordinate {
    pub fn new(
        namespace: CloudNamespace,
        account_key_fingerprint: [u8; 32],
        runner: RunnerCoordinate,
        revision: u64,
    ) -> Result<Self, AccountCatalogError> {
        if runner.key_epoch == 0 || revision == 0 {
            return Err(AccountCatalogError::Position);
        }
        Ok(Self {
            namespace,
            account_key_fingerprint,
            runner,
            revision,
        })
    }
    pub fn namespace(&self) -> &CloudNamespace {
        &self.namespace
    }
    pub fn account_key_fingerprint(&self) -> [u8; 32] {
        self.account_key_fingerprint
    }
    pub fn runner(&self) -> RunnerCoordinate {
        self.runner
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AccountCatalogError> {
        let mut bytes = Vec::with_capacity(384);
        codec::field(&mut bytes, b"nocterm/cloud-native-account-catalog/v1")?;
        codec::field(
            &mut bytes,
            self.namespace.hub_instance_id.as_str().as_bytes(),
        )?;
        codec::field(&mut bytes, self.namespace.account_id.as_str().as_bytes())?;
        bytes.extend_from_slice(&self.account_key_fingerprint);
        bytes.extend_from_slice(&self.runner.id);
        bytes.extend_from_slice(&self.runner.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AccountCatalogError> {
        if bytes.len() > 512 {
            return Err(AccountCatalogError::Malformed);
        }
        let mut reader = Reader::new(bytes);
        if reader.field(64)? != b"nocterm/cloud-native-account-catalog/v1" {
            return Err(AccountCatalogError::Malformed);
        }
        let namespace = CloudNamespace {
            hub_instance_id: reader.text()?,
            account_id: reader.text()?,
        };
        let account_key_fingerprint = reader.array()?;
        let runner = RunnerCoordinate {
            id: reader.array()?,
            key_epoch: u64::from_be_bytes(reader.array()?),
        };
        let revision = u64::from_be_bytes(reader.array()?);
        reader.finish()?;
        Self::new(namespace, account_key_fingerprint, runner, revision)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccountCatalogError {
    #[error("native catalog runner epoch and revision must be positive")]
    Position,
    #[error("malformed native account catalog context")]
    Malformed,
    #[error("native account catalog framing is invalid")]
    Framing(#[from] CommandError),
}
