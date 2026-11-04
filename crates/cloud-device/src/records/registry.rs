//! `cloud-runner-registry` / `trusted-runners-v1`: the runners the account enrolled and pinned.
//!
//! Context: `nocterm/private-runner-registry/v1` ‖ u16 len ‖ hub namespace ‖ u16 len ‖
//! account id ‖ authority fingerprint (32) ‖ account key digest (32).
//! Plaintext: context ‖ version u64 ‖ count u8 ‖ rows sorted by runner id, each runner id (16)
//! ‖ key epoch u64 ‖ encryption (32) ‖ signing (32) ‖ proof (32) ‖ u8 len ‖ label.
//! The registry only grows, so its version equals its row count and the Store object version.
use super::{Reader, StoredObject, collection_uuid, push_u16_text};
use crate::{AccountScope, CloudDeviceError};
use nocterm_hub_model::cloud::RunnerCoordinate;
use nocterm_keys::CollectionKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const RUNNER_REGISTRY_KIND: &str = "cloud-runner-registry";
pub const RUNNER_REGISTRY_OBJECT: &str = "trusted-runners-v1";
pub const MAX_TRUSTED_RUNNERS: usize = 16;
const LABEL: &[u8] = b"nocterm/private-runner-registry/v1";
const COLLECTION_LABEL: &[u8] = b"nocterm/private-runner-registry/collection/v1";
const MAX_PLAINTEXT: usize = 8 * 1024;
const MAX_LABEL: usize = 128;

/// The three keys a device pins for one runner. Plain data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunnerPins {
    /// X25519 key commands, head queries and chat key grants are sealed to.
    pub encryption: [u8; 32],
    /// Ed25519 key that signs records and head witnesses.
    pub signing: [u8; 32],
    /// Ed25519 key the hub reports as the publishing runner's transport origin.
    pub proof: [u8; 32],
}

/// One enrolled runner with its pins and the label the person gave it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedRunner {
    runner: RunnerCoordinate,
    pins: RunnerPins,
    label: String,
}
impl TrustedRunner {
    pub fn new(
        runner: RunnerCoordinate,
        pins: RunnerPins,
        label: &str,
    ) -> Result<Self, CloudDeviceError> {
        if runner.key_epoch == 0 {
            return Err(CloudDeviceError::Format);
        }
        if label.is_empty() || label.len() > MAX_LABEL || label.chars().any(char::is_control) {
            return Err(CloudDeviceError::Capacity);
        }
        Ok(Self {
            runner,
            pins,
            label: label.to_owned(),
        })
    }
    pub fn runner(&self) -> RunnerCoordinate {
        self.runner
    }
    pub fn pins(&self) -> RunnerPins {
        self.pins
    }
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// The decoded registry of one account scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerRegistry {
    scope: AccountScope,
    runners: Vec<TrustedRunner>,
}
impl RunnerRegistry {
    /// Sorts the rows by runner id and refuses duplicates or more than 16 runners.
    pub fn new(
        scope: AccountScope,
        mut runners: Vec<TrustedRunner>,
    ) -> Result<Self, CloudDeviceError> {
        if runners.len() > MAX_TRUSTED_RUNNERS {
            return Err(CloudDeviceError::Capacity);
        }
        runners.sort_by_key(|row| row.runner.id);
        if runners
            .windows(2)
            .any(|pair| pair[0].runner.id == pair[1].runner.id)
        {
            return Err(CloudDeviceError::Format);
        }
        Ok(Self { scope, runners })
    }
    pub fn scope(&self) -> &AccountScope {
        &self.scope
    }
    pub fn runners(&self) -> &[TrustedRunner] {
        &self.runners
    }
    pub fn runner(&self, id: &[u8; 16]) -> Option<&TrustedRunner> {
        self.runners.iter().find(|row| &row.runner.id == id)
    }
    /// The registry version, which is its row count.
    pub fn version(&self) -> u64 {
        self.runners.len() as u64
    }
    pub fn context(scope: &AccountScope) -> Result<Vec<u8>, CloudDeviceError> {
        let mut bytes = LABEL.to_vec();
        push_u16_text(&mut bytes, scope.hub_instance())?;
        push_u16_text(&mut bytes, scope.account_id())?;
        bytes.extend_from_slice(&scope.authority_fingerprint());
        bytes.extend_from_slice(&scope.account_key_digest());
        Ok(bytes)
    }
    pub fn collection_id(scope: &AccountScope) -> Result<String, CloudDeviceError> {
        let mut hash = Sha256::new();
        hash.update(COLLECTION_LABEL);
        hash.update(Self::context(scope)?);
        hash.update(RUNNER_REGISTRY_KIND.as_bytes());
        Ok(collection_uuid(&hash.finalize()))
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CloudDeviceError> {
        let mut bytes = Zeroizing::new(Self::context(&self.scope)?);
        bytes.extend_from_slice(&self.version().to_be_bytes());
        bytes.push(u8::try_from(self.runners.len()).map_err(|_| CloudDeviceError::Capacity)?);
        for row in &self.runners {
            bytes.extend_from_slice(&row.runner.id);
            bytes.extend_from_slice(&row.runner.key_epoch.to_be_bytes());
            bytes.extend_from_slice(&row.pins.encryption);
            bytes.extend_from_slice(&row.pins.signing);
            bytes.extend_from_slice(&row.pins.proof);
            bytes.push(u8::try_from(row.label.len()).map_err(|_| CloudDeviceError::Capacity)?);
            bytes.extend_from_slice(row.label.as_bytes());
        }
        if bytes.len() > MAX_PLAINTEXT {
            return Err(CloudDeviceError::Capacity);
        }
        Ok(bytes)
    }
    /// Decodes the registry stored at Store object version `version`.
    pub fn decode(
        scope: &AccountScope,
        version: u64,
        plaintext: &[u8],
    ) -> Result<Self, CloudDeviceError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(CloudDeviceError::Capacity);
        }
        let context = Self::context(scope)?;
        let body = plaintext
            .strip_prefix(context.as_slice())
            .ok_or(CloudDeviceError::Binding)?;
        let mut reader = Reader::new(body);
        let stored = reader.u64()?;
        let count = usize::from(reader.u8()?);
        if count == 0 || count > MAX_TRUSTED_RUNNERS || stored != version || version != count as u64
        {
            return Err(CloudDeviceError::Format);
        }
        let mut runners: Vec<TrustedRunner> = Vec::with_capacity(count);
        for _ in 0..count {
            let runner = RunnerCoordinate {
                id: reader.array()?,
                key_epoch: reader.u64()?,
            };
            let pins = RunnerPins {
                encryption: reader.array()?,
                signing: reader.array()?,
                proof: reader.array()?,
            };
            let length = usize::from(reader.u8()?);
            if length == 0 || length > MAX_LABEL {
                return Err(CloudDeviceError::Capacity);
            }
            let row = TrustedRunner::new(runner, pins, reader.text(length)?)?;
            if runners
                .last()
                .is_some_and(|previous| previous.runner.id >= row.runner.id)
            {
                return Err(CloudDeviceError::Format);
            }
            runners.push(row);
        }
        reader.finish()?;
        Ok(Self {
            scope: scope.clone(),
            runners,
        })
    }
    /// Opens the registry from its personal collection, whose id must be the derived one.
    pub fn open(
        key: &CollectionKey,
        scope: &AccountScope,
        object: &StoredObject<'_>,
    ) -> Result<Self, CloudDeviceError> {
        let collection = Self::collection_id(scope)?;
        let plaintext = object.open(
            key,
            (&collection, RUNNER_REGISTRY_OBJECT, RUNNER_REGISTRY_KIND),
            None,
            MAX_PLAINTEXT,
        )?;
        if object.version > MAX_TRUSTED_RUNNERS as u64 {
            return Err(CloudDeviceError::ObjectVersion(object.version));
        }
        Self::decode(scope, object.version, &plaintext)
    }
}
