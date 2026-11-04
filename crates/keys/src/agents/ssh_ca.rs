//! The account's SSH CA for Cloud agents: the CA key, its `agent_ssh_trust` document, the
//! per-server principals and the OpenSSH user certificates it signs (contract ADR 0009; native
//! ADR 0119 made per-chat).
//!
//! A [`UserCa`] is an Ed25519 key whose seed lives only in the account's end-to-end encrypted
//! `agent_ssh_trust` collection ([`CaDocument`], object [`CA_OBJECT`]). It signs two things:
//! - a chat's [`SshBinding`] ([`UserCa::sign_binding`]), which names the servers, the window and
//!   the CA; any account device verifies it without trusting the runner or the hub;
//! - OpenSSH user certificates ([`UserCa::issue`]) that are narrower than any login of the person:
//!   only the principals of the bound servers ([`principal_for`]), at most 24 hours, a mandatory
//!   `source-address`, and the `permit-pty` extension alone (no port, agent or X11 forwarding,
//!   no user rc). An OpenSSH certificate grants nothing it does not list.
//!
//! The two signed values cannot be confused: a certificate blob starts with the length-prefixed
//! key type `ssh-ed25519-cert-v01@openssh.com`, a binding with the length-prefixed label
//! `nocterm/cloud-ssh-binding/v1`.
mod document;

pub use document::{CA_OBJECT, CaDocument, CaDocumentError, MAX_CA_DOCUMENT_BYTES, MAX_RETIRED};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use nocterm_hub_model::cloud::ssh::{
    MAX_BINDING_TARGETS, MAX_CERTIFICATE_BYTES, MAX_CERTIFICATE_VALIDITY_MS,
    MAX_SOURCE_ADDRESS_BYTES, MAX_SOURCE_ADDRESSES, SignedSshBinding, SshBinding, SshFormatError,
    SshServerId,
};
use sha2::{Digest, Sha256};
use ssh_key::{
    Certificate, HashAlg, PrivateKey,
    certificate::{Builder, CertType},
    private::{Ed25519Keypair, KeypairData},
    public::{Ed25519PublicKey, KeyData},
};
use zeroize::Zeroizing;

use super::ssh_grant::{MAX_PRINCIPAL_BYTES, PRINCIPAL_PREFIX};

/// The only extension a certificate carries.
pub const PERMIT_PTY: &str = "permit-pty";
/// The only critical option a certificate carries.
pub const SOURCE_ADDRESS: &str = "source-address";
/// Clock skew allowed before a certificate becomes valid, in seconds.
pub const BACKDATE_SECONDS: u64 = 60;
/// The longest certificate key id.
pub const MAX_KEY_ID_BYTES: usize = 128;
const CA_COMMENT: &str = "nocterm agent CA";

/// Why a certificate cannot be issued or is not one this CA would issue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertificateError {
    /// A principal does not name an agent, or principals are missing, repeated or too many.
    #[error("the principals are missing, repeated or do not name an agent")]
    Principal,
    /// The key id is empty, too long or not printable ASCII.
    #[error("the key id is invalid")]
    KeyId,
    /// The subject key is missing.
    #[error("the subject key is missing")]
    Subject,
    /// The validity window is empty, negative or longer than 24 hours.
    #[error("the validity window is empty or longer than 24 hours")]
    Validity,
    /// Source addresses are missing, too many or not plain addresses.
    #[error("the source addresses are missing or invalid")]
    SourceAddress,
    /// The certificate is not a user certificate of this CA with exactly these restrictions.
    #[error("the certificate is not an agent certificate of this CA")]
    Restrictions,
    /// The OpenSSH library refused to build, sign, parse or verify the certificate.
    #[error("the OpenSSH certificate could not be built or read")]
    OpenSsh(#[source] ssh_key::Error),
}

/// What the CA is asked to certify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateSpec {
    /// The principals of the bound servers ([`principal_for`]), at most 16.
    pub principals: Vec<String>,
    /// Shown in the server's log, e.g. `nocterm-chat-<chat>-<request>`.
    pub key_id: String,
    /// The runner's per-chat Ed25519 public key.
    pub subject_key: [u8; 32],
    /// Serial number, random per certificate.
    pub serial: u64,
    /// Start of validity, Unix milliseconds (backdated by [`BACKDATE_SECONDS`]).
    pub valid_after_ms: i64,
    /// End of validity, Unix milliseconds.
    pub valid_before_ms: i64,
    /// Addresses or CIDRs the key may connect from (`source-address`).
    pub source_addresses: Vec<String>,
}
impl CertificateSpec {
    /// Checks the rules that make a certificate safe to sign.
    pub fn validate(&self) -> Result<(), CertificateError> {
        if self.principals.is_empty()
            || self.principals.len() > MAX_BINDING_TARGETS
            || !self.principals.iter().all(|p| principal_ok(p))
            || self
                .principals
                .iter()
                .enumerate()
                .any(|(index, p)| self.principals[..index].contains(p))
        {
            return Err(CertificateError::Principal);
        }
        if self.key_id.is_empty()
            || self.key_id.len() > MAX_KEY_ID_BYTES
            || !self.key_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(CertificateError::KeyId);
        }
        if self.subject_key == [0; 32] {
            return Err(CertificateError::Subject);
        }
        let life = self.valid_before_ms.saturating_sub(self.valid_after_ms);
        if self.valid_after_ms < 0 || life <= 0 || life > MAX_CERTIFICATE_VALIDITY_MS {
            return Err(CertificateError::Validity);
        }
        if self.source_addresses.is_empty()
            || self.source_addresses.len() > MAX_SOURCE_ADDRESSES
            || !self.source_addresses.iter().all(|a| address_ok(a))
        {
            return Err(CertificateError::SourceAddress);
        }
        Ok(())
    }
}

fn principal_ok(principal: &str) -> bool {
    principal.len() <= MAX_PRINCIPAL_BYTES
        && principal
            .strip_prefix(PRINCIPAL_PREFIX)
            .is_some_and(|rest| {
                !rest.is_empty()
                    && rest
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            })
}
fn address_ok(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= MAX_SOURCE_ADDRESS_BYTES
        && address
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
}

/// The first 8 bytes of SHA-256 of the CA key in hex: the part every principal of this CA
/// shares.
fn ca_tag(ca_key: &[u8; 32]) -> String {
    hex::encode(&Sha256::digest(ca_key)[..8])
}

/// The single principal of the first `authorized_keys` line form (line version 1, native ADR
/// 0119): `nocterm-agent-<ca>`. No certificate names it any more; a server whose line still
/// admits only it needs a CA update.
pub fn agent_principal(ca_key: &[u8; 32]) -> String {
    format!("{PRINCIPAL_PREFIX}{}", ca_tag(ca_key))
}

/// The principal of one server (line version 2): `nocterm-agent-<ca>-<server>`, with the first 8
/// bytes of the server id in hex. A certificate names only the principals of the servers its
/// chat is bound to, so a runner reaches no other server of the person.
pub fn principal_for(ca_key: &[u8; 32], server: &SshServerId) -> String {
    format!(
        "{PRINCIPAL_PREFIX}{}-{}",
        ca_tag(ca_key),
        hex::encode(&server.as_bytes()[..8])
    )
}

/// The `SHA256:…` fingerprint OpenSSH prints for a raw Ed25519 public key.
pub fn fingerprint_of(public_key: &[u8; 32]) -> String {
    KeyData::Ed25519(Ed25519PublicKey(*public_key))
        .fingerprint(HashAlg::Sha256)
        .to_string()
}

/// The digest an OpenSSH `SHA256:<base64>` fingerprint names (how `agent_ssh_trust` records keep
/// a server's host key); `None` for any other text.
pub fn sha256_of_fingerprint(fingerprint: &str) -> Option<[u8; 32]> {
    let encoded = fingerprint.strip_prefix("SHA256:")?;
    STANDARD_NO_PAD.decode(encoded).ok()?.try_into().ok()
}

/// An issued certificate: the OpenSSH blob a `SshCertificate` answer carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedCertificate {
    blob: Vec<u8>,
}
impl IssuedCertificate {
    /// The certificate in the SSH wire format (`ssh-ed25519-cert-v01@openssh.com` blob).
    pub fn as_bytes(&self) -> &[u8] {
        &self.blob
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.blob
    }
    /// The one-line text of an `-cert.pub` file, without a trailing newline.
    pub fn openssh(&self) -> Result<String, CertificateError> {
        certificate_line(&self.blob)
    }
}

/// The one-line OpenSSH text of a certificate blob.
pub fn certificate_line(blob: &[u8]) -> Result<String, CertificateError> {
    Certificate::from_bytes(blob)
        .and_then(|certificate| certificate.to_openssh())
        .map_err(CertificateError::OpenSsh)
}

/// What a certificate of this CA says, after [`CertificateFacts::read`] checked it is one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateFacts {
    pub subject_key: [u8; 32],
    pub principals: Vec<String>,
    pub key_id: String,
    pub serial: u64,
    /// Unix seconds, as signed (already backdated).
    pub valid_after: u64,
    /// Unix seconds.
    pub valid_before: u64,
    pub source_addresses: Vec<String>,
}
impl CertificateFacts {
    /// Reads a certificate blob and checks that `ca_key` signed it as an agent user certificate:
    /// Ed25519 subject, user type, agent principals only, at most 24 hours (plus the backdate),
    /// exactly the `source-address` option and the `permit-pty` extension. Validity against a
    /// clock is the caller's check.
    pub fn read(blob: &[u8], ca_key: &[u8; 32]) -> Result<Self, CertificateError> {
        if blob.len() > MAX_CERTIFICATE_BYTES {
            return Err(CertificateError::Restrictions);
        }
        let certificate = Certificate::from_bytes(blob).map_err(CertificateError::OpenSsh)?;
        let signer = KeyData::Ed25519(Ed25519PublicKey(*ca_key));
        if certificate.signature_key() != &signer || certificate.cert_type() != CertType::User {
            return Err(CertificateError::Restrictions);
        }
        certificate
            .verify_signature()
            .map_err(CertificateError::OpenSsh)?;
        let KeyData::Ed25519(subject) = certificate.public_key() else {
            return Err(CertificateError::Restrictions);
        };
        let options = certificate.critical_options();
        let extensions = certificate.extensions();
        let source = options
            .get(SOURCE_ADDRESS)
            .filter(|_| options.len() == 1)
            .ok_or(CertificateError::Restrictions)?;
        if extensions.len() != 1 || extensions.get(PERMIT_PTY).is_none_or(|v| !v.is_empty()) {
            return Err(CertificateError::Restrictions);
        }
        let life = certificate
            .valid_before()
            .checked_sub(certificate.valid_after())
            .ok_or(CertificateError::Restrictions)?;
        let longest = u64::try_from(MAX_CERTIFICATE_VALIDITY_MS / 1000).unwrap_or(0);
        let principals = certificate.valid_principals().to_vec();
        if life == 0
            || life > longest + BACKDATE_SECONDS
            || principals.is_empty()
            || !principals.iter().all(|p| principal_ok(p))
        {
            return Err(CertificateError::Restrictions);
        }
        Ok(Self {
            subject_key: subject.0,
            principals,
            key_id: certificate.key_id().to_owned(),
            serial: certificate.serial(),
            valid_after: certificate.valid_after(),
            valid_before: certificate.valid_before(),
            source_addresses: source.split(',').map(str::to_owned).collect(),
        })
    }
}

/// Why the CA cannot be made or cannot sign a binding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaError {
    /// The binding names another CA key than this one.
    #[error("the binding names another CA")]
    OtherCa,
    /// The binding is not valid.
    #[error("the SSH binding is invalid")]
    Binding(#[from] SshFormatError),
    /// The operating system could not provide randomness for a new CA.
    #[error("no randomness for a new CA")]
    Random,
}

/// The account's SSH CA: an Ed25519 key. `Debug` shows only its fingerprint.
pub struct UserCa {
    seed: Zeroizing<[u8; 32]>,
    signing: SigningKey,
}
impl UserCa {
    /// A CA derived from `seed`; the caller supplies the entropy and keeps the seed in the
    /// account's `agent_ssh_trust` document.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        let signing = SigningKey::from_bytes(&seed);
        Self { seed, signing }
    }
    /// A new CA from operating-system randomness.
    pub fn generate() -> Result<Self, CaError> {
        let seed = Zeroizing::new(crate::random_bytes::<32>().map_err(|_| CaError::Random)?);
        Ok(Self::from_seed(*seed))
    }
    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
    /// The raw Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
    /// The `SHA256:…` fingerprint of the CA key.
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.public_key())
    }
    /// The public key as OpenSSH text (`ssh-ed25519 AAAA… nocterm agent CA`).
    pub fn openssh_public_key(&self) -> Result<String, CertificateError> {
        ssh_key::PublicKey::new(
            KeyData::Ed25519(Ed25519PublicKey(self.public_key())),
            CA_COMMENT,
        )
        .to_openssh()
        .map_err(CertificateError::OpenSsh)
    }
    /// Signs a chat's binding; it must name this CA.
    pub fn sign_binding(&self, binding: SshBinding) -> Result<SignedSshBinding, CaError> {
        if binding.ca_key != self.public_key() {
            return Err(CaError::OtherCa);
        }
        let signature = self.signing.sign(&binding.signing_bytes()?).to_bytes();
        Ok(SignedSshBinding::new(binding, signature)?)
    }
    /// Certifies the subject key of `spec`. `nonce` is fresh entropy from the caller.
    pub fn issue(
        &self,
        spec: &CertificateSpec,
        nonce: [u8; 32],
    ) -> Result<IssuedCertificate, CertificateError> {
        spec.validate()?;
        let seconds = |ms: i64| u64::try_from(ms / 1000).unwrap_or(0);
        let valid_after = seconds(spec.valid_after_ms).saturating_sub(BACKDATE_SECONDS);
        let subject = KeyData::Ed25519(Ed25519PublicKey(spec.subject_key));
        let failed = CertificateError::OpenSsh;
        let mut builder = Builder::new(
            nonce.to_vec(),
            subject,
            valid_after,
            seconds(spec.valid_before_ms),
        )
        .map_err(failed)?;
        builder.serial(spec.serial).map_err(failed)?;
        builder.cert_type(CertType::User).map_err(failed)?;
        builder.key_id(spec.key_id.clone()).map_err(failed)?;
        for principal in &spec.principals {
            builder.valid_principal(principal.clone()).map_err(failed)?;
        }
        builder
            .critical_option(SOURCE_ADDRESS, spec.source_addresses.join(","))
            .map_err(failed)?;
        // Only a terminal: no port, agent or X11 forwarding, and no user rc.
        builder.extension(PERMIT_PTY, "").map_err(failed)?;
        let key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&self.seed)),
            CA_COMMENT,
        )
        .map_err(failed)?;
        let certificate = builder.sign(&key).map_err(failed)?;
        let blob = certificate.to_bytes().map_err(failed)?;
        Ok(IssuedCertificate { blob })
    }
}
impl std::fmt::Debug for UserCa {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "UserCa({})", self.fingerprint())
    }
}

#[cfg(test)]
mod tests;
