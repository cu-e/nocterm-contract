//! The credential broker's formats: virtual tokens and the sealed real secret.
//!
//! The broker is a separate process on the pool host, outside the runner's sandbox. The
//! runner holds a virtual token that is useful only through the broker and only for what its
//! claims allow; the real API key reaches the broker sealed by the owner and never the runner.
use hmac::{Hmac, KeyInit, Mac};
use nocterm_hub_model::agents::AgentScope;
use nocterm_hub_model::{AgentId, InstanceId, PoolId};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::boxed::{box_open, box_seal};
use super::canon::Writer;
use crate::seal::Purpose;
use crate::{AccountKeyPair, KeyError, OpenError, PublicKey, SealError, random_bytes};

const TOKEN_DOMAIN: &[u8] = b"nocterm/agents-broker-virtual-token/v1";
const SECRET_INFO: &[u8] = b"nocterm-agent-broker-secret-v1/auth";
const PREFIX: &str = "nvt1_";
const ID_LEN: usize = 16;
const TAG_LEN: usize = 32;
/// Longest chat identifier a token binds.
pub const MAX_TOKEN_CHAT_BYTES: usize = 64;
/// Most models one token binds.
pub const MAX_TOKEN_MODELS: usize = 32;
/// Longest accepted token text.
pub const MAX_TOKEN_TEXT_BYTES: usize = PREFIX.len() + (ID_LEN + TAG_LEN).div_ceil(3) * 4;

/// A token or sealed secret that is not valid.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// Not the `nvt1_` text format.
    #[error("not a broker virtual token")]
    Malformed,
    /// The claims are out of bounds.
    #[error("the token claims exceed their limits")]
    Claims,
    /// The tag does not match the claims: forged, or issued for something else.
    #[error("the token does not match its claims")]
    Forged,
    /// The token's lifetime has ended.
    #[error("the token has expired")]
    Expired,
    /// No randomness for a token id.
    #[error(transparent)]
    Random(#[from] KeyError),
}

/// The broker's own MAC key. Only the broker holds it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BrokerKey([u8; 32]);

impl std::fmt::Debug for BrokerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerKey").finish_non_exhaustive()
    }
}

impl BrokerKey {
    /// A fresh random key.
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self(random_bytes::<32>()?))
    }

    /// Restores a key the broker stored.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// What a token may do. The broker stores the claims by token id and re-checks the tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenClaims {
    /// The instance whose runner holds the token.
    pub instance: InstanceId,
    /// The chat the token is bound to.
    pub chat: String,
    /// Models the token may call.
    pub models: Vec<String>,
    /// Spending ceiling in millionths of a US dollar.
    pub budget_micro_usd: u64,
    /// End of the token's life, Unix milliseconds.
    pub expires_at_ms: i64,
}

impl TokenClaims {
    fn check(&self) -> Result<(), BrokerError> {
        let ok = !self.chat.is_empty()
            && self.chat.len() <= MAX_TOKEN_CHAT_BYTES
            && self.models.len() <= MAX_TOKEN_MODELS
            && self.models.iter().all(|m| !m.is_empty() && m.len() <= 128);
        ok.then_some(()).ok_or(BrokerError::Claims)
    }

    fn mac(&self, key: &BrokerKey, id: &[u8; ID_LEN]) -> Result<Hmac<Sha256>, BrokerError> {
        self.check()?;
        let mut layout = Writer::new(TOKEN_DOMAIN);
        layout
            .field(id)
            .field(self.instance.as_uuid().as_bytes())
            .field(self.chat.as_bytes())
            .list(&self.models)
            .u64(self.budget_micro_usd)
            .i64(self.expires_at_ms);
        let mut mac = Hmac::<Sha256>::new_from_slice(&key.0).map_err(|_| BrokerError::Forged)?;
        mac.update(&layout.finish());
        Ok(mac)
    }
}

/// A token as the runner holds it: an id the broker looks claims up by, and a tag over them.
#[derive(Clone, PartialEq, Eq)]
pub struct VirtualToken {
    id: [u8; ID_LEN],
    tag: [u8; TAG_LEN],
}

impl std::fmt::Debug for VirtualToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualToken").finish_non_exhaustive()
    }
}

impl VirtualToken {
    /// Issues a token for `claims` with a fresh random id.
    pub fn issue(key: &BrokerKey, claims: &TokenClaims) -> Result<Self, BrokerError> {
        Self::issue_with_id(key, claims, random_bytes::<ID_LEN>()?)
    }

    pub(crate) fn issue_with_id(
        key: &BrokerKey,
        claims: &TokenClaims,
        id: [u8; ID_LEN],
    ) -> Result<Self, BrokerError> {
        let tag = claims.mac(key, &id)?.finalize().into_bytes().into();
        Ok(Self { id, tag })
    }

    /// The id the broker stores the claims under.
    pub fn id(&self) -> [u8; ID_LEN] {
        self.id
    }

    /// The text form handed to the runner.
    pub fn to_text(&self) -> String {
        use base64::Engine as _;
        let mut raw = Vec::with_capacity(ID_LEN + TAG_LEN);
        raw.extend_from_slice(&self.id);
        raw.extend_from_slice(&self.tag);
        format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        )
    }

    /// Parses the text form without checking the tag.
    pub fn parse(text: &str) -> Result<Self, BrokerError> {
        use base64::Engine as _;
        if text.len() > MAX_TOKEN_TEXT_BYTES {
            return Err(BrokerError::Malformed);
        }
        let body = text.strip_prefix(PREFIX).ok_or(BrokerError::Malformed)?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| BrokerError::Malformed)?;
        if raw.len() != ID_LEN + TAG_LEN {
            return Err(BrokerError::Malformed);
        }
        let (id, tag) = raw.split_at(ID_LEN);
        Ok(Self {
            id: id.try_into().map_err(|_| BrokerError::Malformed)?,
            tag: tag.try_into().map_err(|_| BrokerError::Malformed)?,
        })
    }

    /// Checks the tag against the claims the broker stored and the time `now_ms`.
    pub fn verify(
        &self,
        key: &BrokerKey,
        claims: &TokenClaims,
        now_ms: i64,
    ) -> Result<(), BrokerError> {
        claims
            .mac(key, &self.id)?
            .verify_slice(&self.tag)
            .map_err(|_| BrokerError::Forged)?;
        if now_ms >= claims.expires_at_ms {
            return Err(BrokerError::Expired);
        }
        Ok(())
    }
}

/// What a sealed provider secret is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretContext<'a> {
    /// The agent the secret belongs to.
    pub agent: AgentId,
    /// The scope that owns the agent.
    pub scope: AgentScope,
    /// The pool whose broker receives it.
    pub pool: PoolId,
    /// The secret's name inside the definition.
    pub name: &'a str,
}

fn with_parts<R>(
    context: &SecretContext<'_>,
    sender: &PublicKey,
    f: impl FnOnce(&[&str]) -> R,
) -> R {
    let (agent, scope, pool) = (
        context.agent.to_string(),
        context.scope.canonical_text(),
        context.pool.to_string(),
    );
    f(&[&agent, &scope, &pool, context.name, &sender.fingerprint()])
}

/// Seals a real secret from its owner to the broker's key.
pub fn seal_broker_secret(
    owner: &AccountKeyPair,
    broker: &PublicKey,
    context: &SecretContext<'_>,
    secret: &[u8],
) -> Result<Vec<u8>, SealError> {
    with_parts(context, &owner.public_key(), |parts| {
        box_seal(
            Purpose::BrokerSecret,
            SECRET_INFO,
            owner,
            broker,
            parts,
            secret,
        )
    })
}

/// Opens a secret sealed by [`seal_broker_secret`] with the broker's pair.
pub fn open_broker_secret(
    broker: &AccountKeyPair,
    owner: &PublicKey,
    context: &SecretContext<'_>,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    with_parts(context, owner, |parts| {
        box_open(
            Purpose::BrokerSecret,
            SECRET_INFO,
            broker,
            owner,
            parts,
            sealed,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> TokenClaims {
        TokenClaims {
            instance: InstanceId::from_uuid(uuid::Uuid::from_bytes([3; 16])),
            chat: "chat-1".into(),
            models: vec!["gpt".into(), "mini".into()],
            budget_micro_usd: 5_000_000,
            expires_at_ms: 2_000,
        }
    }

    #[test]
    fn a_token_round_trips_through_text_and_verifies() {
        let key = BrokerKey::from_bytes([1; 32]);
        let token = VirtualToken::issue(&key, &claims()).unwrap();
        let parsed = VirtualToken::parse(&token.to_text()).unwrap();
        assert_eq!(parsed.id(), token.id());
        parsed.verify(&key, &claims(), 1_000).unwrap();
        assert!(token.to_text().len() <= MAX_TOKEN_TEXT_BYTES);
    }

    #[test]
    fn a_token_is_bound_to_every_claim_and_the_key() {
        let key = BrokerKey::from_bytes([1; 32]);
        let token = VirtualToken::issue(&key, &claims()).unwrap();
        let mutate: [fn(&mut TokenClaims); 5] = [
            |c| c.instance = InstanceId::from_uuid(uuid::Uuid::from_bytes([4; 16])),
            |c| c.chat = "chat-2".into(),
            |c| c.models.push("extra".into()),
            |c| c.budget_micro_usd += 1,
            |c| c.expires_at_ms += 1,
        ];
        for change in mutate {
            let mut other = claims();
            change(&mut other);
            assert!(matches!(
                token.verify(&key, &other, 0),
                Err(BrokerError::Forged)
            ));
        }
        let other_key = BrokerKey::from_bytes([2; 32]);
        assert!(matches!(
            token.verify(&other_key, &claims(), 0),
            Err(BrokerError::Forged)
        ));
    }

    #[test]
    fn an_expired_token_and_malformed_text_are_refused() {
        let key = BrokerKey::from_bytes([1; 32]);
        let token = VirtualToken::issue(&key, &claims()).unwrap();
        assert!(matches!(
            token.verify(&key, &claims(), 2_000),
            Err(BrokerError::Expired)
        ));
        assert!(VirtualToken::parse("nvt2_AAAA").is_err());
        assert!(VirtualToken::parse("nvt1_AAAA").is_err());
        assert!(VirtualToken::parse(&format!("nvt1_{}", "A".repeat(200))).is_err());
        let mut bad = claims();
        bad.chat.clear();
        assert!(matches!(
            VirtualToken::issue(&key, &bad),
            Err(BrokerError::Claims)
        ));
    }

    #[test]
    fn an_issued_token_travels_in_a_chat_access_frame() {
        use nocterm_hub_model::agents::{ChatAccessFrame, ChatAccessToken, limits};
        const { assert!(MAX_TOKEN_TEXT_BYTES <= limits::MAX_ACCESS_TOKEN_BYTES) };
        let key = BrokerKey::from_bytes([1; 32]);
        let token = VirtualToken::issue(&key, &claims()).unwrap();
        let frame = ChatAccessFrame::Issue {
            chat: [3; 16],
            token: ChatAccessToken::new(token.to_text()).unwrap(),
        };
        let back = ChatAccessFrame::decode(&frame.encode()).unwrap();
        let ChatAccessFrame::Issue { token: text, .. } = back else {
            panic!("an issue frame reads back as an issue");
        };
        assert_eq!(VirtualToken::parse(text.expose()).unwrap(), token);
    }

    #[test]
    fn the_token_matches_the_independent_vector() {
        let key = BrokerKey::from_bytes([1; 32]);
        let token = VirtualToken::issue_with_id(&key, &claims(), [9; 16]).unwrap();
        let expected = include_str!("../../../../fixtures/agents-v1/broker-token.txt").trim();
        assert_eq!(token.to_text(), expected);
    }

    #[test]
    fn a_secret_opens_only_for_its_broker_agent_and_name() {
        let (owner, broker) = (
            AccountKeyPair::generate().unwrap(),
            AccountKeyPair::generate().unwrap(),
        );
        let context = SecretContext {
            agent: AgentId::new(),
            scope: AgentScope::Account,
            pool: PoolId::new(),
            name: "api_key",
        };
        let sealed =
            seal_broker_secret(&owner, &broker.public_key(), &context, b"sk-real").unwrap();
        let opened = open_broker_secret(&broker, &owner.public_key(), &context, &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"sk-real");
        let other = SecretContext {
            name: "other",
            ..context
        };
        assert!(open_broker_secret(&broker, &owner.public_key(), &other, &sealed).is_err());
        let stranger = AccountKeyPair::generate().unwrap();
        assert!(open_broker_secret(&stranger, &owner.public_key(), &context, &sealed).is_err());
    }
}
