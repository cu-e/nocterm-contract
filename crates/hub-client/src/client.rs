//! A device's connection to one hub: sign-in, token refresh and service clients.

use std::any::Any;
use std::sync::Arc;

use nocterm_hub_grpc::account_service_client::AccountServiceClient;
use nocterm_hub_grpc::agent_service_client::AgentServiceClient;
use nocterm_hub_grpc::auth_service_client::AuthServiceClient;
use nocterm_hub_grpc::chat_service_client::ChatServiceClient;
use nocterm_hub_grpc::server_service_client::ServerServiceClient;
use nocterm_hub_grpc::vault_service_client::VaultServiceClient;
use nocterm_hub_model::PROTOCOL_VERSION;
use nocterm_hub_model::pop::{login_message, refresh_message};
use nocterm_hub_proto::v2::{self, LoginGrant, complete_login_request};
use nocterm_keys::{DeviceKey, LoginSecrets};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use zeroize::Zeroizing;

use crate::signer::{Credentials, Session, Signer, now_ms};
use crate::store::SessionStore;
use crate::{ClientError, HubEndpoint};

/// Refresh the access token when it expires within this window.
const REFRESH_MARGIN_MS: i64 = 60_000;
/// Largest message a vault or chat answer may carry (a page of history, a vault batch).
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

pub type Signed = InterceptedService<Channel, Signer>;

/// How this device presents itself when it signs in; the caller names it (the library
/// reads no host name or environment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The machine as the user knows it (a host name, "Work laptop").
    pub device: String,
    /// The application signing in ("Nocterm").
    pub app: String,
    /// The operating system; [`DeviceInfo::new`] uses the one this build targets.
    pub platform: String,
}

impl DeviceInfo {
    /// `app` running on `device`, on the operating system this build targets.
    pub fn new(device: impl Into<String>, app: impl Into<String>) -> Self {
        Self {
            device: device.into(),
            app: app.into(),
            platform: std::env::consts::OS.to_owned(),
        }
    }

    /// The name the hub lists for this device: "{app} on {device}".
    pub fn display_name(&self) -> String {
        match (self.app.trim(), self.device.trim()) {
            ("", device) => device.to_owned(),
            (app, "") => app.to_owned(),
            (app, device) => format!("{app} on {device}"),
        }
    }
}

/// A device signed in with a password: its tokens and the secrets derived from the password.
///
/// The hub never sees the password, only `secrets.auth()`. Keep `secrets.unlock()` just as
/// long as the account key must be opened, then drop it.
#[derive(Debug)]
pub struct SignedIn {
    /// Tokens to persist next to the device key.
    pub session: Session,
    /// What the password derives on this hub for this user.
    pub secrets: LoginSecrets,
}

/// A connection to a hub on behalf of one device key.
#[derive(Debug, Clone)]
pub struct HubClient {
    channel: Channel,
    info: Arc<v2::HubInfo>,
    credentials: Arc<Credentials>,
}

impl HubClient {
    /// Connects, reads the hub's identity and checks the protocol version.
    pub async fn connect(
        endpoint: &HubEndpoint,
        key: DeviceKey,
        session: Option<Session>,
    ) -> Result<Self, ClientError> {
        let channel = endpoint.connect().await?;
        let info = AuthServiceClient::new(channel.clone())
            .get_hub_info(v2::Empty {})
            .await?
            .into_inner();
        if info.protocol_version != PROTOCOL_VERSION {
            return Err(ClientError::UpgradeRequired {
                hub: info.protocol_version,
                client: PROTOCOL_VERSION,
            });
        }
        // The offset is estimated without the round trip: it only has to stay well inside the
        // hub's freshness window.
        let clock_offset_ms = if info.server_time_ms > 0 {
            info.server_time_ms - now_ms()
        } else {
            0
        };
        let credentials = Arc::new(Credentials::new(
            info.hub_id.clone(),
            key,
            session,
            clock_offset_ms,
        ));
        Ok(Self {
            channel,
            info: Arc::new(info),
            credentials,
        })
    }

    pub fn info(&self) -> &v2::HubInfo {
        &self.info
    }

    /// The public URL of the hub's web panel, when the hub serves one and states a usable
    /// `https://` URL (`HubInfo.web_url`, read with `nocterm_hub_proto::web_url_from_wire`).
    pub fn web_url(&self) -> Option<&str> {
        nocterm_hub_proto::web_url_from_wire(&self.info)
    }

    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }

    /// Current tokens, to persist after sign-in or refresh.
    pub fn session(&self) -> Option<Session> {
        self.credentials.session()
    }

    pub fn sign_out(&self) {
        self.credentials.set_session(None);
    }

    /// Unauthenticated sign-in service.
    pub fn auth(&self) -> AuthServiceClient<Channel> {
        AuthServiceClient::new(self.channel.clone())
    }

    pub(crate) fn signed(&self) -> Signed {
        InterceptedService::new(
            self.channel.clone(),
            Signer::new(Arc::clone(&self.credentials)),
        )
    }

    pub fn account(&self) -> AccountServiceClient<Signed> {
        AccountServiceClient::new(self.signed())
    }

    pub fn vault(&self) -> VaultServiceClient<Signed> {
        VaultServiceClient::new(self.signed()).max_decoding_message_size(MAX_MESSAGE_BYTES)
    }

    pub fn agents(&self) -> AgentServiceClient<Signed> {
        AgentServiceClient::new(self.signed())
    }

    pub fn servers(&self) -> ServerServiceClient<Signed> {
        ServerServiceClient::new(self.signed())
    }

    pub fn chats(&self) -> ChatServiceClient<Signed> {
        ChatServiceClient::new(self.signed()).max_decoding_message_size(MAX_MESSAGE_BYTES)
    }

    /// Signs this device out on the hub (it is revoked there) and forgets its tokens.
    pub async fn logout(&self) -> Result<(), ClientError> {
        let result = self.account().logout(v2::Empty {}).await;
        self.sign_out();
        result.map(|_| ()).map_err(ClientError::from)
    }

    /// Redeems a login grant (or an OIDC code) and registers or re-binds this device.
    pub async fn complete_login(
        &self,
        grant: complete_login_request::Grant,
        device: &DeviceInfo,
    ) -> Result<Session, ClientError> {
        let signed_value = match &grant {
            complete_login_request::Grant::LoginGrant(grant) => grant.clone(),
            complete_login_request::Grant::Oidc(oidc) => oidc.code.clone(),
        };
        let public_key = self.credentials.key.public_key();
        let ts = self.credentials.hub_now_ms();
        let proof = self.credentials.key.sign(&login_message(
            &self.info.hub_id,
            &signed_value,
            &public_key,
            ts,
        ));
        let request = v2::CompleteLoginRequest {
            grant: Some(grant),
            device: Some(v2::DeviceRegistration {
                device_id: self
                    .credentials
                    .session()
                    .map(|s| s.device_id)
                    .unwrap_or_default(),
                name: device.display_name(),
                platform: device.platform.clone(),
                signing_public_key: public_key.to_vec(),
                assurance: v2::Assurance::Software.into(),
            }),
            proof: proof.to_vec(),
            signed_at_ms: ts,
        };
        let session = Session::from(self.auth().complete_login(request).await?.into_inner());
        self.credentials.set_session(Some(session.clone()));
        Ok(session)
    }

    /// Derives the login secrets of `username` from `password` off the calling thread (the
    /// derivation takes 64 MiB and a few hundred milliseconds).
    async fn derive_secrets(
        &self,
        password: Zeroizing<String>,
        username: &str,
    ) -> Result<LoginSecrets, ClientError> {
        let hub_id = self.info.hub_id.clone();
        let username = username.to_owned();
        tokio::task::spawn_blocking(move || LoginSecrets::derive(&password, &hub_id, &username))
            .await
            .map_err(ClientError::DerivationInterrupted)?
            .map_err(ClientError::Login)
    }

    async fn redeem(
        &self,
        grant: LoginGrant,
        secrets: LoginSecrets,
        device: &DeviceInfo,
    ) -> Result<SignedIn, ClientError> {
        let session = self
            .complete_login(
                complete_login_request::Grant::LoginGrant(grant.grant),
                device,
            )
            .await?;
        Ok(SignedIn { session, secrets })
    }

    /// Creates the hub's first administrator with the setup code and signs this device in.
    ///
    /// `request.auth` is the password the user typed. It is replaced by the derived login
    /// value before anything is sent, and the user name is trimmed.
    pub async fn setup(
        &self,
        mut request: v2::SetupRequest,
        device: &DeviceInfo,
    ) -> Result<SignedIn, ClientError> {
        let password = Zeroizing::new(std::mem::take(&mut request.auth));
        request.username = request.username.trim().to_owned();
        let secrets = self.derive_secrets(password, &request.username).await?;
        request.auth = secrets.auth().to_owned();
        let grant = self.auth().setup(request).await?.into_inner();
        self.redeem(grant, secrets, device).await
    }

    /// Signs in with the account's password; the hub receives only the derived login value.
    pub async fn password_login(
        &self,
        username: &str,
        password: &str,
        device: &DeviceInfo,
    ) -> Result<SignedIn, ClientError> {
        let username = username.trim();
        let secrets = self
            .derive_secrets(Zeroizing::new(password.to_owned()), username)
            .await?;
        let request = v2::PasswordLoginRequest {
            username: username.to_owned(),
            auth: secrets.auth().to_owned(),
        };
        let grant = self.auth().password_login(request).await?.into_inner();
        self.redeem(grant, secrets, device).await
    }

    /// Creates a local account from an invite and signs this device in.
    ///
    /// `request.auth` is the password the user typed; like [`HubClient::setup`], it is
    /// replaced by the derived login value before anything is sent.
    pub async fn redeem_invite(
        &self,
        mut request: v2::RedeemInviteRequest,
        device: &DeviceInfo,
    ) -> Result<SignedIn, ClientError> {
        let password = Zeroizing::new(std::mem::take(&mut request.auth));
        request.username = request.username.trim().to_owned();
        let secrets = self.derive_secrets(password, &request.username).await?;
        request.auth = secrets.auth().to_owned();
        let grant = self.auth().redeem_invite(request).await?.into_inner();
        self.redeem(grant, secrets, device).await
    }

    /// Keeps the tokens in `store` and rotates them in turn with other processes using it.
    pub fn persist_with(&self, store: Arc<dyn SessionStore>) {
        self.credentials.set_store(store);
    }

    /// Rotates the refresh token.
    pub async fn refresh(&self) -> Result<Session, ClientError> {
        let _turn = self.credentials.refreshing.lock().await;
        let _lock = self.adopt_stored()?;
        self.rotate().await
    }

    /// Refreshes the access token if it is about to expire; `true` when it changed.
    pub async fn ensure_fresh(&self) -> Result<bool, ClientError> {
        if !self.expiring()? {
            return Ok(false);
        }
        let _turn = self.credentials.refreshing.lock().await;
        let before = self.credentials.session();
        let _lock = self.adopt_stored()?;
        if !self.expiring()? {
            // Another task or process refreshed meanwhile.
            return Ok(self.credentials.session() != before);
        }
        self.rotate().await.map(|_| true)
    }

    fn expiring(&self) -> Result<bool, ClientError> {
        let session = self.credentials.session().ok_or(ClientError::NotSignedIn)?;
        Ok(session.access_expires_at_ms - now_ms() <= REFRESH_MARGIN_MS)
    }

    /// Locks the store and takes the session another process saved, if it differs.
    fn adopt_stored(&self) -> Result<Option<Box<dyn Any + Send>>, ClientError> {
        let Some(store) = self.credentials.store() else {
            return Ok(None);
        };
        let (generation, _) = self
            .credentials
            .snapshot()
            .ok_or(ClientError::NotSignedIn)?;
        let lock = store.lock().map_err(ClientError::SessionStore)?;
        if let Some(stored) = store.load().map_err(ClientError::SessionStore)?
            && Some(&stored) != self.credentials.session().as_ref()
            && !self.credentials.rotate_session(generation, stored)
        {
            return Err(ClientError::SessionReplaced);
        }
        if self.credentials.snapshot().map(|(current, _)| current) != Some(generation) {
            return Err(ClientError::SessionReplaced);
        }
        Ok(Some(lock))
    }

    /// Exchanges the current refresh token; callers hold the refresh turn.
    async fn rotate(&self) -> Result<Session, ClientError> {
        let (generation, session) = self
            .credentials
            .snapshot()
            .ok_or(ClientError::NotSignedIn)?;
        let ts = self.credentials.hub_now_ms();
        let proof = self.credentials.key.sign(&refresh_message(
            &self.info.hub_id,
            &session.refresh_token,
            ts,
        ));
        let request = v2::RefreshRequest {
            refresh_token: session.refresh_token,
            device_id: session.device_id,
            proof: proof.to_vec(),
            signed_at_ms: ts,
        };
        let fresh = Session::from(self.auth().refresh(request).await?.into_inner());
        if !self.credentials.rotate_session(generation, fresh.clone()) {
            return Err(ClientError::SessionReplaced);
        }
        if let Some(store) = self.credentials.store() {
            store.save(&fresh).map_err(ClientError::SessionStore)?;
        }
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_is_named_by_its_caller() {
        let device = DeviceInfo::new("laptop", "Nocterm");
        assert_eq!(device.display_name(), "Nocterm on laptop");
        assert_eq!(device.platform, std::env::consts::OS);
        assert_eq!(DeviceInfo::new("", "Nocterm").display_name(), "Nocterm");
        assert_eq!(DeviceInfo::new("laptop", " ").display_name(), "laptop");
    }
}
