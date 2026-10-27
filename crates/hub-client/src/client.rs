//! A device's connection to one hub: sign-in, token refresh and service clients.

use std::any::Any;
use std::sync::Arc;

use nocterm_hub_grpc::LINK_PATH;
use nocterm_hub_grpc::audit_service_client::AuditServiceClient;
use nocterm_hub_grpc::auth_service_client::AuthServiceClient;
use nocterm_hub_grpc::directory_service_client::DirectoryServiceClient;
use nocterm_hub_grpc::fleet_service_client::FleetServiceClient;
use nocterm_hub_grpc::link_service_client::LinkServiceClient;
use nocterm_hub_grpc::session_service_client::SessionServiceClient;
use nocterm_hub_grpc::store_service_client::StoreServiceClient;
use nocterm_hub_model::PROTOCOL_VERSION;
use nocterm_hub_model::pop::{login_message, refresh_message, request_message};
use nocterm_hub_proto::v1::{self, LoginGrant, complete_login_request};
use nocterm_keys::{DeviceKey, LoginSecrets};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use zeroize::Zeroizing;

use crate::signer::{Credentials, Session, Signer, now_ms};
use crate::store::SessionStore;
use crate::{ClientError, HubEndpoint};

/// Refresh the access token when it expires within this window.
const REFRESH_MARGIN_MS: i64 = 60_000;

pub type Signed = InterceptedService<Channel, Signer>;

/// How this device presents itself when it signs in; the caller names it (the library
/// reads no host name or environment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The machine as the user knows it (a host name, "Work laptop").
    pub device: String,
    /// The application signing in ("hubctl", "Nocterm").
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
    info: v1::HubInfo,
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
            .get_hub_info(v1::Empty {})
            .await?
            .into_inner();
        if info.protocol_version != PROTOCOL_VERSION {
            return Err(ClientError::UpgradeRequired {
                hub: info.protocol_version,
                client: PROTOCOL_VERSION,
            });
        }
        let credentials = Arc::new(Credentials::new(info.hub_id.clone(), key, session));
        Ok(Self {
            channel,
            info,
            credentials,
        })
    }

    pub fn info(&self) -> &v1::HubInfo {
        &self.info
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

    pub fn directory(&self) -> DirectoryServiceClient<Signed> {
        DirectoryServiceClient::new(self.signed())
    }

    pub fn store(&self) -> StoreServiceClient<Signed> {
        StoreServiceClient::new(self.signed()).max_decoding_message_size(4 * 1024 * 1024)
    }

    pub fn sessions(&self) -> SessionServiceClient<Signed> {
        SessionServiceClient::new(self.signed())
    }

    pub fn fleet(&self) -> FleetServiceClient<Signed> {
        FleetServiceClient::new(self.signed())
    }

    pub fn audit(&self) -> AuditServiceClient<Signed> {
        AuditServiceClient::new(self.signed())
    }

    /// The Link service; the stream authenticates with [`HubClient::link_hello`].
    pub fn link(&self) -> LinkServiceClient<Channel> {
        LinkServiceClient::new(self.channel.clone())
    }

    /// A signed first frame for a new Link.
    pub fn link_hello(&self) -> Result<v1::LinkHello, ClientError> {
        let session = self.credentials.session().ok_or(ClientError::NotSignedIn)?;
        let nonce = crate::signer::nonce().map_err(ClientError::Randomness)?;
        let ts = now_ms();
        let message = request_message(
            &self.info.hub_id,
            LINK_PATH,
            &session.access_token,
            &nonce,
            ts,
        );
        Ok(v1::LinkHello {
            access_token: session.access_token,
            device_id: session.device_id,
            signed_at_ms: ts,
            nonce,
            proof: self.credentials.key.sign(&message).to_vec(),
            protocol_version: PROTOCOL_VERSION,
        })
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
        let ts = now_ms();
        let proof = self.credentials.key.sign(&login_message(
            &self.info.hub_id,
            &signed_value,
            &public_key,
            ts,
        ));
        let request = v1::CompleteLoginRequest {
            grant: Some(grant),
            device: Some(v1::DeviceRegistration {
                device_id: self
                    .credentials
                    .session()
                    .map(|s| s.device_id)
                    .unwrap_or_default(),
                name: device.display_name(),
                platform: device.platform.clone(),
                signing_public_key: public_key.to_vec(),
                assurance: v1::Assurance::Software.into(),
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

    /// Creates the hub's first owner with the setup token and signs this device in.
    ///
    /// `request.password` is the password the user typed. It is replaced by the derived
    /// login value before anything is sent, and the user name is trimmed.
    pub async fn bootstrap(
        &self,
        mut request: v1::BootstrapRequest,
        device: &DeviceInfo,
    ) -> Result<SignedIn, ClientError> {
        let password = Zeroizing::new(std::mem::take(&mut request.password));
        request.username = request.username.trim().to_owned();
        let secrets = self.derive_secrets(password, &request.username).await?;
        request.password = secrets.auth().to_owned();
        let grant = self.auth().bootstrap(request).await?.into_inner();
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
        let request = v1::PasswordLoginRequest {
            username: username.to_owned(),
            password: secrets.auth().to_owned(),
        };
        let grant = self.auth().password_login(request).await?.into_inner();
        self.redeem(grant, secrets, device).await
    }

    /// Creates a local account from an invite and signs this device in.
    ///
    /// `request.password` is the password the user typed; like [`HubClient::bootstrap`], it
    /// is replaced by the derived login value before anything is sent.
    pub async fn redeem_invite(
        &self,
        mut request: v1::RedeemInviteRequest,
        device: &DeviceInfo,
    ) -> Result<SignedIn, ClientError> {
        let password = Zeroizing::new(std::mem::take(&mut request.password));
        request.username = request.username.trim().to_owned();
        let secrets = self.derive_secrets(password, &request.username).await?;
        request.password = secrets.auth().to_owned();
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
        let lock = store.lock().map_err(ClientError::SessionStore)?;
        if let Some(stored) = store.load().map_err(ClientError::SessionStore)?
            && Some(&stored) != self.credentials.session().as_ref()
        {
            self.credentials.set_session(Some(stored));
        }
        Ok(Some(lock))
    }

    /// Exchanges the current refresh token; callers hold the refresh turn.
    async fn rotate(&self) -> Result<Session, ClientError> {
        let session = self.credentials.session().ok_or(ClientError::NotSignedIn)?;
        let ts = now_ms();
        let proof = self.credentials.key.sign(&refresh_message(
            &self.info.hub_id,
            &session.refresh_token,
            ts,
        ));
        let request = v1::RefreshRequest {
            refresh_token: session.refresh_token,
            device_id: session.device_id,
            proof: proof.to_vec(),
            signed_at_ms: ts,
        };
        let fresh = Session::from(self.auth().refresh(request).await?.into_inner());
        self.credentials.set_session(Some(fresh.clone()));
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
        let device = DeviceInfo::new("laptop", "hubctl");
        assert_eq!(device.display_name(), "hubctl on laptop");
        assert_eq!(device.platform, std::env::consts::OS);
        assert_eq!(DeviceInfo::new("", "Nocterm").display_name(), "Nocterm");
        assert_eq!(DeviceInfo::new("laptop", " ").display_name(), "laptop");
    }
}
