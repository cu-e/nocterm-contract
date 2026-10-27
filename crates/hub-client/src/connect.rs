//! Connections to a hub: TLS pinned to a certificate fingerprint, public CAs, or plaintext.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint, Uri};

/// Where a hub listens and how its certificate is trusted.
#[derive(Clone, PartialEq, Eq)]
pub struct HubEndpoint {
    host: String,
    port: u16,
    trust: Trust,
}

/// How the hub's certificate is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// Accept exactly the certificate with this SHA-256 (self-signed hubs).
    Pinned([u8; 32]),
    /// Verify against the public web PKI.
    PublicCa,
    /// No TLS (only for hubs behind a local TLS-terminating proxy or in tests).
    Plaintext,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("hub address must look like host:port, https://host:port or http://host:port")]
    Address,
    #[error("fingerprint must be 64 hexadecimal characters (SHA-256)")]
    Fingerprint,
    #[error("a fingerprint cannot be pinned on a plaintext http:// address")]
    PinnedPlaintext,
    #[error("the address scheme (http:// or https://) does not match the trust mode")]
    Scheme,
}

/// The hub could not be reached.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("invalid hub address")]
    Endpoint(#[from] EndpointError),
    #[error("TLS setup failed")]
    Tls(#[from] rustls::Error),
    #[error("cannot connect to the hub")]
    Transport(#[from] tonic::transport::Error),
}

/// Parses a fingerprint printed by the hub (hex, colons and case ignored).
pub fn parse_fingerprint(text: &str) -> Result<[u8; 32], EndpointError> {
    let clean: String = text
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    let bytes = hex::decode(clean).map_err(|_| EndpointError::Fingerprint)?;
    bytes.try_into().map_err(|_| EndpointError::Fingerprint)
}

/// `host`, `port` and whether the address asked for plaintext (`http://`) or TLS
/// (`https://`); `None` for a bare `host:port`.
pub(crate) fn parse_address(address: &str) -> Result<(String, u16, Option<bool>), EndpointError> {
    let (plaintext, rest) = if let Some(rest) = address.strip_prefix("http://") {
        (Some(true), rest)
    } else if let Some(rest) = address.strip_prefix("https://") {
        (Some(false), rest)
    } else {
        (None, address)
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = rest.rsplit_once(':').ok_or(EndpointError::Address)?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = port.parse().map_err(|_| EndpointError::Address)?;
    if host.is_empty() || host.contains('/') {
        return Err(EndpointError::Address);
    }
    Ok((host.to_owned(), port, plaintext))
}

impl HubEndpoint {
    /// `address` with an optional fingerprint: a fingerprint pins the certificate, `https://`
    /// or a bare `host:port` without one uses public CAs, `http://` disables TLS.
    pub fn new(address: &str, fingerprint: Option<&str>) -> Result<Self, EndpointError> {
        let (host, port, plaintext) = parse_address(address)?;
        let trust = match (plaintext == Some(true), fingerprint) {
            (true, Some(_)) => return Err(EndpointError::PinnedPlaintext),
            (true, None) => Trust::Plaintext,
            (false, Some(fp)) => Trust::Pinned(parse_fingerprint(fp)?),
            (false, None) => Trust::PublicCa,
        };
        Ok(Self { host, port, trust })
    }

    /// `address` with a trust mode the caller stored (for example after
    /// [`HubEndpoint::probe`]); an `http://` address needs [`Trust::Plaintext`] and an
    /// `https://` one a TLS mode.
    pub fn with_trust(address: &str, trust: Trust) -> Result<Self, EndpointError> {
        let (host, port, plaintext) = parse_address(address)?;
        match (plaintext, &trust) {
            (Some(true), Trust::Pinned(_)) => return Err(EndpointError::PinnedPlaintext),
            (Some(true), Trust::PublicCa) | (Some(false), Trust::Plaintext) => {
                return Err(EndpointError::Scheme);
            }
            _ => {}
        }
        Ok(Self { host, port, trust })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn trust(&self) -> &Trust {
        &self.trust
    }

    /// The address in the form [`HubEndpoint::new`] accepts.
    pub fn address(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.trust {
            Trust::Plaintext => format!("http://{host}:{}", self.port),
            _ => format!("{host}:{}", self.port),
        }
    }

    /// Opens an HTTP/2 channel; it reconnects by itself after transient failures.
    pub async fn connect(&self) -> Result<Channel, ConnectError> {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let endpoint = Endpoint::from_shared(format!("http://{host}:{}", self.port))?
            .connect_timeout(Duration::from_secs(10))
            .tcp_nodelay(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(20))
            .keep_alive_while_idle(true);
        let tls = match &self.trust {
            Trust::Plaintext => return Ok(endpoint.connect().await?),
            Trust::Pinned(fingerprint) => pinned_config(*fingerprint)?,
            Trust::PublicCa => public_config()?,
        };
        let connector = TlsConnector::from(Arc::new(tls));
        let target = (self.host.clone(), self.port);
        let service = tower::service_fn(move |_: Uri| {
            let connector = connector.clone();
            let (host, port) = target.clone();
            async move {
                let tcp = TcpStream::connect((host.as_str(), port)).await?;
                tcp.set_nodelay(true)?;
                let name = ServerName::try_from(host)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
                let stream = connector.connect(name, tcp).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        });
        Ok(endpoint.connect_with_connector(service).await?)
    }
}

impl fmt::Debug for HubEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HubEndpoint({}, {:?})", self.address(), self.trust)
    }
}

impl FromStr for HubEndpoint {
    type Err = EndpointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s, None)
    }
}

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(crate) fn finish(mut config: ClientConfig) -> ClientConfig {
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

/// Root certificates of the public web PKI.
pub(crate) fn public_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

fn public_config() -> Result<ClientConfig, rustls::Error> {
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(public_roots())
        .with_no_client_auth();
    Ok(finish(config))
}

fn pinned_config(fingerprint: [u8; 32]) -> Result<ClientConfig, rustls::Error> {
    let provider = provider();
    let verifier = Arc::new(Pinned {
        fingerprint,
        provider: Arc::clone(&provider),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(finish(config))
}

/// Accepts only the leaf certificate with the pinned SHA-256; signatures are still checked.
#[derive(Debug)]
struct Pinned {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            tracing::warn!(expected = %hex::encode(self.fingerprint), actual = %hex::encode(actual), "hub certificate changed");
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_choose_the_trust_mode() {
        let fp = "AB:".repeat(31) + "AB";
        let pinned = HubEndpoint::new("https://hub.example:7443/", Some(&fp)).unwrap();
        assert_eq!(pinned.trust(), &Trust::Pinned([0xab; 32]));
        assert_eq!(pinned.host(), "hub.example");
        assert_eq!(
            HubEndpoint::new("hub:7443", None).unwrap().trust(),
            &Trust::PublicCa
        );
        assert_eq!(
            HubEndpoint::new("http://127.0.0.1:7443", None)
                .unwrap()
                .trust(),
            &Trust::Plaintext
        );
        assert_eq!(
            HubEndpoint::new("http://h:1", Some(&fp)),
            Err(EndpointError::PinnedPlaintext)
        );
        assert_eq!(HubEndpoint::new("hub", None), Err(EndpointError::Address));
        assert_eq!(
            HubEndpoint::new("[::1]:7443", None).unwrap().address(),
            "[::1]:7443"
        );
    }

    #[test]
    fn a_stored_trust_mode_must_match_the_address_scheme() {
        let pinned = HubEndpoint::with_trust("https://hub:7443", Trust::Pinned([1; 32])).unwrap();
        assert_eq!(
            pinned,
            HubEndpoint::new("hub:7443", Some(&"01".repeat(32))).unwrap()
        );
        assert_eq!(
            HubEndpoint::with_trust("hub:7443", Trust::PublicCa)
                .unwrap()
                .trust(),
            &Trust::PublicCa
        );
        assert_eq!(
            HubEndpoint::with_trust("http://h:1", Trust::Plaintext)
                .unwrap()
                .address(),
            "http://h:1"
        );
        assert_eq!(
            HubEndpoint::with_trust("http://h:1", Trust::PublicCa),
            Err(EndpointError::Scheme)
        );
        assert_eq!(
            HubEndpoint::with_trust("https://h:1", Trust::Plaintext),
            Err(EndpointError::Scheme)
        );
        assert_eq!(
            HubEndpoint::with_trust("http://h:1", Trust::Pinned([1; 32])),
            Err(EndpointError::PinnedPlaintext)
        );
    }
}
