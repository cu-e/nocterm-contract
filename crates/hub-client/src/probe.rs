//! First contact with a hub: read its certificate without trusting it (trust on first use).

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{VerifierBuilderError, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, InvalidDnsNameError, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::connect::{finish, parse_address, provider, public_roots};
use crate::{EndpointError, HubEndpoint};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// What a hub presented in a TLS handshake that trusted no certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// SHA-256 of the leaf certificate (DER), the value [`crate::Trust::Pinned`] expects.
    pub fingerprint: [u8; 32],
    /// The chain is valid for the probed host name under the public web PKI, so
    /// [`crate::Trust::PublicCa`] would accept it.
    pub publicly_trusted: bool,
}

impl Probe {
    /// The fingerprint as lowercase hex, the form the hub prints and
    /// [`crate::parse_fingerprint`] accepts.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }
}

/// The hub's certificate could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    #[error("invalid hub address")]
    Endpoint(#[from] EndpointError),
    /// An `http://` address has no TLS, so there is no certificate to show.
    #[error("a plaintext http:// hub has no certificate")]
    Plaintext,
    #[error("the host is not a valid TLS server name")]
    ServerName(#[source] InvalidDnsNameError),
    #[error("TLS setup failed")]
    Tls(#[source] rustls::Error),
    #[error("cannot check certificates against public CAs")]
    Verifier(#[source] VerifierBuilderError),
    #[error("cannot reach the hub")]
    Unreachable(#[source] std::io::Error),
    /// TCP connected but the TLS handshake failed (not a TLS server, bad signature, …).
    #[error("the TLS handshake with the hub failed")]
    Handshake(#[source] std::io::Error),
    #[error("the hub presented no certificate")]
    NoCertificate,
    #[error("timed out waiting for the hub")]
    TimedOut,
}

impl HubEndpoint {
    /// Completes a TLS handshake with the hub at `address` (`host:port` or
    /// `https://host:port`) that accepts any certificate, and reports the leaf's
    /// fingerprint and whether public CAs vouch for it. Handshake signatures are still
    /// verified, so the peer holds the certificate's key. Sends no credentials and makes no
    /// call: show the fingerprint to the user before pinning it.
    pub async fn probe(address: &str) -> Result<Probe, ProbeError> {
        let (host, port, plaintext) = parse_address(address)?;
        if plaintext == Some(true) {
            return Err(ProbeError::Plaintext);
        }
        let name = ServerName::try_from(host.clone()).map_err(ProbeError::ServerName)?;
        let public =
            WebPkiServerVerifier::builder_with_provider(Arc::new(public_roots()), provider())
                .build()
                .map_err(ProbeError::Verifier)?;
        let config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(ProbeError::Tls)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate {
                public: Arc::clone(&public),
            }))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(finish(config)));
        let handshake = async {
            let tcp = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(ProbeError::Unreachable)?;
            connector
                .connect(name.clone(), tcp)
                .await
                .map_err(ProbeError::Handshake)
        };
        let mut stream = tokio::time::timeout(PROBE_TIMEOUT, handshake)
            .await
            .map_err(|_| ProbeError::TimedOut)??;
        let chain = stream.get_ref().1.peer_certificates().unwrap_or_default();
        let (leaf, intermediates) = chain.split_first().ok_or(ProbeError::NoCertificate)?;
        let probe = Probe {
            fingerprint: Sha256::digest(leaf.as_ref()).into(),
            publicly_trusted: public
                .verify_server_cert(leaf, intermediates, &name, &[], UnixTime::now())
                .is_ok(),
        };
        let _ = stream.shutdown().await;
        Ok(probe)
    }
}

/// Accepts any certificate; handshake signatures are checked as the public verifier does.
#[derive(Debug)]
struct AnyCertificate {
    public: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.public.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.public.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.public.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_plaintext_address_has_nothing_to_probe() {
        assert!(matches!(
            HubEndpoint::probe("http://127.0.0.1:1").await,
            Err(ProbeError::Plaintext)
        ));
        assert!(matches!(
            HubEndpoint::probe("no-port").await,
            Err(ProbeError::Endpoint(EndpointError::Address))
        ));
    }

    #[tokio::test]
    async fn a_closed_port_is_unreachable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(matches!(
            HubEndpoint::probe(&format!("127.0.0.1:{port}")).await,
            Err(ProbeError::Unreachable(_))
        ));
    }
}
