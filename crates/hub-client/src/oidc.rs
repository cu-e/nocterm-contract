//! Sign-in through an identity provider with a loopback redirect and PKCE (RFC 8252).

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nocterm_hub_proto::v1::{self, complete_login_request};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::signer::Session;
use crate::{ClientError, DeviceInfo, HubClient, OidcError};

/// How long the user has to finish signing in in the browser.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

fn random_text<const N: usize>() -> Result<String, OidcError> {
    nocterm_keys::random_bytes::<N>()
        .map(|b| URL_SAFE_NO_PAD.encode(b))
        .map_err(OidcError::Randomness)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parameters of a `GET /callback?…` request line, or `None` for other paths.
fn callback_query(request: &str) -> Option<Vec<(String, String)>> {
    let target = request
        .lines()
        .next()?
        .strip_prefix("GET ")?
        .split(' ')
        .next()?;
    let query = target
        .strip_prefix("/callback")?
        .strip_prefix('?')
        .unwrap_or("");
    Some(
        query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                (percent_decode(key), percent_decode(value))
            })
            .collect(),
    )
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let page = format!(
        "<!doctype html><meta charset=utf-8><title>Nocterm</title><body style=\"font-family:sans-serif;padding:3em\"><h2>{body}</h2></body>"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buffer = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    while !buffer.windows(4).any(|w| w == b"\r\n\r\n") && buffer.len() < 16 * 1024 {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

/// Waits for the provider's redirect and returns the authorization code.
async fn wait_for_code(listener: &TcpListener, state: &str) -> Result<String, OidcError> {
    loop {
        let (mut stream, _) = listener.accept().await.map_err(OidcError::Loopback)?;
        let request = read_request(&mut stream)
            .await
            .map_err(OidcError::Loopback)?;
        let Some(params) = callback_query(&request) else {
            respond(&mut stream, "404 Not Found", "Not found").await;
            continue;
        };
        let get = |name: &str| {
            params
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        if get("state").as_deref() != Some(state) {
            respond(
                &mut stream,
                "400 Bad Request",
                "Sign-in failed: unexpected state.",
            )
            .await;
            return Err(OidcError::UnexpectedState);
        }
        if let Some(error) = get("error") {
            let description = get("error_description").unwrap_or_default();
            respond(
                &mut stream,
                "400 Bad Request",
                "Sign-in was cancelled or failed.",
            )
            .await;
            return Err(OidcError::Provider { error, description });
        }
        let Some(code) = get("code") else {
            respond(&mut stream, "400 Bad Request", "Sign-in failed: no code.").await;
            return Err(OidcError::NoCode);
        };
        respond(
            &mut stream,
            "200 OK",
            "Signed in to Nocterm. You can close this tab.",
        )
        .await;
        return Ok(code);
    }
}

impl HubClient {
    /// Signs in through `provider`: `open` receives the URL to show in a browser.
    pub async fn oidc_login(
        &self,
        provider: &str,
        device: &DeviceInfo,
        open: impl FnOnce(&str),
    ) -> Result<Session, ClientError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(OidcError::Loopback)?;
        let port = listener.local_addr().map_err(OidcError::Loopback)?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}/callback");
        let verifier = random_text::<32>()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = random_text::<16>()?;
        let start = self
            .auth()
            .start_oidc_login(v1::StartOidcLoginRequest {
                provider_id: provider.to_owned(),
                redirect_uri: redirect_uri.clone(),
                code_challenge: challenge,
                state: state.clone(),
            })
            .await?
            .into_inner();
        open(&start.authorize_url);
        let code = tokio::time::timeout(LOGIN_TIMEOUT, wait_for_code(&listener, &state))
            .await
            .map_err(|_| OidcError::TimedOut)??;
        let grant = v1::OidcCodeGrant {
            code,
            code_verifier: verifier,
            redirect_uri,
        };
        self.complete_login(complete_login_request::Grant::Oidc(grant), device)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_callback_query_is_decoded() {
        let params =
            callback_query("GET /callback?code=a%2Fb+c&state=xyz HTTP/1.1\r\nHost: x\r\n\r\n")
                .unwrap();
        assert_eq!(
            params,
            vec![
                ("code".into(), "a/b c".into()),
                ("state".into(), "xyz".into())
            ]
        );
        assert!(callback_query("GET /favicon.ico HTTP/1.1\r\n").is_none());
        assert_eq!(percent_decode("100%"), "100%");
    }
}
