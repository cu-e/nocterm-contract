//! What a client learns about a hub before signing in.

mod support;

use support::{FakeHub, WEB_URL};

#[tokio::test]
async fn the_client_offers_the_web_panel_the_hub_states() {
    let hub = FakeHub::start(false).await;
    let client = hub.client().await;
    assert_eq!(client.info().web_url, WEB_URL);
    assert_eq!(client.web_url(), Some(WEB_URL));
}
