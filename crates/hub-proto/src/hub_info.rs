//! Reading the descriptive fields of `HubInfo`.

use crate::v2;

/// Longest web panel URL a client accepts.
const MAX_WEB_URL_BYTES: usize = 2048;

/// The hub's web panel URL, when it states one a client may offer as a link: an absolute
/// `https://` URL of at most 2048 bytes without whitespace or control characters. `None` for an
/// empty field (no panel, or a hub that predates it) and for anything else.
pub fn web_url_from_wire(info: &v2::HubInfo) -> Option<&str> {
    let url = info.web_url.as_str();
    let host = url.strip_prefix("https://")?;
    let usable = !host.is_empty()
        && !host.starts_with('/')
        && url.len() <= MAX_WEB_URL_BYTES
        && !url.chars().any(|c| c.is_whitespace() || c.is_control());
    usable.then_some(url)
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    fn info(url: &str) -> v2::HubInfo {
        v2::HubInfo {
            hub_id: "hub".into(),
            web_url: url.into(),
            ..v2::HubInfo::default()
        }
    }

    #[test]
    fn a_stated_panel_url_survives_the_wire() {
        let wire = info("https://hub.example.org/panel/");
        let decoded = v2::HubInfo::decode(wire.encode_to_vec().as_slice()).unwrap();
        assert_eq!(
            web_url_from_wire(&decoded),
            Some("https://hub.example.org/panel/")
        );
    }

    #[test]
    fn no_or_unusable_urls_read_as_none() {
        for url in [
            "",
            "http://hub.example.org/",
            "javascript:alert(1)",
            "https://",
            "https:///path",
            "https://hub.example.org/a b",
            "https://hub.example.org/\n",
            &format!("https://{}", "a".repeat(MAX_WEB_URL_BYTES)),
        ] {
            assert_eq!(web_url_from_wire(&info(url)), None, "{url:?}");
        }
    }
}
