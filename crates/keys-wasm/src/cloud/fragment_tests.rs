#![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
use super::{
    fixture::{NOW_MS, drive, replay::Replayer},
    tests::opened,
    types::{ChatActionInput, PromptImageInput, WireEffect},
};

fn action() -> ChatActionInput {
    ChatActionInput::Prompt {
        text: String::new(),
        model: None,
        server: None,
        images: vec![PromptImageInput {
            mime: "image/png".into(),
            bytes: include_bytes!("../../../cloud-device/tests/fixtures/prompt-large.png").to_vec(),
        }],
    }
}

#[test]
fn an_old_hub_refuses_a_large_image_before_pending_admission() {
    let mut hub = Replayer::new();
    let (_, mut chat, ..) = opened(&mut hub);
    let before = serde_json::to_value(chat.transcript()).unwrap();
    let error = chat.delivery(action(), None, NOW_MS).unwrap_err();
    assert_eq!(error.code(), "large_publication_unsupported");
    assert!(error.to_string().contains("update the Cloud hub"));
    assert_eq!(serde_json::to_value(chat.transcript()).unwrap(), before);
    assert!(hub.published.is_empty());
}

#[test]
fn a_large_image_effect_preserves_its_original_body_and_negotiated_frame_bound() {
    let mut hub = Replayer::with_fragmented_publish();
    let (_, mut chat, ..) = opened(&mut hub);
    let mut delivery = chat.delivery(action(), None, NOW_MS).unwrap();
    drive(&mut delivery, &mut hub, NOW_MS);
    let WireEffect::Publish {
        publication,
        data,
        max_frame_bytes,
    } = &hub.published[0]
    else {
        panic!("publication expected")
    };
    assert_eq!(*max_frame_bytes, Some(16 * 1024));
    assert!(data.len() > 128 * 1024);
    assert_eq!(
        data.len(),
        usize::try_from(publication.total_bytes).unwrap()
    );
    let wire = serde_json::to_value(&hub.published[0]).unwrap();
    assert_eq!(wire["maxFrameBytes"], 16 * 1024);
    let (kind, _, payload) = super::tests::opened_command(&hub.published[0]);
    let nocterm_hub_model::cloud::payload::CloudCommandPayload::SubmitPrompt(prompt) =
        nocterm_hub_model::cloud::payload::CloudCommandPayload::from_canonical_bytes(
            kind, &payload,
        )
        .unwrap()
    else {
        panic!("prompt expected")
    };
    assert_eq!(
        prompt.content,
        vec![nocterm_hub_model::cloud::payload::PromptPart::Image {
            mime: nocterm_hub_model::cloud::payload::ImageMime::Png,
            bytes: include_bytes!("../../../cloud-device/tests/fixtures/prompt-large.png"),
        }]
    );
}
