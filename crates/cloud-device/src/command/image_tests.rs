#![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
use super::{
    CommandAction,
    tests::{open, policy, prepare, sign_and_seal},
};
use crate::{
    CloudDeviceError,
    open::{MAX_PROMPT_IMAGE_BYTES, MAX_PROMPT_IMAGES, PromptImage},
    testing::World,
};
use nocterm_hub_model::cloud::capabilities::CLOUD_FEATURE_FRAGMENTED_PUBLISH;
use nocterm_hub_model::cloud::payload::{CloudCommandPayload, ImageMime, PromptPart};

#[test]
fn an_image_larger_than_one_frame_is_sealed_under_the_logical_envelope_limit() {
    let world =
        World::with_features(crate::testing::ALL_FEATURES | CLOUD_FEATURE_FRAGMENTED_PUBLISH);
    let bytes = include_bytes!("../../tests/fixtures/prompt-large.png");
    assert!(bytes.len() > 128 * 1024);
    let images = [PromptImage {
        mime: ImageMime::Png,
        bytes: bytes.as_slice().into(),
    }];
    let policy = policy();
    let sealed = sign_and_seal(
        &world,
        prepare(
            &world,
            CommandAction::PromptWithImages {
                policy: &policy,
                text: "",
                images: &images,
            },
        ),
    );
    assert!(sealed.publication().total_bytes() > world.capabilities.limits().max_frame_bytes);
    open(&world, &sealed, |command| {
        let CloudCommandPayload::SubmitPrompt(prompt) =
            CloudCommandPayload::from_command(command).unwrap()
        else {
            panic!("prompt expected")
        };
        assert_eq!(
            prompt.content,
            vec![PromptPart::Image {
                mime: ImageMime::Png,
                bytes
            }]
        );
    });
}

#[test]
fn a_five_mib_valid_png_keeps_the_exact_signed_body_through_stored_command_roundtrip() {
    let world =
        World::with_features(crate::testing::ALL_FEATURES | CLOUD_FEATURE_FRAGMENTED_PUBLISH);
    let original = include_bytes!("../../tests/fixtures/prompt-large.png");
    // Add a valid private ancillary chunk before IEND; CRC32(npAD || 4,980,380 zeroes).
    let padding = MAX_PROMPT_IMAGE_BYTES - original.len() - 12;
    assert_eq!(padding, 4_980_380);
    let mut bytes = original[..original.len() - 12].to_vec();
    bytes.extend_from_slice(&u32::try_from(padding).unwrap().to_be_bytes());
    bytes.extend_from_slice(b"npAD");
    bytes.resize(bytes.len() + padding, 0);
    bytes.extend_from_slice(&0x5ee8_c97f_u32.to_be_bytes());
    bytes.extend_from_slice(&original[original.len() - 12..]);
    assert_eq!(bytes.len(), MAX_PROMPT_IMAGE_BYTES);
    let images = [PromptImage {
        mime: ImageMime::Png,
        bytes: bytes.into(),
    }];
    let policy = policy();
    let command = prepare(
        &world,
        CommandAction::PromptWithImages {
            policy: &policy,
            text: "",
            images: &images,
        },
    );
    command.require_publication(&world.capabilities).unwrap();
    let command_id = command.command_id();
    let sealed = sign_and_seal(&world, command);
    let pending = crate::transcript::PendingCommand {
        command_id,
        kind: crate::transcript::PendingKind::Prompt,
        text: String::new(),
        run: None,
        state: crate::transcript::CommandState::Sending,
        at_ms: crate::testing::NOW,
    };
    let stored = super::stored::store(&world.selector, &world.keys(), &sealed, &pending).unwrap();
    let (restored, restored_pending) =
        super::stored::open(&world.selector, &world.keys(), &world.capabilities, &stored).unwrap();
    assert_eq!(restored_pending, pending);
    assert_eq!(
        restored.publication().publication_id(),
        sealed.publication().publication_id()
    );
    assert_eq!(
        restored.publication().ciphertext(),
        sealed.publication().ciphertext()
    );
    assert_eq!(
        restored.publication().ciphertext_sha256(),
        sealed.publication().ciphertext_sha256()
    );
    let old = World::new();
    assert!(matches!(
        super::stored::open(&world.selector, &world.keys(), &old.capabilities, &stored),
        Err(CloudDeviceError::LargePublicationUnsupported)
    ));
    open(&world, &restored, |command| {
        let CloudCommandPayload::SubmitPrompt(prompt) =
            CloudCommandPayload::from_command(command).unwrap()
        else {
            panic!("prompt expected")
        };
        assert_eq!(
            prompt.content,
            vec![PromptPart::Image {
                mime: ImageMime::Png,
                bytes: &images[0].bytes
            }]
        );
    });
}

#[test]
fn a_large_image_on_an_old_hub_is_refused_before_signing_or_tracking() {
    let world = World::new();
    let images = [PromptImage {
        mime: ImageMime::Png,
        bytes: include_bytes!("../../tests/fixtures/prompt-large.png")
            .as_slice()
            .into(),
    }];
    let policy = policy();
    let command = prepare(
        &world,
        CommandAction::PromptWithImages {
            policy: &policy,
            text: "",
            images: &images,
        },
    );
    assert!(matches!(
        command.require_publication(&world.capabilities),
        Err(CloudDeviceError::LargePublicationUnsupported)
    ));
}

#[test]
fn inline_images_reach_the_runner_inside_the_original_signed_prompt() {
    let world = World::new();
    let image = PromptImage {
        mime: ImageMime::Png,
        bytes: b"image bytes".as_slice().into(),
    };
    let images = [image];
    let policy = policy();
    let sealed = sign_and_seal(
        &world,
        prepare(
            &world,
            CommandAction::PromptWithImages {
                policy: &policy,
                text: "describe it",
                images: &images,
            },
        ),
    );
    open(&world, &sealed, |command| {
        let CloudCommandPayload::SubmitPrompt(prompt) =
            CloudCommandPayload::from_command(command).unwrap()
        else {
            panic!("prompt expected")
        };
        assert_eq!(
            prompt.content,
            vec![
                PromptPart::Text("describe it"),
                PromptPart::Image {
                    mime: ImageMime::Png,
                    bytes: b"image bytes"
                }
            ]
        );
        assert_eq!(prompt.model.model.as_str(), "model-a");
    });
}

#[test]
fn image_admission_refuses_excessive_count_bytes_and_empty_images() {
    let image = PromptImage {
        mime: ImageMime::Png,
        bytes: b"image bytes".as_slice().into(),
    };
    let images = vec![image.clone(); MAX_PROMPT_IMAGES + 1];
    assert!(matches!(
        policy().prompt_with_images("hi", &images, 0),
        Err(CloudDeviceError::Capacity)
    ));
    let images = [PromptImage {
        bytes: vec![0; MAX_PROMPT_IMAGE_BYTES + 1].into(),
        ..image.clone()
    }];
    assert!(matches!(
        policy().prompt_with_images("hi", &images, 0),
        Err(CloudDeviceError::Capacity)
    ));
    let images = [PromptImage {
        bytes: [].as_slice().into(),
        ..image
    }];
    assert!(matches!(
        policy().prompt_with_images("hi", &images, 0),
        Err(CloudDeviceError::Capacity)
    ));
}

#[test]
fn an_image_only_prompt_has_no_empty_text_part_in_its_signed_payload() {
    let world = World::new();
    let images = [PromptImage {
        mime: ImageMime::Png,
        bytes: b"image bytes".as_slice().into(),
    }];
    let policy = policy();
    let sealed = sign_and_seal(
        &world,
        prepare(
            &world,
            CommandAction::PromptWithImages {
                policy: &policy,
                text: "",
                images: &images,
            },
        ),
    );
    open(&world, &sealed, |command| {
        let CloudCommandPayload::SubmitPrompt(prompt) =
            CloudCommandPayload::from_command(command).unwrap()
        else {
            panic!("prompt expected")
        };
        assert_eq!(
            prompt.content,
            vec![PromptPart::Image {
                mime: ImageMime::Png,
                bytes: b"image bytes"
            }]
        );
    });
    assert!(matches!(
        policy.prompt_with_images("", &[], 0),
        Err(CloudDeviceError::Policy)
    ));
}
