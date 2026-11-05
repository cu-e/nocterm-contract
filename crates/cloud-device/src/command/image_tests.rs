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
use nocterm_hub_model::cloud::payload::{CloudCommandPayload, ImageMime, PromptPart};

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
