//! Admission of inline prompt bytes before the device flow retains them.
use super::{CloudResult, WebCloudError, view::PromptImageInput};
use nocterm_cloud_device::open::{
    MAX_PROMPT_IMAGE_BYTES, MAX_PROMPT_IMAGE_TOTAL_BYTES, MAX_PROMPT_IMAGES, PromptImage,
};
use nocterm_hub_model::cloud::payload::ImageMime;

pub(super) fn images(inputs: Vec<PromptImageInput>) -> CloudResult<Vec<PromptImage>> {
    if inputs.len() > MAX_PROMPT_IMAGES
        || inputs
            .iter()
            .any(|image| image.bytes.is_empty() || image.bytes.len() > MAX_PROMPT_IMAGE_BYTES)
        || inputs.iter().map(|image| image.bytes.len()).sum::<usize>()
            > MAX_PROMPT_IMAGE_TOTAL_BYTES
    {
        return Err(WebCloudError::Argument(
            "images exceed the prompt image limits",
        ));
    }
    inputs
        .into_iter()
        .map(|image| {
            let mime = match image.mime.as_str() {
                "image/png" => ImageMime::Png,
                "image/jpeg" => ImageMime::Jpeg,
                "image/gif" => ImageMime::Gif,
                "image/webp" => ImageMime::Webp,
                _ => return Err(WebCloudError::Argument("unsupported prompt image type")),
            };
            Ok(PromptImage {
                mime,
                bytes: image.bytes.into(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validated_mime_and_raw_bytes_survive_the_wasm_boundary() {
        let result = images(vec![PromptImageInput {
            mime: "image/png".into(),
            bytes: vec![1, 2, 3],
        }]);
        assert!(
            matches!(result, Ok(images) if images[0].mime == ImageMime::Png && images[0].bytes.as_ref() == [1,2,3])
        );
        assert!(matches!(
            images(vec![PromptImageInput {
                mime: "text/plain".into(),
                bytes: vec![1]
            }]),
            Err(WebCloudError::Argument(_))
        ));
    }
    #[test]
    fn image_limits_apply_before_the_flow_retains_bytes() {
        let input = || PromptImageInput {
            mime: "image/png".into(),
            bytes: vec![1],
        };
        assert!(matches!(
            images((0..=MAX_PROMPT_IMAGES).map(|_| input()).collect()),
            Err(WebCloudError::Argument(_))
        ));
    }
}
