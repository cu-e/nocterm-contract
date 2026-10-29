use super::*;
use crate::cloud::{
    CommandError,
    payload::{ModelSelection, PromptPart},
};

fn accepted() -> Result<AcceptedPrompt<'static>, CommandError> {
    Ok(AcceptedPrompt {
        content: vec![PromptPart::Text("accepted without execution authority")],
        model: ModelSelection {
            provider: CloudTextId::new("openai")?,
            model: CloudTextId::new("model")?,
            pricing_policy: CloudTextId::new("pricing")?,
        },
        target: None,
        existing_session: None,
    })
}

#[test]
fn accepted_prompt_is_view_content_with_no_required_execution_target_or_inference_limits()
-> TestResult {
    let event = observation(CloudEventPayload::PromptAccepted {
        command: command()?,
        run: run(),
        prompt: Box::new(accepted()?),
    });
    let bytes = event.canonical_bytes()?;
    let actual = CloudEvent::from_canonical_bytes(&bytes)?;
    assert_eq!(actual, event);
    let CloudEventPayload::PromptAccepted { prompt, .. } = actual.payload else {
        return Err("prompt".into());
    };
    assert!(prompt.target.is_none());
    assert!(prompt.existing_session.is_none());
    assert_eq!(
        prompt.content,
        vec![PromptPart::Text("accepted without execution authority")]
    );
    assert!(!format!("{prompt:?}").contains("accepted without execution authority"));
    Ok(())
}

#[test]
fn accepted_prompt_keeps_shared_content_bounds_and_exact_session_target_relationship() -> TestResult
{
    let mut prompt = accepted()?;
    prompt.content = vec![PromptPart::Text("x"); 129];
    assert!(
        observation(CloudEventPayload::PromptAccepted {
            command: command()?,
            run: run(),
            prompt: Box::new(prompt)
        })
        .validate()
        .is_err()
    );
    let mut prompt = accepted()?;
    prompt.existing_session = Some(approval()?.execution.session);
    assert!(
        observation(CloudEventPayload::PromptAccepted {
            command: command()?,
            run: run(),
            prompt: Box::new(prompt)
        })
        .validate()
        .is_err()
    );
    Ok(())
}
