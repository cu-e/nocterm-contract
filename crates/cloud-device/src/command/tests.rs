#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::{
    testing::{NONCE, NOW, World, capability_proof},
    transcript::Transcript,
};
use nocterm_hub_model::cloud::{
    capabilities::CLOUD_FEATURE_FRESH_HEAD,
    events::CloudEvent,
    payload::{GrantPayload, PromptPart},
};
use nocterm_keys::{DeviceKey, cloud::open_command};

const RUN: RunCoordinate = RunCoordinate {
    id: [0x21; 16],
    expected_epoch: 2,
};

pub(super) fn policy() -> PromptPolicy {
    PromptPolicy::managed("model-a").unwrap()
}
pub(super) fn prepare(world: &World, action: CommandAction<'_>) -> UnsignedCommand {
    UnsignedCommand::prepare(
        &world.selector,
        world.account_public(),
        &world.device,
        action,
        7,
        NOW,
    )
    .unwrap()
}
/// Signs like the browser: plain Ed25519 over the given bytes with the device key.
pub(super) fn sign_and_seal(world: &World, command: UnsignedCommand) -> SealedCommand {
    let signature = world.device_key.sign(&command.signing_bytes().unwrap());
    command
        .seal(&world.account_pair, &signature, &world.capabilities)
        .unwrap()
}
/// The runner's side: open the publication from the account pin at the expected route.
pub(super) fn open<R>(
    world: &World,
    sealed: &SealedCommand,
    check: impl FnOnce(&SignedCommand<'_>) -> R,
) -> R {
    let binding =
        RelayBinding::from_canonical_bytes(&sealed.publication().binding().unwrap()).unwrap();
    let route = binding.command_route().unwrap();
    let opened = open_command(
        &world.runner_key,
        &world.account_pair.public_key(),
        route,
        sealed.publication().ciphertext(),
    )
    .unwrap();
    let command = opened.command().unwrap();
    check(&command)
}

#[test]
fn a_prompt_signed_outside_opens_at_the_runner_with_the_policy_bounds() {
    let world = World::new();
    let sealed = sign_and_seal(
        &world,
        prepare(
            &world,
            CommandAction::Prompt {
                policy: &policy(),
                text: "hello",
            },
        ),
    );
    open(&world, &sealed, |command| {
        let header = command.header();
        assert_eq!(header.issuer().signing_key, world.device_key.public_key());
        assert_eq!(header.issuer().device_id.as_str(), "device-0001");
        assert_eq!(header.route().chat_id, [0x05; 16]);
        assert_eq!(header.context().expected_chat_revision, 7);
        assert_eq!(header.context().run, None);
        let CloudCommandPayload::SubmitPrompt(prompt) =
            CloudCommandPayload::from_command(command).unwrap()
        else {
            panic!("prompt expected");
        };
        assert_eq!(prompt.content, vec![PromptPart::Text("hello")]);
        assert_eq!(prompt.model.provider.as_str(), "managed");
        assert!(prompt.target.is_none() && prompt.existing_session.is_none());
        assert_eq!(prompt.inference.deadline_ms, NOW + 600_000);
        assert_eq!(
            sealed.semantic_digest(),
            <[u8; 32]>::from(Sha256::digest(header.canonical_bytes().unwrap()))
        );
    });
    let publication = sealed.publication();
    assert_eq!(
        publication.ciphertext_sha256(),
        <[u8; 32]>::from(Sha256::digest(publication.ciphertext()))
    );
    assert!(publication.is_receipt(
        &publication.publication_id(),
        9,
        &publication.ciphertext_sha256()
    ));
    assert!(!publication.is_receipt(&[0; 16], 9, &publication.ciphertext_sha256()));
}

#[test]
fn an_allow_carries_exactly_the_prompt_bounds_for_its_run() {
    let world = World::new();
    let policy = policy();
    let sealed = sign_and_seal(
        &world,
        prepare(
            &world,
            CommandAction::Allow {
                policy: &policy,
                run: RUN,
            },
        ),
    );
    open(&world, &sealed, |command| {
        assert_eq!(command.header().context().run, Some(RUN));
        assert_eq!(command.header().context().kind, CommandKind::IssueGrant);
        let CloudCommandPayload::IssueGrant(grant) =
            CloudCommandPayload::from_command(command).unwrap()
        else {
            panic!("grant expected");
        };
        let GrantPayload::Inference {
            window,
            limits,
            model,
            ..
        } = *grant
        else {
            panic!("inference grant expected");
        };
        let CloudCommandPayload::SubmitPrompt(prompt) = policy.prompt("x", NOW).unwrap() else {
            panic!("prompt expected");
        };
        assert_eq!(model, prompt.model);
        assert_eq!(window.issued_at_ms, NOW);
        assert_eq!(window.expires_at_ms, NOW + 300_000);
        assert_eq!(limits.deadline_ms, window.expires_at_ms);
        assert_eq!(
            InferenceLimitsView::from(limits, 0),
            InferenceLimitsView::from(prompt.inference, 0)
        );
    });
}

/// Limits without their deadline, to compare a grant with its prompt.
#[derive(Debug, PartialEq, Eq)]
struct InferenceLimitsView(nocterm_hub_model::cloud::payload::InferenceLimits);
impl InferenceLimitsView {
    fn from(
        mut limits: nocterm_hub_model::cloud::payload::InferenceLimits,
        deadline_ms: i64,
    ) -> Self {
        limits.deadline_ms = deadline_ms;
        Self(limits)
    }
}

#[test]
fn a_stop_names_its_run() {
    let world = World::new();
    let sealed = sign_and_seal(&world, prepare(&world, CommandAction::Stop { run: RUN }));
    open(&world, &sealed, |command| {
        assert_eq!(command.header().context().run, Some(RUN));
        assert_eq!(
            CloudCommandPayload::from_command(command).unwrap(),
            CloudCommandPayload::Stop
        );
    });
}

#[test]
fn an_answer_names_the_pending_approval_it_resolves() {
    let world = World::new();
    let mut transcript = Transcript::new();
    let approval =
        hex::decode(include_str!("../../../../fixtures/cloud-events-v1/approval.hex").trim())
            .unwrap();
    transcript.apply(&CloudEvent::from_canonical_bytes(&approval).unwrap());
    let request = transcript.pending_approvals()[0].clone();
    let sealed = sign_and_seal(
        &world,
        prepare(
            &world,
            CommandAction::Answer {
                approval: &request,
                choice: ApprovalChoice::Approve,
            },
        ),
    );
    open(&world, &sealed, |command| {
        let CloudCommandPayload::ResolveApproval(answer) =
            CloudCommandPayload::from_command(command).unwrap()
        else {
            panic!("answer expected");
        };
        assert_eq!(*answer, request.answer(ApprovalChoice::Approve));
        assert_eq!(command.header().context().run, Some(request.run()));
    });
}

#[test]
fn a_signature_by_another_key_or_of_another_length_is_refused() {
    let world = World::new();
    let command = prepare(&world, CommandAction::Stop { run: RUN });
    let other = DeviceKey::from_seed(&[0x62; 32]).sign(&command.signing_bytes().unwrap());
    assert!(matches!(
        command.seal(&world.account_pair, &other, &world.capabilities),
        Err(CloudDeviceError::Signature(_))
    ));
    let command = prepare(&world, CommandAction::Stop { run: RUN });
    assert!(matches!(
        command.seal(&world.account_pair, &[1; 63], &world.capabilities),
        Err(CloudDeviceError::Signature(_))
    ));
}

#[test]
fn a_prompt_whose_deadline_outlives_the_session_is_refused() {
    let mut world = World::new();
    world.device = DeviceIdentity::new(
        "device-0001",
        world.device_key.public_key(),
        "a",
        NOW + 60_000,
    )
    .unwrap();
    assert!(matches!(
        UnsignedCommand::prepare(
            &world.selector,
            world.account_public(),
            &world.device,
            CommandAction::Prompt {
                policy: &policy(),
                text: "x"
            },
            0,
            NOW
        ),
        Err(CloudDeviceError::SessionTooShort)
    ));
    let stop = prepare(&world, CommandAction::Stop { run: RUN });
    let sealed = sign_and_seal(&world, stop);
    assert_eq!(sealed.accept_before_ms(), NOW + 60_000);
}

#[test]
fn a_hub_without_unary_publish_or_an_oversized_command_is_refused() {
    let world = World::new();
    let (claim, signature) =
        capability_proof(&world.authority, CLOUD_FEATURE_FRESH_HEAD, NONCE, NOW);
    let reading = world
        .hub
        .verify_capabilities(&claim, &signature, &NONCE, NOW)
        .unwrap();
    let command = prepare(&world, CommandAction::Stop { run: RUN });
    let signature = world.device_key.sign(&command.signing_bytes().unwrap());
    assert!(matches!(
        command.seal(&world.account_pair, &signature, &reading),
        Err(CloudDeviceError::Unsupported)
    ));
    let long = "x".repeat(20 * 1024);
    let command = prepare(
        &world,
        CommandAction::Prompt {
            policy: &policy(),
            text: &long,
        },
    );
    let signature = world.device_key.sign(&command.signing_bytes().unwrap());
    assert!(matches!(
        command.seal(&world.account_pair, &signature, &world.capabilities),
        Err(CloudDeviceError::Capacity)
    ));
}

#[test]
fn a_command_for_another_account_key_is_refused() {
    let world = World::new();
    assert!(matches!(
        UnsignedCommand::prepare(
            &world.selector,
            [3; 32],
            &world.device,
            CommandAction::Stop { run: RUN },
            0,
            NOW
        ),
        Err(CloudDeviceError::Binding)
    ));
}
