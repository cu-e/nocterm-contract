#![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
use super::*;
use crate::{command::UnsignedCommand, testing::NOW, testing::World};

fn sealed(world: &World) -> (SealedCommand, PendingCommand) {
    let command = UnsignedCommand::prepare(
        &world.selector,
        world.account_public(),
        &world.device,
        crate::command::CommandAction::Stop {
            run: RunCoordinate {
                id: [0x21; 16],
                expected_epoch: 1,
            },
        },
        4,
        NOW,
    )
    .unwrap();
    let pending = PendingCommand {
        command_id: command.command_id(),
        kind: PendingKind::Stop,
        text: "ünïcode".to_owned(),
        run: Some(RunCoordinate {
            id: [0x21; 16],
            expected_epoch: 1,
        }),
        state: CommandState::Delivered,
        at_ms: NOW,
    };
    let signature = world.device_key.sign(&command.signing_bytes().unwrap());
    let sealed = command
        .seal(&world.account_pair, &signature, &world.capabilities)
        .unwrap();
    (sealed, pending)
}

#[test]
fn a_stored_command_opens_with_exactly_its_bytes_and_its_pending_row_sending_again() {
    let world = World::new();
    let (sealed, pending) = sealed(&world);
    let stored = store(&world.selector, &world.keys(), &sealed, &pending).unwrap();
    assert!(
        !stored
            .as_bytes()
            .windows(pending.text.len())
            .any(|w| w == pending.text.as_bytes()),
        "no plaintext at rest"
    );
    let stored = StoredCommand::from_bytes(stored.into_bytes());
    let (opened, again) =
        open(&world.selector, &world.keys(), &world.capabilities, &stored).unwrap();
    let (before, after) = (sealed.publication(), opened.publication());
    assert_eq!(before.publication_id(), after.publication_id());
    assert_eq!(before.binding().unwrap(), after.binding().unwrap());
    assert_eq!(before.ciphertext(), after.ciphertext());
    assert_eq!(before.ciphertext_sha256(), after.ciphertext_sha256());
    assert_eq!(opened.semantic_digest(), sealed.semantic_digest());
    assert_eq!(opened.expected_control_revision(), 4);
    assert_eq!(opened.accept_before_ms(), sealed.accept_before_ms());
    assert_eq!(
        again,
        PendingCommand {
            state: CommandState::Sending,
            ..pending
        }
    );
}

#[test]
fn a_stored_command_opens_only_unaltered_and_for_its_own_account() {
    let world = World::new();
    let (sealed, pending) = sealed(&world);
    let stored = store(&world.selector, &world.keys(), &sealed, &pending).unwrap();
    let mut altered = stored.as_bytes().to_vec();
    *altered.last_mut().unwrap() ^= 1;
    for bytes in [altered, stored.as_bytes()[..20].to_vec(), Vec::new()] {
        let refused = open(
            &world.selector,
            &world.keys(),
            &world.capabilities,
            &StoredCommand::from_bytes(bytes),
        );
        assert!(matches!(refused, Err(CloudDeviceError::StoredCommand)));
    }
    let other = World::new();
    assert!(open(&other.selector, &other.keys(), &other.capabilities, &stored).is_err());
    let oversized = StoredCommand::from_bytes(vec![0; MAX_STORED_COMMAND_PLAINTEXT_BYTES + 65]);
    assert!(matches!(
        open(
            &world.selector,
            &world.keys(),
            &world.capabilities,
            &oversized
        ),
        Err(CloudDeviceError::StoredCommand)
    ));
}
