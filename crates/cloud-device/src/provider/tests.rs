#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::testing::{
    NOW, World,
    hub::{Ended, FakeHub},
};
use nocterm_hub_model::cloud::{
    CommandKind,
    payload::{CloudCommandPayload, GrantPayload},
    provider::{BootDescriptor, BootWindow},
    relay::RelayBinding,
};
use nocterm_keys::{
    PublicKey,
    cloud::{RunnerBootKey, open_command},
};

const COLLECTION: &str = "provider-keys";
const SECRET: &[u8] = b"sk-test-secret";

/// A hub with the agent's key and a runner whose current boot `boot` attests.
fn leasing_hub(boot: &RunnerBootKey) -> FakeHub {
    let mut hub = FakeHub::new(World::new());
    let key = hub.collection(COLLECTION, PROVIDER_KEYS_KIND);
    let record = ProviderKeyRecord::new("openai", "gpt-own", SECRET).unwrap();
    let object = provider_key_object("agent-1");
    let sealed = key
        .seal_object(
            COLLECTION,
            &object,
            PROVIDER_KEYS_KIND,
            &record.encode().unwrap(),
        )
        .unwrap();
    hub.object(COLLECTION, &object, PROVIDER_KEYS_KIND, sealed);
    let descriptor = BootDescriptor::new(
        hub.world.selector.scope().namespace(),
        hub.world.runner.runner(),
        [0xb0; 16],
        boot.public_key().to_bytes(),
        BootWindow {
            issued_at_ms: NOW - 1_000,
            expires_at_ms: NOW + 29 * 60 * 1000,
        },
    )
    .unwrap();
    let signed = hub.world.runner_signer.attest_boot(descriptor).unwrap();
    hub.status = Some(signed.canonical_bytes().unwrap());
    hub
}
fn lease(hub: &FakeHub) -> ProviderLease {
    ProviderLease::new(
        hub.world.session(),
        hub.world.device.clone(),
        &ChatRef::of(&hub.world.selector),
        "agent-1",
        3,
    )
    .unwrap()
}
/// The provider grant the runner opens from the last publication.
fn opened_grant(hub: &FakeHub, boot: &RunnerBootKey, now: i64) -> (GrantReference, Vec<u8>) {
    let publication = hub.published.last().unwrap();
    let binding = RelayBinding::from_canonical_bytes(&publication.binding().unwrap()).unwrap();
    let opened = open_command(
        &hub.world.runner_key,
        &PublicKey::from_bytes(&hub.world.account_public()).unwrap(),
        binding.command_route().unwrap(),
        publication.ciphertext(),
    )
    .unwrap();
    let command = opened.command().unwrap();
    assert_eq!(command.header().context().run, None);
    let payload =
        CloudCommandPayload::from_canonical_bytes(CommandKind::IssueGrant, command.payload())
            .unwrap();
    let CloudCommandPayload::IssueGrant(grant) = payload else {
        panic!("a grant");
    };
    let GrantPayload::Provider {
        grant,
        context,
        allowed_models,
        capsule,
    } = *grant
    else {
        panic!("a provider grant");
    };
    assert_eq!(allowed_models[0].as_str(), "gpt-own");
    assert_eq!(context.provider_reference().as_str(), "openai");
    let account = PublicKey::from_bytes(&hub.world.account_public()).unwrap();
    let opened = boot
        .open_provider_lease(&account, &context, capsule, now)
        .unwrap();
    (grant, opened.secret().to_vec())
}

#[test]
fn the_lease_capsule_opens_with_the_runners_boot_key_and_renews_at_half_term() {
    let boot = RunnerBootKey::generate().unwrap();
    let mut hub = leasing_hub(&boot);
    let mut flow = lease(&hub);
    let (leases, ended) = hub.run(&mut flow, NOW);
    let renew = NOW + LEASE_TERM_MS / 2;
    assert!(matches!(ended, Ended::Idle(Some(at)) if at == renew));
    assert_eq!(leases[0].expires_at_ms, NOW + LEASE_TERM_MS);
    assert_eq!(leases[0].renew_at_ms, renew);
    let (grant, secret) = opened_grant(&hub, &boot, NOW);
    assert_eq!(secret, SECRET);
    assert_eq!(grant.id, leases[0].grant);
    assert_eq!(grant.epoch, u64::try_from(NOW + LEASE_TERM_MS).unwrap());

    let (renewed, _) = hub.run(&mut flow, renew);
    assert_eq!(hub.published.len(), 2);
    assert_eq!(
        renewed[0].grant, leases[0].grant,
        "one grant id, a newer epoch"
    );
    let (grant, secret) = opened_grant(&hub, &boot, renew);
    assert_eq!(secret, SECRET);
    assert!(grant.epoch > u64::try_from(NOW + LEASE_TERM_MS).unwrap());
    assert_eq!(
        hub.effects
            .iter()
            .filter(|e| **e == "runner_status")
            .count(),
        2,
        "each renewal verifies the current boot"
    );
}

#[test]
fn an_unknown_outcome_republishes_the_same_lease() {
    let boot = RunnerBootKey::generate().unwrap();
    let mut hub = leasing_hub(&boot);
    hub.publish
        .push_back(Input::Failed(crate::flow::EffectFailure::Unknown));
    let mut flow = lease(&hub);
    let (leases, ended) = hub.run(&mut flow, NOW);
    assert!(leases.is_empty());
    assert!(matches!(ended, Ended::Idle(Some(at)) if at == NOW + LEASE_RETRY_MS));
    let (leases, _) = hub.run(&mut flow, NOW + LEASE_RETRY_MS);
    assert_eq!(leases.len(), 1);
    assert_eq!(hub.published[0].ciphertext(), hub.published[1].ciphertext());
}

#[test]
fn a_boot_of_another_runner_or_a_missing_key_is_refused() {
    let boot = RunnerBootKey::generate().unwrap();
    let mut hub = leasing_hub(&boot);
    let other = RunnerSigningKeyless::forged(&hub, &boot);
    hub.status = Some(other);
    let mut flow = lease(&hub);
    let (_, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(
        ended,
        Ended::Failed(CloudDeviceError::ProviderLease(_))
    ));

    let mut hub = leasing_hub(&boot);
    hub.objects.clear();
    let mut flow = lease(&hub);
    let (_, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(
        ended,
        Ended::Failed(CloudDeviceError::NoProviderKey)
    ));

    let mut hub = leasing_hub(&boot);
    hub.collections.clear();
    let mut flow = lease(&hub);
    let (_, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(
        ended,
        Ended::Failed(CloudDeviceError::NoProviderKey)
    ));
}

#[test]
fn a_provider_key_record_round_trips_and_hides_its_key() {
    let record = ProviderKeyRecord::new("openai", "gpt-own", SECRET).unwrap();
    let encoded = record.encode().unwrap();
    let decoded = ProviderKeyRecord::decode(&encoded).unwrap();
    assert_eq!(decoded.expose(), SECRET);
    assert_eq!(decoded.provider(), "openai");
    assert!(!format!("{decoded:?}").contains("sk-test"));
    // The native client's layout.
    let native = br#"{"format":1,"provider":"p","model":"m","key":"c2stMQ=="}"#;
    assert_eq!(ProviderKeyRecord::decode(native).unwrap().expose(), b"sk-1");
    let other = br#"{"format":2,"provider":"p","model":"m","key":"c2stMQ=="}"#;
    assert!(matches!(
        ProviderKeyRecord::decode(other),
        Err(CloudDeviceError::Format)
    ));
}

/// A boot descriptor signed by a key that is not the pinned runner's.
struct RunnerSigningKeyless;
impl RunnerSigningKeyless {
    fn forged(hub: &FakeHub, boot: &RunnerBootKey) -> Vec<u8> {
        let descriptor = BootDescriptor::new(
            hub.world.selector.scope().namespace(),
            hub.world.runner.runner(),
            [0xb1; 16],
            boot.public_key().to_bytes(),
            BootWindow {
                issued_at_ms: NOW - 1_000,
                expires_at_ms: NOW + 60_000,
            },
        )
        .unwrap();
        nocterm_keys::cloud::RunnerSigningKey::from_seed(&[0x99; 32])
            .attest_boot(descriptor)
            .unwrap()
            .canonical_bytes()
            .unwrap()
    }
}
