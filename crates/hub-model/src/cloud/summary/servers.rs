//! The servers a runner lists in a chat's summary, from the chat's current binding and the
//! access state the runner last reported for it (contract ADR 0011).
use super::{BoundServer, ServerState};
use crate::cloud::ssh::{SshAccess, SshAccessUpdate, SshBinding, SshServerReach};

/// The [`super::ChatSummary::servers`] of a chat whose current binding is `binding` and whose
/// latest `SshAccessState` is `update`, at `now_ms`:
///
/// - revoked or expired, or a report of another grant or epoch: no servers (the chat is not
///   bound);
/// - refused: every bound server [`ServerState::Unreachable`];
/// - pending, or active with a certificate that lapsed by `now_ms`: admitted servers
///   [`ServerState::AwaitingDevice`];
/// - active: admitted servers [`ServerState::Active`] until the certificate's `valid_before_ms`;
/// - a server the report names unreachable, or does not name: [`ServerState::Unreachable`].
///
/// Servers keep the binding's order. A runner cannot know [`ServerState::NeedsCaUpdate`]; a
/// device derives it from its trust record.
pub fn bound_servers(
    binding: &SshBinding,
    update: &SshAccessUpdate,
    now_ms: i64,
) -> Vec<BoundServer> {
    if update.grant != binding.grant {
        return Vec::new();
    }
    let admitted = match update.access {
        SshAccess::Revoked | SshAccess::Expired => return Vec::new(),
        SshAccess::Refused(_) => None,
        SshAccess::Active {
            valid_before_ms, ..
        } if valid_before_ms > now_ms => Some((ServerState::Active, Some(valid_before_ms))),
        // Pending, or a certificate that lapsed: the runner waits for a device.
        SshAccess::Pending | SshAccess::Active { .. } => Some((ServerState::AwaitingDevice, None)),
    };
    binding
        .targets
        .iter()
        .map(|target| {
            let reach = update
                .servers
                .iter()
                .find(|status| status.server == target.server)
                .map(|status| status.reach);
            let (state, valid_before_ms) = match admitted {
                Some(state) if reach == Some(SshServerReach::Admitted) => state,
                _ => (ServerState::Unreachable, None),
            };
            BoundServer {
                server: target.server,
                host: target.host.clone(),
                port: target.port,
                user: target.user.clone(),
                state,
                valid_before_ms,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
    use super::*;
    use crate::cloud::{
        CloudTextId,
        payload::GrantReference,
        ssh::{BindingWindow, SshBindingRefusal, SshServerId, SshServerStatus, SshTarget},
    };

    const NOW: i64 = 1_800_000_000_000;

    fn target(profile: &str, host: &str) -> SshTarget {
        SshTarget {
            server: SshServerId::of_profile(profile),
            host: CloudTextId::new(host).unwrap(),
            port: 22,
            user: CloudTextId::new("deploy").unwrap(),
            host_key_sha256: [0xa1; 32],
        }
    }
    fn binding() -> SshBinding {
        SshBinding {
            chat: crate::cloud::summary::tests::context(1).chat().clone(),
            grant: GrantReference {
                id: [0x33; 16],
                epoch: 5,
            },
            window: BindingWindow {
                issued_at_ms: NOW - 1,
                expires_at_ms: NOW + 1_000_000,
            },
            ca_key: [0x91; 32],
            targets: vec![
                target("profile-db", "db.example.org"),
                target("profile-cache", "cache.example.org"),
                target("profile-web", "web.example.org"),
            ],
        }
    }
    fn update(access: SshAccess) -> SshAccessUpdate {
        let status = |profile, reach| SshServerStatus {
            server: SshServerId::of_profile(profile),
            reach,
        };
        SshAccessUpdate {
            grant: binding().grant,
            access,
            // `profile-web` is not named: it reads as unreachable.
            servers: vec![
                status("profile-db", SshServerReach::Admitted),
                status("profile-cache", SshServerReach::Unreachable),
            ],
        }
    }
    fn states(access: SshAccess) -> Vec<(ServerState, Option<i64>)> {
        bound_servers(&binding(), &update(access), NOW)
            .into_iter()
            .map(|server| (server.state, server.valid_before_ms))
            .collect()
    }

    #[test]
    fn admitted_servers_follow_the_access_state_and_the_rest_are_unreachable() {
        let unreachable = (ServerState::Unreachable, None);
        let active = SshAccess::Active {
            request: [4; 16],
            valid_before_ms: NOW + 10,
        };
        assert_eq!(
            states(active),
            [
                (ServerState::Active, Some(NOW + 10)),
                unreachable,
                unreachable
            ]
        );
        assert_eq!(
            states(SshAccess::Pending),
            [
                (ServerState::AwaitingDevice, None),
                unreachable,
                unreachable
            ]
        );
        let lapsed = SshAccess::Active {
            request: [4; 16],
            valid_before_ms: NOW,
        };
        assert_eq!(states(lapsed)[0], (ServerState::AwaitingDevice, None));
        let refused = SshAccess::Refused(SshBindingRefusal::NoSourceAddress);
        assert_eq!(states(refused), [unreachable; 3]);
        let servers = bound_servers(&binding(), &update(SshAccess::Pending), NOW);
        assert_eq!(servers[1].server, SshServerId::of_profile("profile-cache"));
        assert_eq!(servers[1].host.as_str(), "cache.example.org");
    }

    #[test]
    fn a_closed_binding_or_a_report_of_another_epoch_lists_no_servers() {
        assert!(states(SshAccess::Revoked).is_empty());
        assert!(states(SshAccess::Expired).is_empty());
        let mut older = update(SshAccess::Pending);
        older.grant.epoch -= 1;
        assert!(bound_servers(&binding(), &older, NOW).is_empty());
    }
}
