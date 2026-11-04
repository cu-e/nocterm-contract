//! A chat's SSH binding on the web panel (contract ADR 0009): the account's CA-trusted servers
//! read from `agent_ssh_trust`, the chat's bindings and open certificate requests as structured
//! values, and the `bindServers`, `unbindServers` and `answerSsh` flows of an open chat.
//!
//! The CA seed is opened inside the flows from the Store effects they hand out and never crosses
//! into JavaScript: `openSshTrust` shows a CA document as its fingerprint only. A page answers a
//! `sshRequest` output with `answerSsh` while the chat is open; the core refuses anything the
//! verified history, the binding and the trusted servers do not allow.
use std::{cell::RefCell, rc::Weak};

use nocterm_cloud_device::{
    SshRefusal,
    command::DeliveryUpdate,
    open::OpenChat,
    records::{StoredObject, open_ca, open_trust},
    ssh::{SshServerChoice, SshUpdate},
    transcript::{BindingState, ChatSsh},
};
use nocterm_hub_model::cloud::ssh::{
    SignedSshBinding, SshAccess, SshBindingRefusal, SshServerId, SshServerReach,
};
use nocterm_keys::agents::{CaLineForm, TrustState};
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use super::{
    CloudResult, WebCloudError,
    flow::{Running, WebChat, WebFlow},
    from_js, hex_id, js, millis,
    view::{FlowOutput, command_state, ms},
};
use crate::WebCollectionKey;

/// A server the person chose for a chat: a CA-trusted server (`serverId`, 32 hex, from
/// `openSshTrust`) and the port of its saved profile.
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct SshServerInput {
    pub server_id: String,
    pub port: u16,
}

/// How long a binding lasts (`windowMs`, seven days when absent, at most thirty) and the managed
/// agent whose seat is woken first (`wake`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct BindOptions {
    #[serde(default)]
    #[tsify(optional)]
    pub window_ms: Option<f64>,
    #[serde(default)]
    #[tsify(optional)]
    pub wake: Option<String>,
}

/// One object of the `agent_ssh_trust` collection as the page lists it. The CA shows only its
/// fingerprint; its seed stays sealed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WireSshTrust {
    #[serde(rename_all = "camelCase")]
    Ca {
        fingerprint: String,
        created_at_ms: f64,
        retired: u32,
    },
    /// `state`: `trusted`, `removalPending`, `removed` or `drifted`; `line`: `perServer`, or
    /// `shared` (the server needs a CA update before a chat's certificate opens it).
    #[serde(rename_all = "camelCase")]
    Server {
        server_id: String,
        profile_id: String,
        host: String,
        user: String,
        host_key_fingerprint: String,
        ca_fingerprint: String,
        state: String,
        line: String,
        added_at_ms: f64,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[tsify(optional)]
        last_verified_at_ms: Option<f64>,
    },
}

/// One bound server of a binding and, once the runner reported, whether it can reach it
/// (`admitted` or `unreachable`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireBoundServer {
    pub server_id: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub reach: Option<String>,
}

/// One binding of the chat. `access`: `pending`, `active` (`validBeforeMs`), `refused`
/// (`refusal`: `noSourceAddress`, `noReachableServer`, `invalid`), `revoked` or `expired`;
/// absent before the runner reported. `servers` is empty until a request carried the binding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireBinding {
    pub grant: String,
    pub epoch: f64,
    pub closed: bool,
    pub withdrawn: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub expires_at_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub access: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub valid_before_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub refusal: Option<String>,
    pub servers: Vec<WireBoundServer>,
}

/// A runner's request no device answered yet.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireSshRequest {
    pub request_id: String,
    pub grant: String,
    pub servers: Vec<String>,
    pub not_after_ms: f64,
}

/// The chat's SSH bindings, newest last, and its open certificate requests.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct WireSsh {
    pub bindings: Vec<WireBinding>,
    pub requests: Vec<WireSshRequest>,
}

fn access_of(access: SshAccess) -> (&'static str, Option<f64>, Option<&'static str>) {
    match access {
        SshAccess::Pending => ("pending", None, None),
        SshAccess::Active {
            valid_before_ms, ..
        } => ("active", Some(ms(valid_before_ms)), None),
        SshAccess::Refused(reason) => (
            "refused",
            None,
            Some(match reason {
                SshBindingRefusal::NoSourceAddress => "noSourceAddress",
                SshBindingRefusal::NoReachableServer => "noReachableServer",
                SshBindingRefusal::Invalid => "invalid",
            }),
        ),
        SshAccess::Revoked => ("revoked", None, None),
        SshAccess::Expired => ("expired", None, None),
    }
}
#[allow(
    clippy::cast_precision_loss,
    reason = "an epoch is a time in milliseconds, which fits 2^53"
)]
fn epoch(value: u64) -> f64 {
    value as f64
}
impl From<&BindingState> for WireBinding {
    fn from(state: &BindingState) -> Self {
        let update = state.update();
        let (access, valid_before_ms, refusal) = update
            .map(|update| access_of(update.access))
            .map_or((None, None, None), |(a, v, r)| (Some(a.to_owned()), v, r));
        let reach = |server: &SshServerId| {
            update
                .and_then(|u| u.servers.iter().find(|s| &s.server == server))
                .map(|status| match status.reach {
                    SshServerReach::Admitted => "admitted".to_owned(),
                    SshServerReach::Unreachable => "unreachable".to_owned(),
                })
        };
        let binding = state.binding().map(SignedSshBinding::binding);
        Self {
            grant: hex::encode(state.grant().id),
            epoch: epoch(state.grant().epoch),
            closed: state.closed(),
            withdrawn: state.withdrawn(),
            expires_at_ms: binding.map(|b| ms(b.window.expires_at_ms)),
            access,
            valid_before_ms,
            refusal: refusal.map(str::to_owned),
            servers: binding
                .map(|b| {
                    b.targets
                        .iter()
                        .map(|target| WireBoundServer {
                            server_id: hex::encode(target.server.as_bytes()),
                            host: target.host.as_str().to_owned(),
                            port: target.port,
                            user: target.user.as_str().to_owned(),
                            reach: reach(&target.server),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}
impl From<&ChatSsh> for WireSsh {
    fn from(ssh: &ChatSsh) -> Self {
        Self {
            bindings: ssh.bindings().iter().map(WireBinding::from).collect(),
            requests: ssh
                .requests()
                .iter()
                .map(|pending| {
                    let request = &pending.request;
                    WireSshRequest {
                        request_id: hex::encode(request.request),
                        grant: hex::encode(request.binding.binding().grant.id),
                        servers: request
                            .servers
                            .iter()
                            .map(|s| hex::encode(s.as_bytes()))
                            .collect(),
                        not_after_ms: ms(request.not_after_ms),
                    }
                })
                .collect(),
        }
    }
}

/// The stable code of an SSH refusal (`ssh_…`).
pub(super) fn refusal_code(refusal: SshRefusal) -> &'static str {
    match refusal {
        SshRefusal::NoCa => "ssh_no_ca",
        SshRefusal::OtherCa => "ssh_other_ca",
        SshRefusal::UntrustedServer => "ssh_untrusted_server",
        SshRefusal::HostKeyUnknown => "ssh_host_key",
        SshRefusal::Servers => "ssh_servers",
        SshRefusal::Window => "ssh_window",
        SshRefusal::UnknownRequest => "ssh_unknown_request",
        SshRefusal::Superseded => "ssh_superseded",
        SshRefusal::Revoked => "ssh_revoked",
        SshRefusal::OutsideBinding => "ssh_outside_binding",
        SshRefusal::SubjectKeyChanged => "ssh_subject_key",
        SshRefusal::NoTrustedServer => "ssh_no_trusted_server",
        SshRefusal::NotBound => "ssh_not_bound",
    }
}

/// An SSH flow's update as the page reads it; a delivery also updates the open chat.
pub(super) fn ssh_output(update: SshUpdate, chat: &Weak<RefCell<OpenChat>>) -> FlowOutput {
    let hexes =
        |servers: Vec<SshServerId>| servers.iter().map(|s| hex::encode(s.as_bytes())).collect();
    match update {
        SshUpdate::Bound {
            grant,
            needs_ca_update,
        } => FlowOutput::SshBound {
            grant: hex::encode(grant.id),
            epoch: epoch(grant.epoch),
            needs_ca_update: hexes(needs_ca_update),
        },
        SshUpdate::Certified {
            request,
            servers,
            valid_before_ms,
        } => FlowOutput::SshCertified {
            request_id: hex::encode(request),
            servers: hexes(servers),
            valid_before_ms: ms(valid_before_ms),
        },
        SshUpdate::Delivery(update) => delivered(&update, chat),
    }
}

/// A delivery's settled state, applied to the open chat it belongs to.
pub(super) fn delivered(update: &DeliveryUpdate, chat: &Weak<RefCell<OpenChat>>) -> FlowOutput {
    if let Some(chat) = chat.upgrade() {
        chat.borrow_mut().delivery(update);
    }
    FlowOutput::Delivery {
        command_id: hex::encode(update.command_id),
        state: command_state(update.state),
        cursor: update.cursor,
    }
}

fn choices(servers: Vec<SshServerInput>) -> CloudResult<Vec<SshServerChoice>> {
    servers
        .into_iter()
        .map(|input| {
            Ok(SshServerChoice {
                server: SshServerId::from_bytes(hex_id(&input.server_id, "server id")?),
                port: input.port,
            })
        })
        .collect()
}

#[wasm_bindgen]
impl WebChat {
    /// The chat's SSH bindings and open certificate requests now.
    pub fn ssh(&self) -> WireSsh {
        WireSsh::from(self.open_chat().borrow().transcript().ssh())
    }
    /// Binds the chat to `servers`, replacing its binding; outputs `sshBound`, then `delivery`.
    #[wasm_bindgen(js_name = bindServers)]
    pub fn bind_servers(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "SshServerInput[]")] servers: JsValue,
        now_ms: f64,
        #[wasm_bindgen(unchecked_optional_param_type = "BindOptions | null")] options: JsValue,
    ) -> Result<WebFlow, JsError> {
        js(from_js(servers, "servers").and_then(|servers| {
            let options = from_js::<Option<BindOptions>>(options, "bind options")?;
            self.binding(servers, options.unwrap_or_default(), now_ms)
        }))
    }
    /// Revokes the chat's binding; outputs `delivery`.
    #[wasm_bindgen(js_name = unbindServers)]
    pub fn unbind_servers(
        &mut self,
        wake: Option<String>,
        now_ms: f64,
    ) -> Result<WebFlow, JsError> {
        js(self.unbinding(wake, now_ms))
    }
    /// Answers the runner's certificate request `requestId` (from an `sshRequest` output);
    /// outputs `sshCertified`, then `delivery`.
    #[wasm_bindgen(js_name = answerSsh)]
    pub fn answer_ssh(&mut self, request_id: &str, now_ms: f64) -> Result<WebFlow, JsError> {
        js(self.answering(request_id, now_ms))
    }
}

impl WebChat {
    pub(crate) fn binding(
        &mut self,
        servers: Vec<SshServerInput>,
        options: BindOptions,
        now_ms: f64,
    ) -> CloudResult<WebFlow> {
        let window = options
            .window_ms
            .map(|window| millis(window, "binding window"))
            .transpose()?;
        let now = millis(now_ms, "time")?;
        let flow = self.open_chat().borrow_mut().bind_servers(
            &choices(servers)?,
            window,
            options.wake,
            now,
        )?;
        Ok(self.flow(Running::Bind(flow, self.handle())))
    }
    pub(crate) fn unbinding(&mut self, wake: Option<String>, now_ms: f64) -> CloudResult<WebFlow> {
        let now = millis(now_ms, "time")?;
        let deliver = self.open_chat().borrow_mut().unbind_servers(wake, now)?;
        Ok(self.flow(Running::Deliver(deliver, self.handle())))
    }
    pub(crate) fn answering(&mut self, request_id: &str, now_ms: f64) -> CloudResult<WebFlow> {
        let request = hex_id(request_id, "request id")?;
        let now = millis(now_ms, "time")?;
        let flow = self.open_chat().borrow_mut().answer_ssh(&request, now)?;
        Ok(self.flow(Running::Answer(flow, self.handle())))
    }
}

#[wasm_bindgen]
impl WebCollectionKey {
    /// Opens one object of the account's `agent_ssh_trust` collection (`objectId` `ca` or
    /// `srv-<hex>`), bound to its id and kind. A CA document shows only its fingerprint.
    #[wasm_bindgen(js_name = openSshTrust)]
    pub fn open_ssh_trust(
        &self,
        object_id: &str,
        ciphertext: &[u8],
    ) -> Result<WireSshTrust, JsError> {
        js(self.ssh_trust(object_id, ciphertext))
    }
}

impl WebCollectionKey {
    pub(crate) fn ssh_trust(
        &self,
        object_id: &str,
        ciphertext: &[u8],
    ) -> CloudResult<WireSshTrust> {
        let object = StoredObject {
            collection_id: &self.collection_id,
            object_id,
            kind: nocterm_cloud_device::records::SSH_TRUST_KIND,
            version: 1,
            deleted: false,
            ciphertext,
        };
        let Some(server) = SshServerId::from_object_id(object_id) else {
            let document = open_ca(&self.key, &object)?;
            return Ok(WireSshTrust::Ca {
                fingerprint: document.ca().fingerprint(),
                created_at_ms: ms(document.created_at_ms()),
                retired: u32::try_from(document.retired().len())
                    .map_err(|_| WebCloudError::Argument("retired"))?,
            });
        };
        let record = open_trust(&self.key, &server, &object)?;
        Ok(WireSshTrust::Server {
            server_id: hex::encode(server.as_bytes()),
            state: match record.state() {
                TrustState::Trusted => "trusted",
                TrustState::RemovalPending => "removalPending",
                TrustState::Removed => "removed",
                TrustState::Drifted => "drifted",
            }
            .to_owned(),
            line: match record.line() {
                CaLineForm::Shared => "shared",
                CaLineForm::PerServer => "perServer",
            }
            .to_owned(),
            added_at_ms: ms(record.added_at_ms),
            last_verified_at_ms: record.last_verified_at_ms.map(ms),
            profile_id: record.profile_id,
            host: record.host,
            user: record.user,
            host_key_fingerprint: record.host_key_fingerprint,
            ca_fingerprint: record.ca_fingerprint,
        })
    }
}

#[cfg(test)]
mod tests;
