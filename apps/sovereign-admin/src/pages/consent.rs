// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The consent modal: the operator's live approve/deny/revoke surface.
//!
//! When an operator session exists (see [`crate::operator_session`]) the
//! buttons are **role-gated** — only decisions the daemon-scoped role permits
//! are shown — and each decision is sent as a signed, token-bearing
//! [`build_consent_request`] payload the daemon authorizes and attributes in
//! its ledger. Without a session it falls back to the legacy plaintext
//! `Approve`/`Deny` a daemon started *without* `--require-operator-auth`
//! accepts. `Revoke` (mid-session stop) is only offered to an authenticated,
//! permitted operator.

use futures_util::{SinkExt, StreamExt};
use gloo_net::websocket::{Message, futures::WebSocket};
use leptos::prelude::*;
use leptos::task::spawn_local;

use xenia_operator_proto::ConsentAction;

use crate::app::OperatorSessionCtx;
use crate::operator_session::{OperatorIdentity, build_consent_request};

/// Extract the `session_id` (hex, 16 bytes) a daemon may include in the consent
/// prompt. Required to bind an *authenticated* decision to the exact session;
/// when absent, only the legacy plaintext path is available.
fn parse_session_id(prompt: &str) -> Option<[u8; 16]> {
    let v: serde_json::Value = serde_json::from_str(prompt).ok()?;
    let hex = v.get("session_id")?.as_str()?;
    hex::decode(hex).ok()?.try_into().ok()
}

#[component]
pub fn ConsentModal() -> impl IntoView {
    let session = use_context::<OperatorSessionCtx>();

    let (consent_req, set_consent_req) = signal(None::<String>);
    let (is_open, set_is_open) = signal(false);

    if let Ok(ws) = WebSocket::open("ws://127.0.0.1:8081/ws") {
        let (_writer, mut reader) = ws.split();
        spawn_local(async move {
            while let Some(msg) = reader.next().await {
                if let Ok(Message::Text(text)) = msg {
                    set_consent_req.set(Some(text));
                    set_is_open.set(true);
                }
            }
        });
    }

    // Whether the current session's role permits `action` — or, with no
    // session, whether the legacy plaintext path allows it (Approve/Deny only).
    let can = move |action: ConsentAction| match session {
        Some(sig) => sig.with(|s| {
            s.as_ref()
                .map(|s| s.is_valid() && s.permits(action.required_permission()))
                .unwrap_or(false)
        }),
        None => matches!(action, ConsentAction::Approve | ConsentAction::Deny),
    };

    // Send a decision: signed + token-bearing when we have a session *and* the
    // prompt carried a session_id to bind to; otherwise the legacy plaintext
    // action a non-`--require-operator-auth` daemon accepts.
    let decide = move |action: ConsentAction| {
        let prompt = consent_req.get_untracked();
        let sess = session.and_then(|sig| sig.get_untracked());
        let session_id = prompt.as_deref().and_then(parse_session_id);
        let payload = match (sess, session_id) {
            (Some(s), Some(sid)) => {
                let id = OperatorIdentity::load_or_generate();
                build_consent_request(&id, &s, action, &sid)
            }
            _ => action.as_str().to_string(),
        };
        spawn_local(async move {
            if let Ok(ws) = WebSocket::open("ws://127.0.0.1:8082") {
                let (mut writer, _) = ws.split();
                let _ = writer.send(Message::Text(payload)).await;
            }
        });
        set_is_open.set(false);
    };

    view! {
        <Show when=move || is_open.get()>
            <div class="modal-overlay">
                <div class="modal">
                    <h2>"New Session Request"</h2>
                    <p>{move || consent_req.get().unwrap_or_default()}</p>
                    <div class="button-row">
                        <Show when=move || can(ConsentAction::Approve)>
                            <button class="primary" on:click=move |_| decide(ConsentAction::Approve)>
                                "Approve"
                            </button>
                        </Show>
                        <Show when=move || can(ConsentAction::Deny)>
                            <button class="secondary" on:click=move |_| decide(ConsentAction::Deny)>
                                "Deny"
                            </button>
                        </Show>
                        <Show when=move || can(ConsentAction::Revoke)>
                            <button class="danger" on:click=move |_| decide(ConsentAction::Revoke)>
                                "Revoke"
                            </button>
                        </Show>
                    </div>
                </div>
            </div>
        </Show>
    }
}
