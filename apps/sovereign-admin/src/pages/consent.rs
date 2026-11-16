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

use crate::agent_client::AgentConfig;
use crate::app::OperatorSessionCtx;
use crate::context::{daemon_config_context, missing_context_view};
use crate::operator_session::build_consent_request;

/// Extract the `session_id` (hex, 16 bytes) a daemon may include in the consent
/// prompt. Required to bind an *authenticated* decision to the exact session;
/// when absent, only the legacy plaintext path is available.
fn parse_session_id(prompt: &str) -> Option<[u8; 16]> {
    let v: serde_json::Value = serde_json::from_str(prompt).ok()?;
    let hex = v.get("session_id")?.as_str()?;
    hex::decode(hex).ok()?.try_into().ok()
}

/// The human-readable scope to show: the daemon now sends the prompt as JSON
/// `{session_id, scope}`, so surface `scope`; fall back to the raw string for a
/// legacy plaintext prompt.
fn display_scope(prompt: &str) -> String {
    let scope = serde_json::from_str::<serde_json::Value>(prompt)
        .ok()
        .and_then(|v| v.get("scope").and_then(|s| s.as_str()).map(String::from))
        .unwrap_or_else(|| prompt.to_string());

    if scope.trim().is_empty() {
        "Scope was not supplied in the request.".to_string()
    } else {
        scope
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_display_uses_only_supplied_scope_and_preserves_legacy_text() {
        assert_eq!(
            display_scope(r#"{"session_id":"00112233445566778899aabbccddeeff","scope":"View-only session"}"#),
            "View-only session"
        );
        assert_eq!(
            display_scope("Legacy plaintext scope"),
            "Legacy plaintext scope"
        );
    }

    #[test]
    fn scope_display_marks_an_empty_scope_as_unknown() {
        assert_eq!(
            display_scope(r#"{"session_id":"00112233445566778899aabbccddeeff","scope":"  "}"#),
            "Scope was not supplied in the request."
        );
    }

    #[test]
    fn session_id_requires_exactly_sixteen_decoded_bytes() {
        assert_eq!(
            parse_session_id(r#"{"session_id":"00112233445566778899aabbccddeeff"}"#),
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_session_id(r#"{"session_id":"001122"}"#),
            None
        );
    }
}

#[component]
pub fn ConsentModal() -> impl IntoView {
    let session = use_context::<OperatorSessionCtx>();
    let Ok(config) = daemon_config_context() else {
        return missing_context_view("DaemonConfig").into_any();
    };
    let Some(agent_config) = use_context::<AgentConfig>() else {
        return missing_context_view("AgentConfig").into_any();
    };

    let (consent_req, set_consent_req) = signal(None::<String>);
    let (is_open, set_is_open) = signal(false);
    let (is_deciding, set_is_deciding) = signal(false);
    let (decision_error, set_decision_error) = signal(None::<String>);
    let (decision_notice, set_decision_notice) = signal(None::<String>);
    let (prompt_conflict, set_prompt_conflict) = signal(false);
    let dialog_ref = NodeRef::<leptos::html::Dialog>::new();

    // Use the browser's native modal dialog implementation. show_modal()
    // provides the top layer, focus placement/trapping, and document inertness;
    // close() restores the element that was focused before the dialog opened.
    Effect::new(move |_| {
        let should_be_open = is_open.get();
        if let Some(dialog) = dialog_ref.get() {
            if should_be_open && !dialog.open() {
                if let Err(error) = dialog.show_modal() {
                    leptos::logging::error!("could not open native consent dialog: {error:?}");
                    set_decision_error.set(Some(
                        "The consent dialog could not be opened. Reload the console before making a decision."
                            .to_string(),
                    ));
                }
            } else if !should_be_open && dialog.open() {
                dialog.close();
            }
        }
    });

    // Listen for consent prompts the daemon broadcasts on its admin `/ws`
    // (derived from DaemonConfig, not hardcoded, so the console targets the
    // configured daemon). Wrapped in an `Effect` tracking `config.endpoint`
    // so changing the daemon endpoint + "Save & Reconnect" actually
    // reopens this connection against the new daemon -- it used to open
    // once at component mount and never again, so the operator could
    // reconnect the *rest* of the console to a different daemon but this
    // listener stayed silently pointed at whatever endpoint was configured
    // on first page load. Found live running the real browser-driven
    // vertical slice (item 6): a real consent prompt from a freshly
    // reconnected daemon never reached the console at all. The stale
    // connection to the old (usually already-dead, on a restart) daemon
    // is left to close on its own rather than explicitly cancelled here --
    // this component never previously did that either, and a dead
    // server-side connection ends the reader loop naturally.
    Effect::new(move |_| {
        let ws_url = config.admin_ws_url();
        let Ok(ws) = WebSocket::open(&ws_url) else {
            leptos::logging::error!("failed to open consent-prompt websocket at {ws_url}");
            return;
        };
        let (_writer, mut reader) = ws.split();
        spawn_local(async move {
            while let Some(msg) = reader.next().await {
                if let Ok(Message::Text(text)) = msg {
                    match consent_req.get_untracked() {
                        None => {
                            set_decision_error.set(None);
                            set_decision_notice.set(None);
                            set_prompt_conflict.set(false);
                            set_consent_req.set(Some(text));
                            set_is_open.set(true);
                        }
                        Some(existing) if existing == text => {
                            // The same prompt can be broadcast more than once.
                            // Ignore an exact duplicate; it must not create a
                            // second decision opportunity.
                        }
                        Some(_) => {
                            // Never replace a visible prompt with a later
                            // session. Fail closed until the browser is
                            // reconnected and the daemon state is reconciled.
                            set_prompt_conflict.set(true);
                            set_decision_error.set(Some(
                                "A different session request arrived while this request is pending. The displayed request has been preserved and decisions are disabled. Reload/reconnect the console to reconcile the daemon state."
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
        });
    });

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
    // action a non-`--require-operator-auth` daemon accepts. When the operator's
    // daemon runs `--operator-sealed`, the *same* payload is sealed over the PQC
    // handshake channel instead of sent plaintext (the daemon decodes it
    // identically after opening the envelope) -- driven by the local agent
    // (`crate::sealed_consent::drive_agent_handshake`) rather than raw seeds
    // held here, so this component no longer needs the operator identity at
    // all.
    let decide = move |action: ConsentAction| {
        if is_deciding.get_untracked() || prompt_conflict.get_untracked() {
            return;
        }
        let Some(prompt) = consent_req.get_untracked() else {
            return;
        };

        let session_id = parse_session_id(&prompt);
        let sealed = config.use_sealed_channel.get_untracked();
        let endpoint = config.endpoint.get_untracked();
        let agent_url = agent_config.agent_url.get_untracked();
        let sealed_url = config.sealed_ws_url();
        let high_security = config.high_security.get_untracked();
        let consent_url = config.consent_ws_url();

        // Preserve the boundary between legacy anonymous mode and a session
        // that was authenticated but has since expired. An expired session
        // must never downgrade into a plaintext decision.
        let had_session = session.is_some_and(|sig| sig.get_untracked().is_some());

        set_is_deciding.set(true);
        set_decision_error.set(None);
        set_decision_notice.set(None);

        spawn_local(async move {
            let outcome: Result<(), String> = async {
                let sess = match session {
                    Some(sig) => {
                        crate::operator_session::ensure_fresh_operator_session(
                            &endpoint,
                            &agent_url,
                            &agent_config,
                            sig,
                        )
                        .await
                        .ok()
                    }
                    None => None,
                };
                if had_session && sess.is_none() {
                    return Err(
                        "The operator session expired and could not be renewed. Sign in again; no decision was sent."
                            .to_string(),
                    );
                }

                let needs_agent = (sess.is_some() && session_id.is_some()) || sealed;
                let agent_session = if needs_agent {
                    match crate::agent_client::ensure_fresh_session(&agent_url, &agent_config).await {
                        Ok(session) => Some(session),
                        Err(error) => {
                            return Err(format!(
                                "The operator agent session is unavailable. No decision was sent: {error}"
                            ));
                        }
                    }
                } else {
                    None
                };

                let scope = display_scope(&prompt);
                let payload = match (&sess, session_id, &agent_session) {
                    (Some(operator), Some(session_id), Some(agent_session)) => {
                        match build_consent_request(
                            &endpoint,
                            &agent_url,
                            agent_session,
                            operator,
                            action,
                            &session_id,
                            &scope,
                        )
                        .await
                        {
                            Ok(payload) => payload,
                            Err(error) => {
                                return Err(format!(
                                    "The signed decision could not be built. No decision was sent: {error}"
                                ));
                            }
                        }
                    }
                    _ => action.as_str().to_string(),
                };

                if sealed {
                    let Some(agent_session) = agent_session else {
                        return Err(
                            "The sealed consent channel requires a live operator-agent session. No decision was sent."
                                .to_string(),
                        );
                    };
                    let result = if high_security {
                        crate::sealed_consent::send_sealed_consent_highsec(
                            &sealed_url,
                            &agent_url,
                            &agent_session,
                            payload.as_bytes(),
                        )
                        .await
                    } else {
                        crate::sealed_consent::send_sealed_consent(
                            &sealed_url,
                            &agent_url,
                            &agent_session,
                            payload.as_bytes(),
                        )
                        .await
                    };
                    result.map_err(|error| {
                        format!("The sealed decision could not be transmitted: {error}")
                    })?;
                } else {
                    let ws = WebSocket::open(&consent_url)
                        .map_err(|error| format!("Could not open the consent channel: {error}"))?;
                    let (mut writer, _) = ws.split();
                    writer
                        .send(Message::Text(payload))
                        .await
                        .map_err(|error| format!("Could not transmit the consent decision: {error}"))?;
                }

                Ok(())
            }
            .await;

            match outcome {
                Ok(()) => {
                    let notice = if prompt_conflict.get_untracked() {
                        "Decision transmitted for the displayed request, but another request arrived before reconciliation. Reload/reconnect the console to retrieve the remaining daemon state."
                    } else {
                        "Decision transmitted. The console has not received an independent host-side outcome confirmation."
                    };
                    set_is_deciding.set(false);
                    set_is_open.set(false);
                    set_consent_req.set(None);
                    set_decision_notice.set(Some(notice.to_string()));
                }
                Err(error) => {
                    leptos::logging::error!("consent decision failed: {error}");
                    set_is_deciding.set(false);
                    set_decision_error.set(Some(error));
                }
            }
        });
    };

    view! {
        <Show when=move || decision_notice.get().is_some()>
            <p class="consent-decision-notice" role="status" aria-live="polite">
                {move || decision_notice.get().unwrap_or_default()}
            </p>
        </Show>

        <dialog
            node_ref=dialog_ref
            class="modal consent-dialog"
            data-testid="consent-modal"
            aria-labelledby="consent-dialog-title"
            aria-describedby="consent-dialog-description"
            on:cancel=move |event: web_sys::Event| {
                // A request remains live at the daemon until Approve or Deny
                // is transmitted. Escape must not silently dismiss it.
                event.prevent_default();
                set_decision_error.set(Some(
                    "This request is still pending. Use Deny to decline it, or Approve to grant it."
                        .to_string(),
                ));
            }
        >
            <h2 id="consent-dialog-title">"New Session Request"</h2>
            <p id="consent-dialog-description">
                {move || consent_req.get().map(|prompt| display_scope(&prompt)).unwrap_or_default()}
            </p>
            <p class="consent-dialog-hint">
                "Escape does not submit a decision. A request remains pending until you choose Approve or Deny."
            </p>

            <section class="consent-revocation-note" aria-label="Revocation information">
                <h3>"Revocation is separate from approval"</h3>
                <p>
                    "Revocation applies only after a session is active. It stops future authorized effects; it cannot undo actions already completed."
                </p>
            </section>

            <Show when=move || decision_error.get().is_some()>
                <p class="consent-decision-error" role="alert" aria-live="assertive">
                    {move || decision_error.get().unwrap_or_default()}
                </p>
            </Show>

            <div class="button-row consent-button-row">
                <Show when=move || can(ConsentAction::Approve)>
                    <button
                        type="button"
                        class="consent-decision"
                        data-testid="consent-approve-button"
                        prop:disabled=move || is_deciding.get() || prompt_conflict.get() || prompt_conflict.get()
                        on:click=move |_| decide(ConsentAction::Approve)
                    >
                        {move || if is_deciding.get() { "Submitting…" } else { "Approve" }}
                    </button>
                </Show>
                <Show when=move || can(ConsentAction::Deny)>
                    <button
                        type="button"
                        class="consent-decision"
                        data-testid="consent-deny-button"
                        autofocus
                        prop:disabled=move || is_deciding.get() || prompt_conflict.get()
                        on:click=move |_| decide(ConsentAction::Deny)
                    >
                        "Deny"
                    </button>
                </Show>
            </div>
        </dialog>
    }

    .into_any()
}
