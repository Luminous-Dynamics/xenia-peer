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
use leptos::html;
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
    serde_json::from_str::<serde_json::Value>(prompt)
        .ok()
        .and_then(|v| v.get("scope").and_then(|s| s.as_str()).map(String::from))
        .unwrap_or_else(|| prompt.to_string())
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
    let (is_dismissed, set_is_dismissed) = signal(false);
    let dialog_ref = NodeRef::<html::Dialog>::new();
    let effect_dialog_ref = dialog_ref.clone();

    // Native showModal() supplies top-layer rendering, modal focus handling,
    // and inertness for the rest of the document. Keeping the dialog mounted
    // lets the close event distinguish an Escape dismissal from a decision.
    Effect::new(move |_| {
        let should_open = is_open.get();
        if let Some(dialog) = effect_dialog_ref.get() {
            if should_open && !dialog.open() {
                if let Err(err) = dialog.show_modal() {
                    leptos::logging::error!("failed to open consent dialog: {err:?}");
                }
            } else if !should_open && dialog.open() {
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
                    set_consent_req.set(Some(text));
                    set_is_dismissed.set(false);
                    set_is_open.set(true);
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
        let prompt = consent_req.get_untracked();
        let session_id = prompt.as_deref().and_then(parse_session_id);
        let sealed = config.use_sealed_channel.get_untracked();

        let endpoint = config.endpoint.get_untracked();
        let agent_url = agent_config.agent_url.get_untracked();
        let sealed_url = config.sealed_ws_url();
        let high_security = config.high_security.get_untracked();
        let consent_url = config.consent_ws_url();

        // Snapshot *before* the async refresh attempt below, to distinguish
        // "never signed in as an operator" (the legitimate legacy-plaintext
        // path, for a daemon run without --require-operator-auth) from "was
        // signed in, but the session has now expired/failed to refresh" --
        // the two used to be conflated (both produced `sess = None` from
        // the refresh call below), which silently downgraded an
        // authenticated operator's decision to an anonymous, unsigned one
        // instead of erroring. Found in the 2026-07-18 audit of this PR's
        // own rotation change.
        let had_session = session.is_some_and(|sig| sig.get_untracked().is_some());

        // The payload now needs an `await` (asking the agent to sign) even
        // in the non-sealed case, so both dispatch paths live inside one
        // `spawn_local` after it resolves rather than each starting their
        // own.
        spawn_local(async move {
            // Proactively re-authenticate the operator session first if
            // it's close to its (short, 15-minute) TTL -- mirrors the
            // agent-session leg's `ensure_fresh_session` below, applied to
            // the daemon-token leg. Otherwise a console left open past the
            // TTL silently loses its privileged buttons (`can()` gates on
            // `is_valid()`) with no way back short of a manual sign-in.
            let sess = match session {
                Some(sig) => crate::operator_session::ensure_fresh_operator_session(
                    &endpoint,
                    &agent_url,
                    &agent_config,
                    sig,
                )
                .await
                .ok(),
                None => None,
            };
            if had_session && sess.is_none() {
                // Was authenticated a moment ago; the session has since
                // expired and couldn't be renewed. Abort rather than
                // falling through to the anonymous/unsigned legacy path
                // below, which would silently strip this decision of its
                // operator attribution and signature.
                leptos::logging::error!(
                    "operator session expired and could not be renewed -- sign in again to submit this decision"
                );
                return;
            }

            // Both a signed consent payload and the sealed channel's own
            // handshake need a live agent session -- fetch (and
            // transparently renew, if it's close to expiry) it once up
            // front rather than separately for each.
            let needs_agent = (sess.is_some() && session_id.is_some()) || sealed;
            let agent_session = if needs_agent {
                match crate::agent_client::ensure_fresh_session(&agent_url, &agent_config).await {
                    Ok(s) => Some(s),
                    Err(e) => {
                        leptos::logging::error!("operator agent session unavailable: {e}");
                        return;
                    }
                }
            } else {
                None
            };

            let scope = prompt.as_deref().map(display_scope).unwrap_or_default();
            let payload = match (&sess, session_id, &agent_session) {
                (Some(s), Some(sid), Some(agent_session)) => {
                    match build_consent_request(
                        &endpoint,
                        &agent_url,
                        agent_session,
                        s,
                        action,
                        &sid,
                        &scope,
                    )
                    .await
                    {
                        Ok(p) => p,
                        Err(e) => {
                            leptos::logging::error!("failed to build signed consent request: {e}");
                            return;
                        }
                    }
                }
                _ => action.as_str().to_string(),
            };
            if sealed {
                let Some(agent_session) = agent_session else {
                    leptos::logging::error!("sealed consent decision needs an agent session");
                    return;
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
                if let Err(err) = result {
                    leptos::logging::error!("sealed consent decision failed: {err}");
                }
            } else if let Ok(ws) = WebSocket::open(&consent_url) {
                let (mut writer, _) = ws.split();
                let _ = writer.send(Message::Text(payload)).await;
            }
        });
        set_is_dismissed.set(false);
        set_is_open.set(false);
    };

    let dismiss_dialog_ref = dialog_ref.clone();
    let dismiss_dialog = move |_| {
        if let Some(dialog) = dismiss_dialog_ref.get() {
            dialog.close();
        }
    };

    view! {
        <dialog
            node_ref=dialog_ref
            class="consent-dialog"
            data-testid="consent-modal"
            aria-labelledby="consent-title"
            aria-describedby="consent-scope"
            on:close=move |_| {
                if is_open.get_untracked() {
                    // Escape / explicit dismiss closes the surface only. It
                    // does not send an approval, denial, or revocation.
                    set_is_open.set(false);
                    set_is_dismissed.set(true);
                }
            }
        >
            <section class="consent-dialog-content">
                <h2 id="consent-title">"New Session Request"</h2>
                <p class="consent-scope-label">"Requested access"</p>
                <p id="consent-scope" class="consent-scope">
                    {move || consent_req.get().map(|p| display_scope(&p)).unwrap_or_default()}
                </p>
                <div class="button-row">
                    <button
                        class="secondary consent-dismiss"
                        type="button"
                        autofocus
                        on:click=dismiss_dialog
                    >
                        "Dismiss"
                    </button>
                    <Show when=move || can(ConsentAction::Deny)>
                        <button class="secondary" type="button" data-testid="consent-deny-button" on:click=move |_| decide(ConsentAction::Deny)>
                            "Deny"
                        </button>
                    </Show>
                    <Show when=move || can(ConsentAction::Approve)>
                        <button class="primary" type="button" data-testid="consent-approve-button" on:click=move |_| decide(ConsentAction::Approve)>
                            "Approve"
                        </button>
                    </Show>
                    <Show when=move || can(ConsentAction::Revoke)>
                        <button class="danger" type="button" data-testid="consent-revoke-button" on:click=move |_| decide(ConsentAction::Revoke)>
                            "Revoke"
                        </button>
                    </Show>
                </div>
            </section>
        </dialog>
        <Show when=move || is_dismissed.get() && consent_req.get().is_some()>
            <aside class="consent-dismissed" role="status" aria-live="polite">
                <span>"Request hidden. No consent decision was sent."</span>
                <Show
                    when=move || consent_req.get().as_deref().and_then(parse_session_id).is_some()
                    fallback=|| view! {
                        <span>"This legacy prompt has no session identifier. Wait for a new request rather than reusing a potentially stale prompt."</span>
                    }
                >
                    <button
                        class="secondary"
                        type="button"
                        on:click=move |_| {
                            set_is_dismissed.set(false);
                            set_is_open.set(true);
                        }
                    >
                        "Review request"
                    </button>
                </Show>
            </aside>
        </Show>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::{display_scope, parse_session_id};

    #[test]
    fn display_scope_extracts_only_the_declared_scope_field() {
        let prompt =
            r#"{"session_id":"00112233445566778899aabbccddeeff","scope":"View-only desktop"}"#;
        assert_eq!(display_scope(prompt), "View-only desktop");
    }

    #[test]
    fn display_scope_preserves_legacy_plaintext_prompt() {
        assert_eq!(
            display_scope("Legacy view-only request"),
            "Legacy view-only request"
        );
    }

    #[test]
    fn session_id_requires_exactly_sixteen_decoded_bytes() {
        let valid = r#"{"session_id":"00112233445566778899aabbccddeeff"}"#;
        assert_eq!(
            parse_session_id(valid),
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
        assert!(parse_session_id(r#"{"session_id":"abcd"}"#).is_none());
    }
}
