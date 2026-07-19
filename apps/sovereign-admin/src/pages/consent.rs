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
use gloo_net::websocket::{futures::WebSocket, Message};
use leptos::prelude::*;
use leptos::task::spawn_local;

use xenia_operator_proto::{AttestedConsentOfferV2, ConsentAction, ConsentScopeV1};

use crate::agent_client::AgentConfig;
use crate::app::OperatorSessionCtx;
use crate::context::{daemon_config_context, missing_context_view};
use crate::operator_session::build_consent_request;

/// Parse the canonical typed scope from a modern consent prompt.
fn parse_scope_v1(prompt: &str) -> Option<ConsentScopeV1> {
    let v: serde_json::Value = serde_json::from_str(prompt).ok()?;
    serde_json::from_value(v.get("scope_v1")?.clone()).ok()
}

fn parse_attested_offer(prompt: &str) -> Option<AttestedConsentOfferV2> {
    let v: serde_json::Value = serde_json::from_str(prompt).ok()?;
    serde_json::from_value(v.get("attested_offer")?.clone()).ok()
}

/// Human-readable scope derived from the canonical object when available;
/// retain the legacy `scope` string only for unauthenticated old daemons.
fn display_scope(prompt: &str) -> String {
    if let Some(attested) = parse_attested_offer(prompt) {
        return attested.offer.scope.summary();
    }
    if let Some(scope) = parse_scope_v1(prompt) {
        return scope.summary();
    }
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
        let attested_offer = prompt.as_deref().and_then(parse_attested_offer);
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
            let needs_agent = (sess.is_some() && attested_offer.is_some()) || sealed;
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

            let payload = match (&sess, attested_offer.as_ref(), &agent_session) {
                (Some(s), Some(attested_offer), Some(agent_session)) => {
                    match build_consent_request(
                        &endpoint,
                        &agent_url,
                        agent_session,
                        s,
                        action,
                        attested_offer,
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
        set_is_open.set(false);
    };

    view! {
        <Show when=move || is_open.get()>
            <div class="modal-overlay" data-testid="consent-modal">
                <div class="modal">
                    <h2>"New Session Request"</h2>
                    <p>{move || consent_req.get().map(|p| display_scope(&p)).unwrap_or_default()}</p>
                    <div class="button-row">
                        <Show when=move || can(ConsentAction::Approve)>
                            <button class="primary" data-testid="consent-approve-button" on:click=move |_| decide(ConsentAction::Approve)>
                                "Approve"
                            </button>
                        </Show>
                        <Show when=move || can(ConsentAction::Deny)>
                            <button class="secondary" data-testid="consent-deny-button" on:click=move |_| decide(ConsentAction::Deny)>
                                "Deny"
                            </button>
                        </Show>
                        <Show when=move || can(ConsentAction::Revoke)>
                            <button class="danger" data-testid="consent-revoke-button" on:click=move |_| decide(ConsentAction::Revoke)>
                                "Revoke"
                            </button>
                        </Show>
                    </div>
                </div>
            </div>
        </Show>
    }
    .into_any()
}
