// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Sessions page — operator authentication/revocation, live ledger
// audit (public checkpoint + RBAC-gated full export), and offline
// xenia-ledger verification (paste-and-verify or a synthetic demo chain).
//
// The live ledger flow used to be gated by a long-lived HMAC secret held in
// browser localStorage (`DaemonConfig::hmac_secret`, `X-Admin-HMAC`),
// calling `GET /identity`/`GET /ledger` on the daemon -- routes that were
// never actually mounted by the real router
// (`apps/xenia-peer/src/operator_http.rs`'s `router()` only ever served
// `/auth/*` and `/operator/revoke`; the `/ledger`/`/identity` handlers
// lived only in an orphaned, never-`mod`-declared
// `apps/xenia-peer/src/api/mod.rs` stub that didn't even reference a real
// state type). That flow always 404'd against a real daemon. Replaced,
// per `docs/security/POST_DELEGATION_HARDENING_PLAN.md` item 3's "private
// contents, public commitments, portable proofs" model, by
// [`LedgerAudit`]: `GET /v1/audit/checkpoint` (public, signed, entry
// count + head hash only -- see `xenia_ledger::LedgerCheckpoint`'s doc
// comment for why this alone is safe to publish) plus, only when the
// operator has an active RBAC session, `GET /v1/audit/ledger` (requires
// `X-Operator-Token`, `OperatorAction::ReadAudit` -- every enrolled role,
// since it's Viewer-level) for the full entry export.

use ed25519_dalek::{SigningKey, VerifyingKey};
use gloo_net::http::Request;
use leptos::prelude::*;
use leptos::task::spawn_local;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xenia_ledger::{
    Chain, ConsentEventRecord, ConsentKind, LedgerCheckpoint, LedgerEntry, Verifier, VerifyError,
};
use xenia_operator_proto::OperatorAction;

use crate::agent_client::AgentConfig;
use crate::app::{OperatorIdentityCtx, OperatorIdentityState, OperatorSessionCtx};
use crate::config::DaemonConfig;
use crate::context::{auth_context, daemon_config_context, missing_context_view};
use crate::operator_session::build_revoke_request;

/// Portable JSON shape used by the export/import pair.
#[derive(Serialize, Deserialize)]
struct ExportedChain {
    public_key_hex: String,
    entries: Vec<LedgerEntry>,
}

#[component]
pub fn SessionsPage() -> impl IntoView {
    let Ok(auth) = auth_context() else {
        return missing_context_view("AuthState").into_any();
    };
    let Ok(config) = daemon_config_context() else {
        return missing_context_view("DaemonConfig").into_any();
    };
    let Some(agent_config) = use_context::<AgentConfig>() else {
        return missing_context_view("AgentConfig").into_any();
    };
    let Some(identity_state) = use_context::<OperatorIdentityCtx>() else {
        return missing_context_view("OperatorIdentity").into_any();
    };

    // Pairing: the raw pairing token is held only in this page-local,
    // never-persisted signal for exactly as long as it takes to exchange
    // it for a session (see `crate::agent_client`'s module doc comment) --
    // unlike the old `AgentConfig::agent_token` field it replaces, it never
    // touches `localStorage`.
    let (pairing_token_input, set_pairing_token_input) = signal(String::new());
    let (pairing_status, set_pairing_status) = signal(String::new());
    let do_pair = move |_| {
        let token = pairing_token_input.get_untracked();
        if token.trim().is_empty() {
            set_pairing_status.set("Enter the pairing token printed by the agent.".to_string());
            return;
        }
        let agent_url = agent_config.agent_url.get_untracked();
        set_pairing_status.set("Pairing…".to_string());
        spawn_local(async move {
            match crate::agent_client::pair(&agent_url, &token).await {
                Ok(session) => {
                    agent_config.set_session(session);
                    set_pairing_token_input.set(String::new());
                    set_pairing_status.set(String::new());
                }
                Err(e) => set_pairing_status.set(format!("Pairing failed: {e}")),
            }
        });
    };

    // Operator-revocation control — shown only to an authenticated operator whose
    // role permits it (EnrollOperator = Admin, the same gate the daemon enforces).
    let operator_session = use_context::<OperatorSessionCtx>();
    let (revoke_target, set_revoke_target) = signal(String::new());
    let (revoke_status, set_revoke_status) = signal(String::new());
    let can_revoke = move || {
        operator_session
            .map(|sig| {
                sig.with(|s| {
                    s.as_ref()
                        .map(|s| s.is_valid() && s.permits(OperatorAction::EnrollOperator))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    };
    // "Forget" the pinned sealed-channel host identity fingerprint (see
    // `crate::host_pin`'s module doc comment) — the operator's explicit path
    // for a legitimate daemon key rotation, since otherwise a rotated key
    // would permanently refuse the channel as a suspected MITM.
    let (forget_status, set_forget_status) = signal(String::new());
    let do_forget_pin = move |_| {
        let suite = if config.high_security.get_untracked() {
            "highsec"
        } else {
            "standard"
        };
        let key = crate::host_pin::storage_key(&config.sealed_ws_url(), suite);
        match crate::host_pin::forget(&key) {
            Ok(()) => set_forget_status.set(format!(
                "Forgot the pinned {suite} host fingerprint for {}. The next connection will \
                 trust-on-first-use whatever identity it sees — only do this if you intentionally \
                 rotated the daemon's key.",
                config.sealed_ws_url()
            )),
            Err(err) => set_forget_status.set(format!(
                "Failed to forget the pinned fingerprint: {err}. The old pin is still in effect."
            )),
        }
    };

    let do_revoke = move |_| {
        let target = revoke_target.get_untracked().trim().to_string();
        if target.is_empty() {
            set_revoke_status.set("Enter an operator id to revoke.".to_string());
            return;
        }
        let Some(sig) = operator_session else {
            set_revoke_status
                .set("No operator session — sign in as an operator first.".to_string());
            return;
        };
        if sig.get_untracked().is_none() {
            set_revoke_status
                .set("No operator session — sign in as an operator first.".to_string());
            return;
        }
        let endpoint = config.endpoint.get_untracked();
        let agent_url = agent_config.agent_url.get_untracked();
        let url = format!("{}/operator/revoke", endpoint.trim_end_matches('/'));
        set_revoke_status.set(format!("Revoking '{target}'…"));
        spawn_local(async move {
            // Proactively re-authenticate the operator session first if
            // it's close to its (short, 15-minute) TTL -- see
            // `crate::operator_session::ensure_fresh_operator_session`.
            let sess = match crate::operator_session::ensure_fresh_operator_session(
                &endpoint,
                &agent_url,
                &agent_config,
                sig,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    set_revoke_status.set(format!("Operator session unavailable: {e}"));
                    return;
                }
            };
            let agent_session =
                match crate::agent_client::ensure_fresh_session(&agent_url, &agent_config).await {
                    Ok(s) => s,
                    Err(e) => {
                        set_revoke_status.set(format!("Operator agent session unavailable: {e}"));
                        return;
                    }
                };
            // `build_revoke_request` no longer needs `OperatorIdentity` --
            // the local agent holds the operator's identity, verifies
            // `sess`'s token, and signs on the console's behalf, running
            // its own mandatory native confirmation for this privileged
            // action (see `crate::operator_session::build_revoke_request`).
            let body =
                match build_revoke_request(&endpoint, &agent_url, &agent_session, &sess, &target)
                    .await
                {
                    Ok(body) => body,
                    Err(e) => {
                        set_revoke_status
                            .set(format!("Failed to build signed revoke request: {e}"));
                        return;
                    }
                };
            let sent = match Request::post(&url)
                .header("content-type", "application/json")
                .body(body)
            {
                Ok(req) => req.send().await,
                Err(err) => {
                    set_revoke_status.set(format!("Request build failed: {err}"));
                    return;
                }
            };
            match sent {
                Ok(resp) if resp.ok() => set_revoke_status.set(format!("Revoked '{target}'.")),
                Ok(resp) => {
                    set_revoke_status.set(format!("Refused by daemon ({}).", resp.status()))
                }
                Err(err) => set_revoke_status.set(format!("Request failed: {err}")),
            }
        });
    };

    view! {
        <Show
            when=move || auth.is_authenticated()
            fallback=|| view! { <a href="/login" class="primary">"Sign in to view sessions"</a> }
        >
            <div class="sessions-page-container">
                <section class="config-section">
                    <h1>"Sovereign Audit Console"</h1>
                    <p class="prose">
                        "Connect to an active Xenia daemon to authenticate as an operator and "
                        "verify its signed consent ledger. All verification is performed locally "
                        "in your browser."
                    </p>
                    <div class="config-grid">
                        <div class="field">
                            <label>"Daemon Endpoint"</label>
                            <input
                                type="text"
                                data-testid="daemon-endpoint-input"
                                prop:value=move || config.endpoint.get()
                                on:input=move |ev| config.endpoint.set(event_target_value(&ev))
                            />
                        </div>
                        <div class="field">
                            <label>"Consent Port"</label>
                            <input
                                type="number"
                                data-testid="daemon-consent-port-input"
                                prop:value=move || config.consent_port.get().to_string()
                                on:input=move |ev| {
                                    if let Ok(p) = event_target_value(&ev).parse::<u16>() {
                                        config.consent_port.set(p);
                                    }
                                }
                            />
                        </div>
                        <div class="field">
                            <label class="checkbox">
                                <input
                                    type="checkbox"
                                    data-testid="use-sealed-channel-checkbox"
                                    prop:checked=move || config.use_sealed_channel.get()
                                    on:change=move |ev| {
                                        config.use_sealed_channel.set(event_target_checked(&ev))
                                    }
                                />
                                " Use sealed operator channel (PQC) — daemon must run --operator-sealed"
                            </label>
                        </div>
                        <div class="field">
                            <label>"Sealed Port"</label>
                            <input
                                type="number"
                                data-testid="daemon-sealed-port-input"
                                prop:value=move || config.sealed_port.get().to_string()
                                on:input=move |ev| {
                                    if let Ok(p) = event_target_value(&ev).parse::<u16>() {
                                        config.sealed_port.set(p);
                                    }
                                }
                            />
                        </div>
                        <div class="field">
                            <label class="checkbox">
                                <input
                                    type="checkbox"
                                    data-testid="high-security-checkbox"
                                    prop:checked=move || config.high_security.get()
                                    on:change=move |ev| {
                                        config.high_security.set(event_target_checked(&ev))
                                    }
                                />
                                " High-security suite (ML-KEM-1024 + ML-DSA-87) — daemon must run "
                                "--operator-high-security too; the two suites don't interoperate"
                            </label>
                        </div>
                        <button class="primary" data-testid="save-reconnect-button" on:click=move |_| config.save()>"Save & Reconnect"</button>
                    </div>
                </section>

                <section class="config-section">
                    <h2>"Operator Agent"</h2>
                    <p class="prose">
                        "The operator's Ed25519 + ML-DSA signing seeds live in a local "
                        <code>"xenia-operator-agent"</code>
                        " process, not this browser's storage. Run it once "
                        "(" <code>"cargo run -p xenia-operator-agent"</code> "), copy the pairing "
                        "token it prints, and paste it below to pair. Pairing exchanges the token "
                        "for a session that expires on its own -- the raw token itself is never "
                        "stored in this browser, only used once, here."
                    </p>
                    <div class="config-grid">
                        <div class="field">
                            <label>"Agent URL"</label>
                            <input
                                type="text"
                                data-testid="agent-url-input"
                                prop:value=move || agent_config.agent_url.get()
                                on:input=move |ev| {
                                    agent_config.agent_url.set(event_target_value(&ev));
                                    agent_config.save();
                                }
                            />
                        </div>
                        <div class="field">
                            <label>"Pairing Token"</label>
                            <input
                                type="password"
                                data-testid="pairing-token-input"
                                prop:value=move || pairing_token_input.get()
                                on:input=move |ev| set_pairing_token_input.set(event_target_value(&ev))
                            />
                        </div>
                        <button class="primary" data-testid="pair-button" on:click=do_pair>
                            "Pair"
                        </button>
                    </div>
                    <p class="prose" data-testid="pairing-status">{move || pairing_status.get()}</p>
                    <p class="prose" data-testid="agent-identity-status">
                        {move || match identity_state.get() {
                            OperatorIdentityState::Loading => "Connecting…".to_string(),
                            OperatorIdentityState::Ready { fingerprint_hex, .. } => {
                                format!("Connected. Fingerprint: {}…", &fingerprint_hex[..16])
                            }
                            OperatorIdentityState::Unavailable(reason) => reason,
                        }}
                    </p>
                    {move || agent_config.agent_session.get().map(|s| {
                        let secs_left = s.expires_at.saturating_sub(
                            (js_sys::Date::now() / 1000.0) as u64
                        );
                        view! {
                            <p class="prose dim">
                                {format!(
                                    "Session valid for about {} more minute(s) (auto-renews while \
                                     this console stays active).",
                                    secs_left / 60
                                )}
                            </p>
                        }
                    })}
                </section>

                <Show when=move || config.use_sealed_channel.get()>
                    <section class="config-section">
                        <h2>"Pinned Host Identity"</h2>
                        <p class="prose">
                            "The sealed channel pins the daemon's host identity fingerprint on "
                            "first connection (trust-on-first-use) and refuses any later "
                            "connection whose fingerprint changed. Only forget the pin if you "
                            "intentionally rotated the daemon's key — otherwise a changed "
                            "fingerprint means a possible impersonation attempt."
                        </p>
                        <button class="danger" data-testid="forget-pin-button" on:click=do_forget_pin>
                            "Forget Pinned Host Fingerprint"
                        </button>
                        <p class="prose" data-testid="forget-pin-status">{move || forget_status.get()}</p>
                    </section>
                </Show>

                <Show when=can_revoke>
                    <section class="config-section">
                        <h2>"Revoke Operator"</h2>
                        <p class="prose">
                            "Immediately revoke a compromised operator by id. Signed with your "
                            "Admin session and applied live on the daemon (sealed channel + consent "
                            "path) with no restart."
                        </p>
                        <div class="field">
                            <label>"Operator ID to revoke"</label>
                            <input
                                type="text"
                                data-testid="revoke-operator-input"
                                prop:value=move || revoke_target.get()
                                on:input=move |ev| set_revoke_target.set(event_target_value(&ev))
                            />
                        </div>
                        <button class="danger" data-testid="revoke-operator-button" on:click=do_revoke>"Revoke Operator"</button>
                        <p class="prose" data-testid="revoke-status">{move || revoke_status.get()}</p>
                    </section>
                </Show>

                <LedgerAudit config/>

                <div class="demo-toggle">
                    "See the ledger verification logic in action with a synthetic chain: "
                    <LedgerDemo/>
                </div>

                <ChainImporter/>
            </div>
        </Show>
    }.into_any()
}

/// Fetch the daemon's public, signed ledger checkpoint (`GET
/// /v1/audit/checkpoint`) -- no authentication needed or sent. Deserializes
/// directly into the same `xenia_ledger::LedgerCheckpoint` type the daemon
/// signs, so the browser can call `Verifier::verify_checkpoint` without a
/// separate DTO.
async fn fetch_checkpoint(endpoint: &str) -> Result<LedgerCheckpoint, String> {
    let url = format!("{}/v1/audit/checkpoint", endpoint.trim_end_matches('/'));
    Request::get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<LedgerCheckpoint>()
        .await
        .map_err(|e| e.to_string())
}

/// Response body of `GET /v1/audit/ledger` -- mirrors
/// `apps/xenia-peer/src/operator_http.rs`'s `AuditLedgerExportDto`.
#[derive(Deserialize)]
struct AuditLedgerExportDto {
    entries: Vec<LedgerEntry>,
    checkpoint: LedgerCheckpoint,
}

/// Fetch the full ledger export (`GET /v1/audit/ledger`), authenticated
/// with the operator's current session token in the `X-Operator-Token`
/// header (the exact JSON `POST /auth/verify` returned -- see
/// `OperatorSession::token_json_string`). Requires a role that permits
/// `OperatorAction::ReadAudit` (every enrolled role, since it's the
/// lowest/`Viewer` permission) -- see
/// `apps/xenia-peer/src/operator_auth.rs::authorize_ledger_read`.
async fn fetch_audit_ledger(
    endpoint: &str,
    token_json: &str,
) -> Result<AuditLedgerExportDto, String> {
    let url = format!("{}/v1/audit/ledger", endpoint.trim_end_matches('/'));
    let resp = Request::get(&url)
        .header("X-Operator-Token", token_json)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.ok() {
        return Err(format!("server returned {}", resp.status()));
    }
    resp.json::<AuditLedgerExportDto>()
        .await
        .map_err(|e| e.to_string())
}

/// Live ledger audit: always shows the daemon's public, signed checkpoint
/// (entry count + head hash, no auth needed); additionally fetches and
/// verifies the full entry export once the operator has an active RBAC
/// session (re-fetches whenever the session or daemon endpoint changes).
#[component]
fn LedgerAudit(config: DaemonConfig) -> impl IntoView {
    let session = use_context::<OperatorSessionCtx>();
    let checkpoint_status = RwSignal::new(String::from("Fetching checkpoint…"));
    let ledger_data = RwSignal::new(None::<(String, Vec<LedgerEntry>)>);
    let ledger_status = RwSignal::new(String::new());

    Effect::new(move |_| {
        let endpoint = config.endpoint.get();
        // Tracked `.get()`, not `.get_untracked()` -- signing in or out
        // should re-trigger this effect and refetch accordingly.
        let token_json = session
            .and_then(|sig| sig.get())
            .map(|s| s.token_json_string());

        spawn_local({
            let endpoint = endpoint.clone();
            async move {
                match fetch_checkpoint(&endpoint).await {
                    Ok(cp) => checkpoint_status.set(format!(
                        "{} entries, head {}…",
                        cp.entry_count,
                        hex_short(&cp.head_hash)
                    )),
                    Err(e) => checkpoint_status.set(format!("checkpoint fetch failed: {e}")),
                }
            }
        });

        match token_json {
            Some(token_json) => {
                spawn_local(async move {
                    match fetch_audit_ledger(&endpoint, &token_json).await {
                        Ok(export) => {
                            let pk_hex = hex::encode(export.checkpoint.ledger_public_key);
                            ledger_data.set(Some((pk_hex, export.entries)));
                            ledger_status.set(String::new());
                        }
                        Err(e) => {
                            ledger_data.set(None);
                            ledger_status.set(format!("ledger fetch failed: {e}"));
                        }
                    }
                });
            }
            None => {
                ledger_data.set(None);
                ledger_status.set(
                    "Sign in as an operator (above) to fetch and verify the full ledger."
                        .to_string(),
                );
            }
        }
    });

    view! {
        <section class="ledger-audit">
            <h2>"Live Ledger Audit"</h2>
            <p class="prose">"Public checkpoint: " {move || checkpoint_status.get()}</p>
            {move || match ledger_data.get() {
                Some((pk_hex, entries)) => view! {
                    <VerifiableLedger
                        title="Live Session Ledger".to_string()
                        description="Fetched from your active Xenia daemon as an authenticated \
                            operator (GET /v1/audit/ledger). Verification is performed locally."
                            .to_string()
                        initial_pk_hex=pk_hex
                        initial_entries=entries
                    />
                }.into_any(),
                None => view! { <p class="prose dim">{move || ledger_status.get()}</p> }.into_any(),
            }}
        </section>
    }
}

#[component]
fn VerifiableLedger(
    title: String,
    description: String,
    initial_pk_hex: String,
    initial_entries: Vec<LedgerEntry>,
) -> impl IntoView {
    let pk_hex = RwSignal::new(initial_pk_hex);
    let entries = RwSignal::new(initial_entries);

    let status = Memo::new(move |_| {
        let pk_bytes = decode_hex_32(&pk_hex.get())?;
        let pk = VerifyingKey::from_bytes(&pk_bytes).ok()?;
        Some(Verifier::verify_chain(&entries.get(), &pk))
    });

    let tamper = move |idx: usize| {
        entries.update(|e| {
            if let Some(entry) = e.get_mut(idx) {
                entry.event.kind = cycle_kind(entry.event.kind);
            }
        });
    };

    view! {
        <section class="ledger-viewer">
            <h2>{title}</h2>
            <p class="prose">{description}</p>

            <div class="pub-key">
                <span class="pub-key-label">"Operator public key:"</span>
                <code class="pub-key-value">{move || pk_hex.get()}</code>
            </div>

            {move || match status.get() {
                Some(s) => view! { <VerifyBadge status=s/> }.into_any(),
                None => view! { <span class="badge err">"Invalid public key"</span> }.into_any(),
            }}

            <table class="ledger-table">
                <thead>
                    <tr>
                        <th>"Seq"</th>
                        <th>"Kind"</th>
                        <th>"Scope"</th>
                        <th>"entry_hash"</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    {move || entries.get().into_iter().enumerate().map(|(idx, entry)| {
                        let hash_hex = hex_short(&entry.entry_hash);
                        let kind_str = entry.event.stable_name();
                        let kind_class_suffix = kind_str.replace('.', "-");
                        let mut kind_class = format!("kind kind-{kind_class_suffix}");
                        if entry.event.kind == ConsentKind::AthenaTriage {
                            kind_class.push_str(" ai-triage");
                        }
                        view! {
                            <tr>
                                <td class="numeric">{entry.seq}</td>
                                <td class=kind_class>
                                    {if entry.event.kind == ConsentKind::AthenaTriage { "🤖 " } else { "" }}
                                    {kind_str.to_string()}
                                </td>
                                <td>{entry.event.scope.clone()}</td>
                                <td><code class="hash">{hash_hex}</code></td>
                                <td>
                                    <button
                                        class="secondary tamper"
                                        on:click=move |_| tamper(idx)
                                    >
                                        "Tamper"
                                    </button>
                                </td>
                            </tr>
                        }
                    }).collect_view()}
                </tbody>
            </table>

            <ExportSection entries pk_hex/>
        </section>
    }
}

#[component]
fn LedgerDemo() -> impl IntoView {
    let show_demo = RwSignal::new(false);

    view! {
        <div class="demo-container">
            <button class="secondary" on:click=move |_| show_demo.update(|s| *s = !*s)>
                {move || if show_demo.get() { "Hide Synthetic Demo" } else { "Show Synthetic Demo" }}
            </button>

            <Show when=move || show_demo.get()>
                {
                    // Generate key pair + chain synchronously.
                    let sk = SigningKey::generate(&mut OsRng);
                    let pk_hex = hex_full(sk.verifying_key().to_bytes().as_slice());
                    let mut chain = Chain::new(sk);
                    let session_id = Uuid::new_v4();
                    for (kind, scope) in [
                        (ConsentKind::Request, "view screen"),
                        (ConsentKind::Approval, "view screen"),
                        (ConsentKind::Revocation, "view screen"),
                    ] {
                        let _ = chain.append(ConsentEventRecord {
                            source_id: [0xABu8; 32],
                            session_id,
                            request_id: Uuid::new_v4(),
                            kind,
                            scope: scope.to_string(),
                        });
                    }

                    view! {
                        <VerifiableLedger
                            title="Synthetic Ledger Demo".to_string()
                            description="This chain was generated in your browser for demonstration purposes.".to_string()
                            initial_pk_hex=pk_hex
                            initial_entries=chain.into_entries()
                        />
                    }
                }
            </Show>
        </div>
    }
}

#[component]
fn ExportSection(entries: RwSignal<Vec<LedgerEntry>>, pk_hex: RwSignal<String>) -> impl IntoView {
    let show = RwSignal::new(false);
    let json = Memo::new(move |_| {
        let exported = ExportedChain {
            public_key_hex: pk_hex.get(),
            entries: entries.get(),
        };
        serde_json::to_string_pretty(&exported)
            .unwrap_or_else(|e| format!("serialization error: {e}"))
    });

    view! {
        <div class="export-section">
            <button
                class="secondary"
                on:click=move |_| show.update(|s| *s = !*s)
            >
                {move || if show.get() { "Hide JSON export" } else { "Show JSON export" }}
            </button>
            <Show when=move || show.get()>
                <p class="prose dim">
                    "The JSON below is a self-contained attestation: anyone holding "
                    "it can verify the session history against the operator's "
                    "embedded public key using only the open-source "
                    <code>"xenia-ledger"</code>" crate."
                </p>
                <textarea class="export-textarea" readonly rows="14">
                    {move || json.get()}
                </textarea>
            </Show>
        </div>
    }
}

#[component]
fn ChainImporter() -> impl IntoView {
    let input = RwSignal::new(String::new());
    let result = RwSignal::new(None::<Result<ImportedSummary, String>>);

    let verify = move |_| {
        let text = input.get();
        if text.trim().is_empty() {
            result.set(Some(Err("Paste a JSON chain first.".into())));
            return;
        }
        result.set(Some(parse_and_verify(&text)));
    };

    let clear = move |_| {
        input.set(String::new());
        result.set(None);
    };

    view! {
        <section class="import-section">
            <h2>"Verify a chain from JSON"</h2>
            <p class="prose">
                "Paste an exported chain to verify it against its own declared public key."
            </p>
            <textarea
                class="import-textarea"
                placeholder=r#"{"public_key_hex":"...","entries":[...]}"#
                rows="8"
                prop:value=move || input.get()
                on:input=move |ev| input.set(event_target_value(&ev))
            ></textarea>
            <div class="button-row">
                <button class="primary" on:click=verify>"Verify"</button>
                <button class="secondary" on:click=clear>"Clear"</button>
            </div>
            <Show when=move || result.get().is_some()>
                {move || result.get().map(render_import_result)}
            </Show>
        </section>
    }
}

#[derive(Clone)]
struct ImportedSummary {
    entry_count: usize,
    public_key_hex: String,
}

fn render_import_result(r: Result<ImportedSummary, String>) -> AnyView {
    match r {
        Ok(summary) => view! {
            <div class="verify-row">
                <span class="badge ok">"✓ Verified"</span>
                <span class="badge-note">
                    {format!(
                        "{} entries; chain integrity confirmed against embedded public key {}…",
                        summary.entry_count,
                        &summary.public_key_hex[..16]
                    )}
                </span>
            </div>
        }
        .into_any(),
        Err(e) => view! {
            <div class="verify-row">
                <span class="badge err">"✗ Verify failed"</span>
                <span class="badge-note">{e}</span>
            </div>
        }
        .into_any(),
    }
}

fn parse_and_verify(text: &str) -> Result<ImportedSummary, String> {
    let exported: ExportedChain =
        serde_json::from_str(text).map_err(|e| format!("JSON parse error: {e}"))?;
    let pk_bytes = decode_hex_32(&exported.public_key_hex)
        .ok_or("public_key_hex must be exactly 64 lowercase-hex characters")?;
    let pk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("invalid public key bytes: {e}"))?;
    Verifier::verify_chain(&exported.entries, &pk).map_err(|e| format!("{e}"))?;
    Ok(ImportedSummary {
        entry_count: exported.entries.len(),
        public_key_hex: exported.public_key_hex,
    })
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = hex_digit(bytes[i * 2])?;
        let lo = hex_digit(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[component]
fn VerifyBadge(status: Result<(), VerifyError>) -> impl IntoView {
    view! {
        <div class="verify-row">
            {match status {
                Ok(()) => view! {
                    <span class="badge ok">"✓ Chain verified"</span>
                    <span class="badge-note">
                        "every entry's hash links correctly and every signature "
                        "verifies under the operator's public key"
                    </span>
                }.into_any(),
                Err(e) => view! {
                    <span class="badge err">"✗ Verify failed"</span>
                    <span class="badge-note">{format!("{e}")}</span>
                }.into_any(),
            }}
        </div>
    }
}

fn cycle_kind(k: ConsentKind) -> ConsentKind {
    match k {
        ConsentKind::Request => ConsentKind::Denial,
        ConsentKind::Approval => ConsentKind::Denial,
        ConsentKind::Denial => ConsentKind::Approval,
        ConsentKind::Revocation => ConsentKind::Approval,
        ConsentKind::Violation => ConsentKind::Request,
        ConsentKind::AthenaTriage | ConsentKind::AuthorizationBinding => ConsentKind::Request,
    }
}

fn hex_short(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16 + 1);
    for b in bytes.iter().take(8) {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s.push('…');
    s
}

fn hex_full(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
