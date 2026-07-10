// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Sessions page — live xenia-ledger verification.

use ed25519_dalek::{SigningKey, VerifyingKey};
use gloo_net::http::Request;
use leptos::prelude::*;
use leptos::task::spawn_local;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, LedgerEntry, Verifier, VerifyError};

use crate::config::DaemonConfig;
use crate::context::{auth_context, daemon_config_context, missing_context_view};

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

    view! {
        <Show
            when=move || auth.is_authenticated()
            fallback=|| view! { <a href="/login" class="primary">"Sign in to view sessions"</a> }
        >
            <div class="sessions-page-container">
                <section class="config-section">
                    <h1>"Sovereign Audit Console"</h1>
                    <p class="prose">
                        "Connect to an active Xenia daemon to fetch its verifiable consent ledger. "
                        "All verification is performed locally in your browser."
                    </p>
                    <div class="config-grid">
                        <div class="field">
                            <label>"Daemon Endpoint"</label>
                            <input
                                type="text"
                                prop:value=move || config.endpoint.get()
                                on:input=move |ev| config.endpoint.set(event_target_value(&ev))
                            />
                        </div>
                        <div class="field">
                            <label>"Admin Secret (HMAC Hex)"</label>
                            <input
                                type="password"
                                prop:value=move || config.hmac_secret.get()
                                on:input=move |ev| config.hmac_secret.set(event_target_value(&ev))
                            />
                        </div>
                        <div class="field">
                            <label>"Consent Port"</label>
                            <input
                                type="number"
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
                                prop:value=move || config.sealed_port.get().to_string()
                                on:input=move |ev| {
                                    if let Ok(p) = event_target_value(&ev).parse::<u16>() {
                                        config.sealed_port.set(p);
                                    }
                                }
                            />
                        </div>
                        <button class="primary" on:click=move |_| config.save()>"Save & Reconnect"</button>
                    </div>
                </section>

                <RealLedger config/>

                <hr class="separator"/>

                <div class="demo-toggle">
                    "Want to see the verification logic in action without a daemon? "
                    <LedgerDemo/>
                </div>

                <ChainImporter/>
            </div>
        </Show>
    }.into_any()
}

#[component]
fn RealLedger(config: DaemonConfig) -> impl IntoView {
    let data = RwSignal::new(None::<(String, Vec<LedgerEntry>)>);
    let error = RwSignal::new(None::<String>);
    let loading = RwSignal::new(false);

    let fetch = move || {
        let endpoint = config.endpoint.get();
        let secret = config.hmac_secret.get();
        if secret.is_empty() {
            return;
        }
        loading.set(true);
        error.set(None);
        spawn_local(async move {
            match fetch_identity(&endpoint).await {
                Ok(pk) => match fetch_ledger(&endpoint, &secret).await {
                    Ok(entries) => {
                        data.set(Some((pk, entries)));
                    }
                    Err(e) => error.set(Some(format!("Ledger fetch failed: {e}"))),
                },
                Err(e) => error.set(Some(format!("Identity fetch failed: {e}"))),
            }
            loading.set(false);
        });
    };

    // Refetch when config changes.
    Effect::new(move |_| {
        fetch();
    });

    view! {
        <div class="real-ledger">
            <Show when=move || loading.get()>
                <p>"Fetching live ledger..."</p>
            </Show>
            <Show when=move || error.get().is_some()>
                <p class="error">{move || error.get().unwrap_or_else(|| "Unknown session error".to_string())}</p>
            </Show>
            {move || data.get().map(|(pk_hex, entries)| {
                view! {
                    <VerifiableLedger
                        title="Live Session Ledger".to_string()
                        description="This data was fetched from your active Xenia daemon. Verification is live.".to_string()
                        initial_pk_hex=pk_hex
                        initial_entries=entries
                    />
                }
            })}
            <Show when=move || data.get().is_none() && !loading.get() && error.get().is_none()>
                <div class="verify-row">
                    <span class="badge err">"Disconnected"</span>
                    <span class="badge-note">"Enter your daemon secret to fetch the live ledger."</span>
                </div>
            </Show>
        </div>
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

async fn fetch_identity(endpoint: &str) -> Result<String, String> {
    let url = format!("{}/identity", endpoint);
    Request::get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())
}

async fn fetch_ledger(endpoint: &str, secret: &str) -> Result<Vec<LedgerEntry>, String> {
    let url = format!("{}/ledger", endpoint);
    let resp = Request::get(&url)
        .header("X-Admin-HMAC", secret)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.ok() {
        return Err(format!("Server returned {}", resp.status()));
    }

    resp.json::<Vec<LedgerEntry>>()
        .await
        .map_err(|e| e.to_string())
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
        ConsentKind::AthenaTriage => ConsentKind::Request,
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
