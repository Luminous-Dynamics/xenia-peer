// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Sessions page — live xenia-ledger verification demo.
//
// On mount, generates an Ed25519 key pair in the browser and builds a
// synthetic consent chain covering one session's worth of events
// (Request → Approval → Request (broader scope) → Approval →
// Revocation). Every byte is computed client-side by ed25519-dalek +
// blake3; no server round-trip. The full chain is verified with
// `xenia_ledger::Verifier` and the result renders as a pass/fail
// badge above the entry table.
//
// The "Tamper" button on each row flips that entry's consent kind
// after the fact, triggering a re-verification. Because the entry's
// hash and signature covered the original event, verification fails
// — this is the NIS2 Art. 21(f) "admin cannot rewrite the audit log"
// property made visible in 30 seconds at a browser tab.

use ed25519_dalek::{SigningKey, VerifyingKey};
use leptos::prelude::*;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xenia_ledger::{Chain, ConsentEventRecord, ConsentKind, LedgerEntry, VerifyError, Verifier};

use crate::auth::AuthState;

/// Portable JSON shape used by the export/import pair. `public_key_hex`
/// is the 64-char lowercase-hex encoding of the 32-byte Ed25519 verifying
/// key; `entries` serializes via the crate-level serde derives on
/// `LedgerEntry`.
#[derive(Serialize, Deserialize)]
struct ExportedChain {
    public_key_hex: String,
    entries: Vec<LedgerEntry>,
}

#[component]
pub fn SessionsPage() -> impl IntoView {
    let auth = use_context::<AuthState>().expect("AuthState provided at App root");
    view! {
        <Show
            when=move || auth.is_authenticated()
            fallback=|| view! { <a href="/login" class="primary">"Sign in to view sessions"</a> }
        >
            <LedgerDemo/>
            <ChainImporter/>
        </Show>
    }
}

#[component]
fn LedgerDemo() -> impl IntoView {
    // Generate key pair + chain synchronously at mount.
    let sk = SigningKey::generate(&mut OsRng);
    let pk: VerifyingKey = sk.verifying_key();
    let mut chain = Chain::new(sk);

    let session_id = Uuid::new_v4();
    for (kind, scope) in [
        (ConsentKind::Request, "view screen"),
        (ConsentKind::Approval, "view screen"),
        (ConsentKind::Request, "view screen, inject input"),
        (ConsentKind::Approval, "view screen, inject input"),
        (ConsentKind::Revocation, "view screen, inject input"),
    ] {
        let _ = chain.append(ConsentEventRecord {
            source_id: [0xABu8; 32],
            session_id,
            request_id: Uuid::new_v4(),
            kind,
            scope: scope.to_string(),
        });
    }
    let initial_entries = chain.into_entries();
    let initial_status = Verifier::verify_chain(&initial_entries, &pk);

    let entries = RwSignal::new(initial_entries);
    let status = RwSignal::new(initial_status);

    let tamper = move |idx: usize| {
        entries.update(|e| {
            if let Some(entry) = e.get_mut(idx) {
                entry.event.kind = cycle_kind(entry.event.kind);
            }
        });
        let latest = entries.get_untracked();
        status.set(Verifier::verify_chain(&latest, &pk));
    };

    let pub_key_hex = hex_full(pk.to_bytes().as_slice());

    view! {
        <section class="sessions-page">
            <h1>"Session ledger (live demo)"</h1>
            <p class="prose">
                "This chain was generated right now, in your browser, by "
                <code>"ed25519-dalek"</code> " + " <code>"blake3"</code>
                " via the "<code>"xenia-ledger"</code>" crate. No server round-trip."
                " Press Tamper on any entry to mutate its consent kind — because "
                "the entry's hash and signature were computed over the original event, "
                "verification will fail. This is the NIS2 Art. 21(f) "
                "\"admin cannot rewrite the audit log\" property made visible."
            </p>

            <div class="pub-key">
                <span class="pub-key-label">"Operator public key:"</span>
                <code class="pub-key-value">{pub_key_hex}</code>
            </div>

            <VerifyBadge status/>

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
                        let kind_str = format!("{:?}", entry.event.kind);
                        let kind_class = format!("kind kind-{}", kind_str.to_lowercase());
                        view! {
                            <tr>
                                <td class="numeric">{entry.seq}</td>
                                <td class=kind_class>{kind_str}</td>
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

            <p class="footnote">
                "Try this: click Tamper on seq 1 (Approval). Verification flips to "
                <code>"EntryHashMismatch { seq: 1 }"</code>
                ". Open the browser console to see zero network activity — "
                "every byte was computed here."
            </p>

            <ExportSection entries pub_key_hex=hex_full(pk.to_bytes().as_slice())/>
        </section>
    }
}

#[component]
fn ExportSection(
    entries: RwSignal<Vec<LedgerEntry>>,
    pub_key_hex: String,
) -> impl IntoView {
    let show = RwSignal::new(false);
    let pk_hex_for_memo = pub_key_hex.clone();
    let json = Memo::new(move |_| {
        let exported = ExportedChain {
            public_key_hex: pk_hex_for_memo.clone(),
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
                    <code>"xenia-ledger"</code>
                    " crate — no access to our servers required. Try modifying a "
                    "byte and pasting the result into the Verify section below."
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
                "Paste an exported chain (or a tampered one) to verify it against "
                "its own declared public key. Same code path a third-party auditor "
                "would use."
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
                {move || render_import_result(result.get().unwrap())}
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
        }.into_any(),
        Err(e) => view! {
            <div class="verify-row">
                <span class="badge err">"✗ Verify failed"</span>
                <span class="badge-note">{e}</span>
            </div>
        }.into_any(),
    }
}

fn parse_and_verify(text: &str) -> Result<ImportedSummary, String> {
    let exported: ExportedChain = serde_json::from_str(text)
        .map_err(|e| format!("JSON parse error: {e}"))?;
    let pk_bytes = decode_hex_32(&exported.public_key_hex)
        .ok_or("public_key_hex must be exactly 64 lowercase-hex characters")?;
    let pk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("invalid public key bytes: {e}"))?;
    Verifier::verify_chain(&exported.entries, &pk)
        .map_err(|e| format!("{e}"))?;
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
fn VerifyBadge(status: RwSignal<Result<(), VerifyError>>) -> impl IntoView {
    view! {
        <div class="verify-row">
            {move || match status.get() {
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
