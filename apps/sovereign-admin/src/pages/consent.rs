use leptos::task::spawn_local;
// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use futures_util::{SinkExt, StreamExt};
use gloo_net::websocket::{Message, futures::WebSocket};
use leptos::prelude::*;

#[component]
pub fn ConsentModal() -> impl IntoView {
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

    view! {
        <Show when=move || is_open.get()>
            <div class="modal-overlay">
                <div class="modal">
                    <h2>"New Session Request"</h2>
                    <p>{move || consent_req.get().unwrap_or_default()}</p>
                    <div class="button-row">
                        <button class="primary" on:click=move |_| {
                            spawn_local(async move {
                                if let Ok(ws) = WebSocket::open("ws://127.0.0.1:8082") {
                                    let (mut writer, _) = ws.split();
                                    let _ = writer.send(Message::Text("Approve".into())).await;
                                }
                            });
                            set_is_open.set(false);
                        }>"Approve"</button>
                        <button class="secondary" on:click=move |_| {
                            spawn_local(async move {
                                if let Ok(ws) = WebSocket::open("ws://127.0.0.1:8082") {
                                    let (mut writer, _) = ws.split();
                                    let _ = writer.send(Message::Text("Deny".into())).await;
                                }
                            });
                            set_is_open.set(false);
                        }>"Deny"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
