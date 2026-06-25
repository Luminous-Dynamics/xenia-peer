// Copyright (C) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! AI Monitor page — real-time Athena thought stream.

use crate::config::DaemonConfig;
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wasm_bindgen::JsCast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thought {
    pub ticket_id: Uuid,
    pub message: String,
    pub sim_score: Option<f32>,
}

#[component]
pub fn MonitorPage() -> impl IntoView {
    let config = use_context::<DaemonConfig>().expect("DaemonConfig provided at App root");
    let thoughts = RwSignal::new(vec![]);

    // Connect to Athena thought stream (websocket)
    // Note: This logic assumes Athena is reachable at endpoint:8430/v1/thoughts
    Effect::new(move |_| {
        let endpoint = config.endpoint.get();
        // Extract host from http://host:port
        let binding = endpoint.replace("http://", "");
        let host = binding.split(':').next().unwrap_or("127.0.0.1");
        let ws_url = format!("ws://{}:8430/v1/thoughts", host);

        let ws = web_sys::WebSocket::new(&ws_url).unwrap();
        let thoughts_signal = thoughts;

        let onmessage_callback =
            wasm_bindgen::closure::Closure::wrap(Box::new(move |e: web_sys::MessageEvent| {
                if let Some(txt) = e.data().as_string() {
                    if let Ok(thought) = serde_json::from_str::<Thought>(&txt) {
                        thoughts_signal.update(|t| t.insert(0, thought));
                    }
                }
            })
                as Box<dyn FnMut(web_sys::MessageEvent)>);

        ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
        onmessage_callback.forget();
    });

    view! {
        <section class="monitor-page">
            <h1>"AI Thought Stream"</h1>
            <p class="prose">
                "Real-time visibility into Athena L1's cognitive loop. This stream "
                "surfaces HDC semantic similarity vectors and causal inferences."
            </p>

            <div class="thought-list">
                {move || thoughts.get().into_iter().map(|t| view! {
                    <div class="thought-item">
                        <span class="ticket-id">"Ticket: " {t.ticket_id.to_string()[..8].to_string()}</span>
                        <span class="message">{t.message}</span>
                        {t.sim_score.map(|s| view! {
                            <span class="badge score">{format!("Resonance: {:.2}", s)}</span>
                        })}
                    </div>
                }).collect_view()}
            </div>
        </section>
    }
}
