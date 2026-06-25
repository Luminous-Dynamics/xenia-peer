// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Devices page. Scaffold: shows a fixed mock list of enrolled devices
// so the admin console has something to render before device-enrollment
// lands (year-2 per MYCELIX_SOVEREIGN_PLAN.md §7).
//
// TODO (year-2):
// - Wire to Holon / symthaea-phone-embodiment device-enrollment flow.
// - Pull live posture state (last-seen, OS, pending updates).
// - Add per-device action menu (revoke access, enroll, etc.).

use leptos::prelude::*;

use crate::context::{auth_context, missing_context_view};

struct MockDevice {
    id: &'static str,
    name: &'static str,
    platform: &'static str,
    last_seen: &'static str,
    posture: &'static str,
}

const MOCK_DEVICES: &[MockDevice] = &[
    MockDevice {
        id: "dev-0001",
        name: "ops-laptop-01",
        platform: "NixOS 26.05",
        last_seen: "just now",
        posture: "healthy",
    },
    MockDevice {
        id: "dev-0002",
        name: "jumphost-euw1",
        platform: "Debian 12",
        last_seen: "2 min ago",
        posture: "healthy",
    },
    MockDevice {
        id: "dev-0003",
        name: "pixel-8-pro",
        platform: "Android 15",
        last_seen: "18 min ago",
        posture: "degraded",
    },
];

#[component]
pub fn DevicesPage() -> impl IntoView {
    let Ok(auth) = auth_context() else {
        return missing_context_view("AuthState").into_any();
    };

    view! {
        <Show
            when=move || auth.is_authenticated()
            fallback=|| view! { <SignInPrompt/> }
        >
            <DevicesTable/>
        </Show>
    }
    .into_any()
}

#[component]
fn DevicesTable() -> impl IntoView {
    view! {
        <section class="devices-page">
            <h1>"Enrolled devices"</h1>
            <p class="prose">
                "Scaffold list. Real enrollment (Holon → DID-bound posture) is "
                "a year-2 track — see "
                <code>"MYCELIX_SOVEREIGN_PLAN.md §7"</code> "."
            </p>
            <table class="devices-table">
                <thead>
                    <tr>
                        <th>"ID"</th>
                        <th>"Name"</th>
                        <th>"Platform"</th>
                        <th>"Last seen"</th>
                        <th>"Posture"</th>
                    </tr>
                </thead>
                <tbody>
                    {MOCK_DEVICES.iter().map(|d| view! {
                        <tr>
                            <td><code>{d.id}</code></td>
                            <td>{d.name}</td>
                            <td>{d.platform}</td>
                            <td class="dim">{d.last_seen}</td>
                            <td class={format!("posture posture-{}", d.posture)}>{d.posture}</td>
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
        </section>
    }
}

#[component]
fn SignInPrompt() -> impl IntoView {
    view! {
        <section class="signin-prompt">
            <h1>"Sign in required"</h1>
            <p>"Xenia admin console needs a DID to show devices."</p>
            <a href="/login" class="primary">"Go to sign-in"</a>
        </section>
    }
}
