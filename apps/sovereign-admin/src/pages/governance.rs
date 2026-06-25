// Copyright (C) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Governance Proposals page — audit and vote on AI-triggered mitigation proposals.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub proposal_type: String,
    pub author: String,
    pub status: String,
}

#[component]
pub fn GovernancePage() -> impl IntoView {
    // In a real implementation, this would fetch from the Governance Zome API
    let proposals = RwSignal::new(vec![GovernanceProposal {
        id: "MIP-001".into(),
        title: "Emergency Revocation: DID:mycelix:123".into(),
        description: "Athena detected suspicious Ledger activity.".into(),
        proposal_type: "Emergency".into(),
        author: "did:mycelix:athena".into(),
        status: "Active".into(),
    }]);

    view! {
        <section class="governance-page">
            <h1>"Governance Proposals"</h1>
            <table class="proposal-table">
                <thead>
                    <tr>
                        <th>"ID"</th>
                        <th>"Title"</th>
                        <th>"Type"</th>
                        <th>"Author"</th>
                        <th>"Status"</th>
                        <th>"Action"</th>
                    </tr>
                </thead>
                <tbody>
                    {move || proposals.get().into_iter().map(|p| view! {
                        <tr>
                            <td>{p.id}</td>
                            <td>{p.title}</td>
                            <td>{p.proposal_type}</td>
                            <td>{p.author}</td>
                            <td>{p.status}</td>
                            <td>
                                <button class="primary">"Vote Approve"</button>
                            </td>
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
        </section>
    }
}
