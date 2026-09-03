// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Application-layer library surfaces shared by the `xenia-peer` daemon.
//!
//! The headless daemon remains the executable boundary, while narrowly scoped
//! typestate adapters can live here when they must join crates with deliberately
//! different ownership/licensing boundaries. In particular, SIF protected custody
//! combines ledger semantics with peer-core filesystem mechanics without making the
//! permissively licensed peer core depend on the AGPL evidence layer.
//!
//! Both lower protected-transfer layers are intentionally crate-private. External
//! callers reach protected Offer/Chunk traffic only through [`sif_transfer_flow`],
//! which enforces authenticated exact-profile negotiation plus phase ordering.
//! [`sif_custody_wire`] is a separate receipt-only verification surface and carries no
//! authority to emit protected file content.

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod sif_custody_wire;
mod sif_negotiation;
pub mod sif_receive_runtime;
mod sif_semantic_wire;
pub mod sif_transfer_flow;

// Lower-layer errors remain reachable because the public phase error taxonomy retains
// them as typed sources, while the bypass-capable channel implementations stay private.
pub use sif_negotiation::SifNegotiationError;
pub use sif_semantic_wire::SifSemanticWireError;
