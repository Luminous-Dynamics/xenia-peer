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
//! The public high-assurance protected-content authority is
//! [`sif_authorized_transfer`]. The historical accountable phase engine remains
//! crate-private beneath that facade so external callers cannot manufacture a protected
//! Offer independently of durable profile-bound release authority. Capability
//! negotiation, semantic transfer, phase state and custody transport also remain private
//! implementation layers.

#![warn(missing_docs)]
#![deny(unsafe_code)]

mod sif_accountable_transfer;
pub mod sif_authorized_transfer;
mod sif_custody_wire;
mod sif_negotiation;
pub mod sif_receive_runtime;
mod sif_semantic_wire;
mod sif_transfer_flow;

// Lower-layer errors remain reachable because public high-assurance error taxonomies
// retain them as typed sources, while authority-bearing implementations stay private.
pub use sif_custody_wire::SifCustodySemanticError;
pub use sif_negotiation::SifNegotiationError;
pub use sif_semantic_wire::SifSemanticWireError;
pub use sif_transfer_flow::SifTransferFlowError;
