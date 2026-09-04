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
//! [`sif_source_owned_transfer`]. Outbound transfer consumes exact durable
//! session/profile/file authority already bound to one move-only opened source; callers
//! never supply an Offer or content bytes. The older authorized/accountable phase
//! engines, capability negotiation, semantic carrier and custody transport remain
//! private implementation layers so application callers cannot bypass durable Offer
//! provenance, source ownership, Accept ordering or receiver-signed custody closure.

#![warn(missing_docs)]
#![deny(unsafe_code)]

mod sif_accountable_transfer;
mod sif_authorized_transfer;
mod sif_custody_wire;
mod sif_negotiation;
pub mod sif_receive_runtime;
mod sif_semantic_wire;
pub mod sif_source_authority;
pub mod sif_source_owned_transfer;
mod sif_transfer_flow;

// Lower-layer errors/evidence remain reachable because the public source-owned taxonomy
// retains them as typed sources. None of these re-exports can create transfer authority.
pub use sif_accountable_transfer::AccountableSifError;
pub use sif_authorized_transfer::AuthorizedSifError;
pub use sif_custody_wire::SifCustodySemanticError;
pub use sif_negotiation::SifNegotiationError;
pub use sif_semantic_wire::SifSemanticWireError;
pub use sif_transfer_flow::{
    SifTransferFlowError, SifTransferTransportUncertain, SifTransportUncertainPhase,
};
