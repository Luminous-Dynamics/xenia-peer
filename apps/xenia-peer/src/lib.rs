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
//! The public protected-content authority is [`sif_accountable_transfer`].
//! [`sif_profile_bound_source`] adds the stronger outbound source-owning path: exact
//! profile-bound file authority is joined to the actual negotiated SIF profile, an
//! owned [`xenia_peer_core::TransferSource`], and the crash-safe write-ahead send journal
//! before any source Chunk becomes carrier-visible. [`sif_staged_source`] strengthens
//! the strict file path further by copying source bytes into a private Xenia-owned
//! snapshot before authorization; on Unix the snapshot pathname is removed after its
//! owned streaming handle is opened. Capability negotiation, semantic transfer, phase
//! state and custody transport remain private implementation layers so application
//! callers cannot bypass Accept ordering or receiver-signed custody closure.

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod sif_accountable_transfer;
mod sif_custody_wire;
mod sif_negotiation;
pub mod sif_profile_bound_source;
pub mod sif_receive_runtime;
mod sif_semantic_wire;
pub mod sif_staged_source;
mod sif_transfer_flow;

// Lower-layer errors remain reachable because the public accountable error taxonomy
// retains them as typed sources, while the authority-bearing implementations stay private.
pub use sif_custody_wire::SifCustodySemanticError;
pub use sif_negotiation::SifNegotiationError;
pub use sif_semantic_wire::SifSemanticWireError;
pub use sif_transfer_flow::SifTransferFlowError;
