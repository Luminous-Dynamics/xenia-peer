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
//! The raw SIF semantic carrier is intentionally crate-private. External callers reach
//! protected Offer/Chunk APIs only through the authenticated pending→negotiated gate in
//! [`sif_negotiation`].

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod sif_negotiation;
pub mod sif_receive_runtime;
mod sif_semantic_wire;

// The raw semantic channel remains unreachable externally, but the negotiated public
// error taxonomy may transparently retain this lower-layer error as a source.
pub use sif_semantic_wire::SifSemanticWireError;
