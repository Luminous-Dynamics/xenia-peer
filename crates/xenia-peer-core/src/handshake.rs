// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Handshake implementation for Xenia.
//!
//! Performs a PQC-hybrid (ML-KEM-768 + Ed25519) handshake over a
//! [`Transport`] to establish a shared session key.

use crate::transport::Transport;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use tracing::info;
use xenia_handshake::{HandshakeManager, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN};

/// Handshake messages exchanged between host and viewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Host starts by sending its identity and KEM public keys + a fresh nonce.
    HostHello {
        /// Ed25519 verifying key.
        ed25519_pk: [u8; 32],
        /// ML-KEM-768 encapsulation key.
        #[serde(with = "BigArray")]
        kem_pk: [u8; ML_KEM_768_PK_LEN],
        /// Classical 32-byte nonce for KDF binding.
        nonce: [u8; 32],
    },
    /// Viewer responds with its identity, KEM ciphertext, and its own nonce.
    /// Signed over (HostHello || ViewerResponse-payload).
    ViewerResponse {
        /// Ed25519 verifying key.
        ed25519_pk: [u8; 32],
        /// ML-KEM-768 ciphertext.
        #[serde(with = "BigArray")]
        kem_ct: [u8; ML_KEM_768_CT_LEN],
        /// Viewer's fresh 32-byte nonce.
        nonce: [u8; 32],
        /// Ed25519 signature from viewer over the transcript.
        #[serde(with = "BigArray")]
        signature: [u8; 64],
    },
    /// Host finalizes the handshake by verifying viewer's response and
    /// signing the final transcript.
    HostFinalize {
        /// Ed25519 signature from host over the full transcript.
        #[serde(with = "BigArray")]
        signature: [u8; 64],
    },
}

/// Perform a host-side handshake.
pub async fn perform_host_handshake<T: Transport>(
    transport: &mut T,
    mgr: &mut HandshakeManager,
    peer_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    info!("Starting host-side handshake");
    let host_nonce = rand::random::<[u8; 32]>();

    let hello = HandshakeMessage::HostHello {
        ed25519_pk: mgr.identity_public_key_bytes(),
        kem_pk: *mgr.kem_public_key_bytes(),
        nonce: host_nonce,
    };

    let hello_bytes = bincode::serialize(&hello)?;
    transport.send_envelope(&hello_bytes).await?;

    let response_bytes = transport.recv_envelope().await?;
    let HandshakeMessage::ViewerResponse {
        ed25519_pk,
        kem_ct,
        nonce: viewer_nonce,
        signature,
    } = bincode::deserialize(&response_bytes)?
    else {
        return Err("Expected ViewerResponse".into());
    };

    // Verify viewer identity.
    let viewer_verifying_key = HandshakeManager::parse_peer_public_key(&ed25519_pk)?;

    // Transcript for viewer's signature: HostHello + ViewerResponse (sans signature).
    let mut transcript = hello_bytes.clone();
    transcript.extend_from_slice(&ed25519_pk);
    transcript.extend_from_slice(&kem_ct);
    transcript.extend_from_slice(&viewer_nonce);

    let sig = ed25519_dalek::Signature::from_bytes(&signature);
    HandshakeManager::verify(&viewer_verifying_key, &transcript, &sig)?;

    // Combined nonce for KDF.
    let mut combined_nonce = [0u8; 64];
    combined_nonce[..32].copy_from_slice(&host_nonce);
    combined_nonce[32..].copy_from_slice(&viewer_nonce);

    let session_key = mgr.decapsulate_and_derive(peer_id, &kem_ct, &combined_nonce)?;

    // Finalize: sign the transcript (including viewer's signature).
    transcript.extend_from_slice(&signature);
    let host_sig = mgr.sign(&transcript).to_bytes();

    let finalize = HandshakeMessage::HostFinalize {
        signature: host_sig,
    };
    transport
        .send_envelope(&bincode::serialize(&finalize)?)
        .await?;

    info!("Host-side handshake complete");
    Ok(session_key)
}

/// Perform a viewer-side handshake.
pub async fn perform_viewer_handshake<T: Transport>(
    transport: &mut T,
    mgr: &mut HandshakeManager,
    peer_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    info!("Starting viewer-side handshake");

    let hello_bytes = transport.recv_envelope().await?;
    let hello = bincode::deserialize::<HandshakeMessage>(&hello_bytes)?;
    let HandshakeMessage::HostHello {
        ed25519_pk,
        kem_pk,
        nonce: host_nonce,
    } = hello
    else {
        return Err("Expected HostHello".into());
    };

    let host_verifying_key = HandshakeManager::parse_peer_public_key(&ed25519_pk)?;
    mgr.receive_kem_public_key(peer_id, &kem_pk)?;

    let viewer_nonce = rand::random::<[u8; 32]>();

    // Combined nonce for KDF.
    let mut combined_nonce = [0u8; 64];
    combined_nonce[..32].copy_from_slice(&host_nonce);
    combined_nonce[32..].copy_from_slice(&viewer_nonce);

    let kem_ct = mgr.encapsulate_for_peer(peer_id, &combined_nonce)?;

    // Sign the transcript: HostHello + ViewerResponse (sans signature).
    let mut transcript = hello_bytes.clone();
    transcript.extend_from_slice(&mgr.identity_public_key_bytes());
    transcript.extend_from_slice(&kem_ct);
    transcript.extend_from_slice(&viewer_nonce);

    let viewer_sig = mgr.sign(&transcript).to_bytes();

    let response = HandshakeMessage::ViewerResponse {
        ed25519_pk: mgr.identity_public_key_bytes(),
        kem_ct: kem_ct.try_into().map_err(|_| "Invalid KEM CT length")?,
        nonce: viewer_nonce,
        signature: viewer_sig,
    };

    let response_bytes = bincode::serialize(&response)?;
    transport.send_envelope(&response_bytes).await?;

    // Wait for Finalize.
    let finalize_bytes = transport.recv_envelope().await?;
    let HandshakeMessage::HostFinalize {
        signature: host_sig_bytes,
    } = bincode::deserialize(&finalize_bytes)?
    else {
        return Err("Expected HostFinalize".into());
    };

    // Verify host signature over (HostHello + ViewerResponse).
    transcript.extend_from_slice(&viewer_sig);
    let host_sig = ed25519_dalek::Signature::from_bytes(&host_sig_bytes);
    HandshakeManager::verify(&host_verifying_key, &transcript, &host_sig)?;

    let session_key = *mgr
        .session_key(peer_id)
        .ok_or("Session key missing after handshake")?
        .bytes();

    info!("Viewer-side handshake complete");
    Ok(session_key)
}
