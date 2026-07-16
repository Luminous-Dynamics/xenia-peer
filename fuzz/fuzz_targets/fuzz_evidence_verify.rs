// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Fuzz target: JSON-decode a `DaemonIdentityCertificate` from arbitrary
//! bytes, then -- on success -- run the same verification steps
//! `xenia-operator-agent`'s `daemon_evidence::verify_daemon_certificate`
//! performs (hex-decode each field, verify both signatures over
//! `daemon_delegation_transcript`, compute the fingerprint). This is the
//! real pipeline a MITM or compromised daemon's `GET /auth/daemon-identity`
//! response bytes reach, before any of it is trusted.
//!
//! **Not a direct call** to `daemon_evidence::verify_daemon_certificate`
//! itself: that function lives in `apps/xenia-operator-agent`, a
//! binary-only crate with no library target, so it isn't reachable from an
//! external fuzz crate. This target reimplements its logic using the same
//! public library primitives (`xenia_handshake`, `xenia_operator_proto`)
//! that function calls -- a real, disclosed gap, not silently worked
//! around; extracting `daemon_evidence` (and `secure_file`, `host_trust`,
//! etc.) into a library crate would make the wrapper itself directly
//! fuzzable, and is a reasonable future refactor, not done here.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_handshake::{HandshakeManager, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};
use xenia_operator_proto::{DaemonIdentityCertificate, daemon_delegation_transcript};

fn decode_fixed_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

fuzz_target!(|data: &[u8]| {
    let Ok(cert) = serde_json::from_slice::<DaemonIdentityCertificate>(data) else {
        return;
    };

    let Some(host_ed25519_pubkey) = decode_fixed_hex::<32>(&cert.host_ed25519_pubkey) else {
        return;
    };
    let Some(host_ml_dsa_pubkey) = decode_fixed_hex::<ML_DSA_65_PK_LEN>(&cert.host_ml_dsa_pubkey)
    else {
        return;
    };
    let Some(http_auth_ed25519_pubkey) = decode_fixed_hex::<32>(&cert.http_auth_ed25519_pubkey)
    else {
        return;
    };
    let Some(http_auth_ml_dsa_pubkey) =
        decode_fixed_hex::<ML_DSA_65_PK_LEN>(&cert.http_auth_ml_dsa_pubkey)
    else {
        return;
    };
    let Some(host_ed_signature) = decode_fixed_hex::<64>(&cert.host_ed_signature) else {
        return;
    };
    let Some(host_ml_dsa_signature) =
        decode_fixed_hex::<ML_DSA_65_SIG_LEN>(&cert.host_ml_dsa_signature)
    else {
        return;
    };

    let Ok(host_ed_pk) = HandshakeManager::parse_peer_public_key(&host_ed25519_pubkey) else {
        return;
    };
    let transcript =
        daemon_delegation_transcript(&http_auth_ed25519_pubkey, &http_auth_ml_dsa_pubkey);

    let _ = HandshakeManager::verify(
        &host_ed_pk,
        &transcript,
        &ed25519_dalek::Signature::from_bytes(&host_ed_signature),
    );
    let _ =
        HandshakeManager::verify_ml_dsa(&host_ml_dsa_pubkey, &transcript, &host_ml_dsa_signature);
    let _ = xenia_handshake::host_identity_fingerprint(&host_ed25519_pubkey, &host_ml_dsa_pubkey);
});
