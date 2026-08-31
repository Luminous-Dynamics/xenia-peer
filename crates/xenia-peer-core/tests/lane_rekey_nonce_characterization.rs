// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Regression for xenia-peer #192.
//!
//! The characterization parent proved that viewer rekey Ack and the host's
//! first subsequent new-key control frame could reuse the same AEAD nonce. This
//! successor requires distinct nonce domains while preserving interoperability.

use xenia_handshake::{RekeyEpochKeys, RekeyReason};
use xenia_peer_core::{
    LaneSession,
    frame::{LANE_ENVELOPE_MAGIC, RawRekey},
};

const SOURCE_ID: [u8; 8] = *b"xnlane01";
const SESSION_EPOCH: u8 = 0x41;
const LANE_HEADER_LEN: usize = 5; // 4-byte XLN1 magic + 1-byte lane tag.
const NONCE_LEN: usize = 12;

fn rekey_keys(control: [u8; 32]) -> RekeyEpochKeys {
    RekeyEpochKeys {
        aead: [0x10; 32],
        control,
        video: [0x30; 32],
        audio: [0x40; 32],
        telemetry: [0x50; 32],
    }
}

fn inner_nonce(envelope: &[u8]) -> &[u8] {
    assert!(
        envelope.len() >= LANE_HEADER_LEN + NONCE_LEN,
        "lane envelope must contain an xenia-wire nonce"
    );
    assert_eq!(&envelope[..LANE_ENVELOPE_MAGIC.len()], &LANE_ENVELOPE_MAGIC);
    &envelope[LANE_HEADER_LEN..LANE_HEADER_LEN + NONCE_LEN]
}

#[test]
fn viewer_rekey_ack_has_distinct_nonce_domain_and_still_interoperates() {
    let mut host = LaneSession::with_fixture(SOURCE_ID, SESSION_EPOCH);
    let mut viewer = LaneSession::with_fixture(SOURCE_ID, SESSION_EPOCH);
    let keys = rekey_keys([0x22; 32]);
    host.install_rekey_keys(&keys);
    viewer.install_rekey_keys(&keys);

    // Viewer Ack is its first seal under the newly-installed control key.
    let ack_hash = [0xA1; 32];
    let ack = RawRekey::Ack {
        key_epoch: 1,
        epoch_hash: ack_hash,
    }
    .into_frame(0, 0)
    .expect("build ack frame");
    let viewer_ack = viewer
        .seal_control_frame(&ack)
        .expect("seal viewer rekey ack");

    // Stand in for the host's first subsequent control frame under the same
    // new key. It also begins at sequence 0 on the regular control sender.
    let proposal_hash = [0xB2; 32];
    let proposal = RawRekey::Proposal {
        key_epoch: 2,
        base_transcript_hash: [0xB1; 32],
        previous_epoch_hash: ack_hash,
        reason: RekeyReason::Manual,
        epoch_hash: proposal_hash,
    }
    .into_frame(1, 1)
    .expect("build proposal frame");
    let host_control = host
        .seal_control_frame(&proposal)
        .expect("seal host control frame");

    let ack_nonce = inner_nonce(&viewer_ack);
    let host_nonce = inner_nonce(&host_control);

    assert_ne!(
        ack_nonce, host_nonce,
        "opposite sealing roles must not reuse an AEAD nonce under the same control key"
    );
    assert_ne!(
        &ack_nonce[..6],
        &host_nonce[..6],
        "rekey Ack must use the separated sender source domain"
    );
    assert_eq!(ack_nonce[6], host_nonce[6], "both remain FRAME payloads");
    assert_eq!(&ack_nonce[8..12], &[0, 0, 0, 0], "viewer Ack is seq 0");
    assert_eq!(&host_nonce[8..12], &[0, 0, 0, 0], "host control is seq 0");

    // Directional source separation must not change the authenticated body or
    // require a second receive-side key. The ordinary control receiver opens
    // both domains because replay state keys from the source carried in the
    // authenticated nonce.
    let opened_ack = host.open_frame(&viewer_ack).expect("host opens Ack");
    assert_eq!(
        RawRekey::from_frame(&opened_ack).expect("decode Ack"),
        RawRekey::Ack {
            key_epoch: 1,
            epoch_hash: ack_hash,
        }
    );

    let opened_proposal = viewer
        .open_frame(&host_control)
        .expect("viewer opens host control frame");
    assert_eq!(
        RawRekey::from_frame(&opened_proposal).expect("decode proposal"),
        RawRekey::Proposal {
            key_epoch: 2,
            base_transcript_hash: [0xB1; 32],
            previous_epoch_hash: ack_hash,
            reason: RekeyReason::Manual,
            epoch_hash: proposal_hash,
        }
    );
}
