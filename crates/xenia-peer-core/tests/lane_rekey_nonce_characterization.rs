// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Security characterization for xenia-peer #192.
//!
//! This test intentionally captures the *current unsafe behavior* so the
//! remediation can prove it changed the right invariant. It must be replaced
//! by an inequality regression when #192 is fixed.

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
        rekey: [0x60; 32],
        context: [0x70; 32],
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
fn viewer_rekey_ack_reuses_host_first_new_key_control_nonce_today() {
    // Host and viewer currently receive the same configured source-id/epoch
    // metadata. They also install the same next-epoch control key.
    let mut host = LaneSession::with_fixture(SOURCE_ID, SESSION_EPOCH);
    let mut viewer = LaneSession::with_fixture(SOURCE_ID, SESSION_EPOCH);
    let keys = rekey_keys([0x22; 32]);
    host.install_rekey_keys(&keys);
    viewer.install_rekey_keys(&keys);

    // The viewer Ack is its first seal under the newly-installed control key,
    // therefore FRAME sequence 0.
    let ack = RawRekey::Ack {
        key_epoch: 1,
        epoch_hash: [0xA1; 32],
    }
    .into_frame(0, 0)
    .expect("build ack frame");
    let viewer_ack = viewer
        .seal_control_frame(&ack)
        .expect("seal viewer rekey ack");

    // Stand in for the host's first subsequent control frame under the same
    // new key. A later rekey Proposal is sufficient to demonstrate the nonce
    // construction; forward clipboard/capability-style control frames share
    // the same FRAME payload type and sender counter on this lane.
    let proposal = RawRekey::Proposal {
        key_epoch: 2,
        base_transcript_hash: [0xB1; 32],
        previous_epoch_hash: [0xA1; 32],
        reason: RekeyReason::Manual,
        epoch_hash: [0xB2; 32],
    }
    .into_frame(1, 1)
    .expect("build proposal frame");
    let host_control = host
        .seal_control_frame(&proposal)
        .expect("seal host control frame");

    let ack_nonce = inner_nonce(&viewer_ack);
    let host_nonce = inner_nonce(&host_control);

    // Characterization, NOT desired behavior: both independent senders reset
    // to sequence 0 on the same new control key and currently share the same
    // source-id/epoch/payload-type domain.
    assert_eq!(
        ack_nonce, host_nonce,
        "current implementation should reproduce the nonce collision tracked in #192"
    );

    // Make the collision shape explicit for reviewers: payload type and seq are
    // equal as part of the complete identical 12-byte nonce.
    assert_eq!(ack_nonce[6], host_nonce[6], "same FRAME payload type");
    assert_eq!(&ack_nonce[8..12], &[0, 0, 0, 0], "viewer Ack is seq 0");
    assert_eq!(&host_nonce[8..12], &[0, 0, 0, 0], "host control is seq 0");
}
