// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Regression for xenia-peer #192.
//!
//! The characterization parent proved that viewer rekey Ack and the host's
//! first subsequent new-key control frame could reuse the same AEAD nonce. This
//! successor requires distinct nonce domains while preserving interoperability.

use std::collections::HashSet;

use xenia_handshake::{RekeyEpochKeys, RekeyReason};
use xenia_peer_core::{
    LaneSession,
    frame::{
        ClipboardContent, FileTransferMessage, LANE_ENVELOPE_MAGIC, RawRekey,
    },
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

fn bare_nonce(envelope: &[u8]) -> &[u8] {
    assert!(
        envelope.len() >= NONCE_LEN,
        "bare envelope must contain an xenia-wire nonce"
    );
    &envelope[..NONCE_LEN]
}

fn inner_nonce_array(envelope: &[u8]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(inner_nonce(envelope));
    nonce
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SenderNonceDomain {
    source_prefix: [u8; 6],
    payload_type: u8,
    epoch: u8,
}

fn nonce_domain(nonce: &[u8]) -> SenderNonceDomain {
    assert!(nonce.len() >= NONCE_LEN);
    let mut source_prefix = [0u8; 6];
    source_prefix.copy_from_slice(&nonce[..6]);
    SenderNonceDomain {
        source_prefix,
        payload_type: nonce[6],
        epoch: nonce[7],
    }
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

#[test]
fn control_key_writer_nonce_domains_are_disjoint_across_independent_sealing_roles() {
    let mut host = LaneSession::with_fixture(SOURCE_ID, SESSION_EPOCH);
    let mut viewer = LaneSession::with_fixture(SOURCE_ID, SESSION_EPOCH);
    let keys = rekey_keys([0x6A; 32]);
    host.install_rekey_keys(&keys);
    viewer.install_rekey_keys(&keys);

    let proposal = RawRekey::Proposal {
        key_epoch: 1,
        base_transcript_hash: [0x10; 32],
        previous_epoch_hash: [0x11; 32],
        reason: RekeyReason::Manual,
        epoch_hash: [0x12; 32],
    }
    .into_frame(0, 0)
    .expect("build host control proposal");
    let host_control = host
        .seal_control_frame(&proposal)
        .expect("seal host control writer");

    let ack = RawRekey::Ack {
        key_epoch: 1,
        epoch_hash: [0x12; 32],
    }
    .into_frame(0, 0)
    .expect("build viewer Ack");
    let viewer_ack = viewer
        .seal_control_frame(&ack)
        .expect("seal viewer Ack writer");

    let viewer_input = viewer
        .seal_input_event(b"input".to_vec())
        .expect("seal viewer input writer");
    let viewer_clipboard = viewer
        .seal_clipboard_event(ClipboardContent::Text("clipboard".to_string()))
        .expect("seal viewer clipboard writer");

    let host_file = host
        .seal_file_transfer_message(
            FileTransferMessage::Reject {
                transfer_id: 1,
                reason: "host writer".to_string(),
            },
            true,
        )
        .expect("seal host file-transfer writer");
    let viewer_file = viewer
        .seal_file_transfer_message(
            FileTransferMessage::Reject {
                transfer_id: 2,
                reason: "viewer writer".to_string(),
            },
            false,
        )
        .expect("seal viewer file-transfer writer");

    // These are the currently independent control-key sealing roles/domains.
    // Multiple semantic host control FRAME messages share one WireSession and
    // one monotonic counter, so they are one writer class rather than separate
    // independent nonce allocators. The Ack has its own WireSession/counter.
    let observed = [
        ("host-control-frame", nonce_domain(inner_nonce(&host_control))),
        ("viewer-rekey-ack", nonce_domain(inner_nonce(&viewer_ack))),
        ("viewer-input", nonce_domain(bare_nonce(&viewer_input))),
        (
            "viewer-reverse-clipboard",
            nonce_domain(bare_nonce(&viewer_clipboard)),
        ),
        (
            "host-file-transfer",
            nonce_domain(bare_nonce(&host_file)),
        ),
        (
            "viewer-file-transfer",
            nonce_domain(bare_nonce(&viewer_file)),
        ),
    ];

    let mut seen = HashSet::new();
    for (name, domain) in observed {
        assert!(
            seen.insert(domain),
            "independent control-key writer {name} collides with an existing sender nonce domain: {domain:?}"
        );
    }

    assert_eq!(
        seen.len(),
        observed.len(),
        "every independent control-key writer must occupy a distinct (source-prefix, payload-type, epoch) domain"
    );

    // The original incident class is structurally separated by source prefix;
    // file transfer is separated by role-specific payload type; input and
    // reverse clipboard occupy their own payload domains.
    assert_ne!(observed[0].1.source_prefix, observed[1].1.source_prefix);
    assert_ne!(observed[4].1.payload_type, observed[5].1.payload_type);
    assert_ne!(observed[2].1.payload_type, observed[3].1.payload_type);
}

#[test]
fn repeated_genuine_rekeys_preserve_key_nonce_uniqueness_after_counter_resets() {
    let mut host = LaneSession::with_fixture(SOURCE_ID, SESSION_EPOCH);
    let mut viewer = LaneSession::with_fixture(SOURCE_ID, SESSION_EPOCH);
    let mut seen_key_nonce_pairs = HashSet::new();

    // A nonce may legitimately repeat byte-for-byte after a genuine rekey if
    // the AEAD key changed. The cryptographic invariant is uniqueness of the
    // (key, nonce) pair, not global nonce-byte uniqueness across unrelated keys.
    // Duplicate installation of the *same* key is a lower-layer xenia-wire
    // defect tracked separately by xenia-wire #35 and is deliberately not
    // hidden inside this peer-layer regression.
    for round in 1u8..=4 {
        let control_key = [0x40 + round; 32];
        let keys = rekey_keys(control_key);
        host.install_rekey_keys(&keys);
        viewer.install_rekey_keys(&keys);

        let ack_hash = [0xA0 + round; 32];
        let ack_epoch = u64::from(round);
        let ack = RawRekey::Ack {
            key_epoch: ack_epoch,
            epoch_hash: ack_hash,
        }
        .into_frame(u64::from(round) * 2, u64::from(round) * 10)
        .expect("build repeated-rekey Ack");
        let viewer_ack = viewer
            .seal_control_frame(&ack)
            .expect("seal repeated-rekey Ack");

        let proposal_hash = [0xC0 + round; 32];
        let proposal = RawRekey::Proposal {
            key_epoch: ack_epoch + 1,
            base_transcript_hash: [0xB0 + round; 32],
            previous_epoch_hash: ack_hash,
            reason: RekeyReason::Manual,
            epoch_hash: proposal_hash,
        }
        .into_frame(u64::from(round) * 2 + 1, u64::from(round) * 10 + 1)
        .expect("build repeated-rekey proposal");
        let host_control = host
            .seal_control_frame(&proposal)
            .expect("seal repeated-rekey host control");

        let ack_nonce = inner_nonce_array(&viewer_ack);
        let host_nonce = inner_nonce_array(&host_control);

        // Every genuine key change resets both sender counters, so both seals
        // are sequence zero again. Safety must therefore come from structural
        // sender source-domain separation, not lucky counter skew.
        assert_eq!(&ack_nonce[8..12], &[0, 0, 0, 0]);
        assert_eq!(&host_nonce[8..12], &[0, 0, 0, 0]);
        assert_ne!(
            ack_nonce, host_nonce,
            "round {round}: opposite sealing roles collided after counter reset"
        );
        assert_ne!(
            &ack_nonce[..6],
            &host_nonce[..6],
            "round {round}: separated sender source domains disappeared"
        );

        assert!(
            seen_key_nonce_pairs.insert((control_key, ack_nonce)),
            "round {round}: viewer Ack reused a prior (key, nonce) pair"
        );
        assert!(
            seen_key_nonce_pairs.insert((control_key, host_nonce)),
            "round {round}: host control reused a prior (key, nonce) pair"
        );

        let opened_ack = host
            .open_frame(&viewer_ack)
            .expect("host opens repeated-rekey Ack");
        assert_eq!(
            RawRekey::from_frame(&opened_ack).expect("decode repeated-rekey Ack"),
            RawRekey::Ack {
                key_epoch: ack_epoch,
                epoch_hash: ack_hash,
            }
        );

        let opened_proposal = viewer
            .open_frame(&host_control)
            .expect("viewer opens repeated-rekey proposal");
        assert_eq!(
            RawRekey::from_frame(&opened_proposal).expect("decode repeated-rekey proposal"),
            RawRekey::Proposal {
                key_epoch: ack_epoch + 1,
                base_transcript_hash: [0xB0 + round; 32],
                previous_epoch_hash: ack_hash,
                reason: RekeyReason::Manual,
                epoch_hash: proposal_hash,
            }
        );
    }

    assert_eq!(
        seen_key_nonce_pairs.len(),
        8,
        "four rekeys × two sealing roles must yield eight unique (key, nonce) pairs"
    );
}
