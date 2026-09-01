// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transport-owned boundary for daemon-initiated operator-channel rekey.
//!
//! `OperatorRekeyInitiator` owns cryptographic/state-machine preparation and
//! commit, while the concrete `Transport` owns the only event that can make
//! delivery ambiguous. This module binds those responsibilities into one
//! production call so callers cannot accidentally reorder:
//!
//! `prepare old-key Proposal -> send exact bytes -> one-way local commit`.
//!
//! A transport send error is session-fatal. The state machine intentionally
//! remains non-Stable after such an error: some prefix or the complete Proposal
//! may have escaped the process, so rollback would be an unsafe guess.

use tokio::time::Instant;
use xenia_peer_core::transport::Transport;
use xenia_wire::Session;

use super::initiator::{OperatorRekeyInitiator, RekeyInitiatorError};

/// Failure while executing the transport-owned initiator transaction.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RekeyTransportTransactionError {
    /// Local state/KDF/encoding/sealing/commit contract rejected the operation.
    #[error(transparent)]
    State(#[from] RekeyInitiatorError),
    /// The carrier could not confirm a complete local send. This is always
    /// session-fatal because remote delivery may be ambiguous.
    #[error("operator rekey Proposal transport send failed after preparation: {0}")]
    Transport(String),
}

/// Prepare, send, and one-way commit one interval-driven operator rekey.
///
/// Every fallible *local* cryptographic operation runs before the transport
/// call. Only after `send_envelope` reports success are the local TX and
/// authority-RX sessions replaced with fresh new-key-only sessions and the
/// initiator moved to `PendingAck`.
///
/// `send_envelope` failure is deliberately not rolled back. The caller must
/// tear the authenticated channel down and require a fresh handshake.
pub(crate) async fn prepare_send_commit_interval<T: Transport>(
    rekey: &mut OperatorRekeyInitiator,
    transport: &mut T,
    tx_session: &mut Session,
    authority_rx_session: &mut Session,
    rekey_root: &[u8; 32],
    ack_deadline: Instant,
) -> Result<u64, RekeyTransportTransactionError> {
    rekey.prepare_interval(tx_session, rekey_root)?;
    let prepared_epoch = rekey.prepared_epoch()?;

    {
        let proposal = rekey.prepared_envelope()?;
        transport
            .send_envelope(proposal)
            .await
            .map_err(|err| RekeyTransportTransactionError::Transport(err.to_string()))?;
    }

    let committed_epoch = rekey.commit_sent(tx_session, authority_rx_session, ack_deadline)?;
    debug_assert_eq!(prepared_epoch, committed_epoch);
    Ok(committed_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use xenia_peer_core::transport::{
        TransportError, TransportKind, TransportProfileV1,
    };
    use xenia_wire::operator_rekey::{self, OperatorRekeyMessage};

    const HOST_SOURCE_ID: [u8; 8] = *b"xnaophs1";
    const PEER_SOURCE_ID: [u8; 8] = *b"xnaopch1";
    const SESSION_EPOCH: u8 = 1;
    const INITIAL_KEY: [u8; 32] = [0x11; 32];
    const REKEY_ROOT: [u8; 32] = [0x22; 32];
    const TRANSCRIPT_HASH: [u8; 32] = [0x33; 32];

    struct RecordingTransport {
        sent: Vec<Vec<u8>>,
        fail_send: bool,
    }

    impl RecordingTransport {
        fn success() -> Self {
            Self {
                sent: Vec::new(),
                fail_send: false,
            }
        }

        fn failing() -> Self {
            Self {
                sent: Vec::new(),
                fail_send: true,
            }
        }
    }

    impl Transport for RecordingTransport {
        fn transport_profile(&self) -> TransportProfileV1 {
            TransportProfileV1::current(TransportKind::WebSocket)
        }

        async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            if self.fail_send {
                return Err(TransportError::UnexpectedEof);
            }
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
            Err(TransportError::UnexpectedEof)
        }
    }

    fn tx_session() -> Session {
        let mut session = Session::with_source_id(HOST_SOURCE_ID, SESSION_EPOCH);
        session.install_key(INITIAL_KEY);
        session
    }

    fn rx_session() -> Session {
        let mut session = Session::with_source_id(PEER_SOURCE_ID, SESSION_EPOCH);
        session.install_key(INITIAL_KEY);
        session
    }

    fn initiator() -> OperatorRekeyInitiator {
        OperatorRekeyInitiator::new(
            TRANSCRIPT_HASH,
            &INITIAL_KEY,
            PEER_SOURCE_ID,
            SESSION_EPOCH,
        )
    }

    #[tokio::test]
    async fn transport_observes_exact_old_key_proposal_before_local_commit() {
        let mut rekey = initiator();
        let mut tx = tx_session();
        let mut rx = rx_session();
        let mut transport = RecordingTransport::success();

        let epoch = prepare_send_commit_interval(
            &mut rekey,
            &mut transport,
            &mut tx,
            &mut rx,
            &REKEY_ROOT,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(epoch, 1);
        assert_eq!(transport.sent.len(), 1);
        assert!(rekey.is_pending_ack());
        assert!(!rekey.application_allowed());

        // The exact transport bytes were produced under the old host key.
        let mut old_key_receiver = Session::with_source_id(HOST_SOURCE_ID, SESSION_EPOCH);
        old_key_receiver.install_key(INITIAL_KEY);
        let plaintext = old_key_receiver.open(&transport.sent[0]).unwrap();
        let proposal = OperatorRekeyMessage::decode(&plaintext).unwrap();
        assert!(matches!(
            proposal,
            OperatorRekeyMessage::Proposal { key_epoch: 1, .. }
        ));

        // After local commit, both local sessions are new-key-only. The old key
        // is not retained merely because generic Session supports grace.
        let mut old_host = Session::with_source_id(HOST_SOURCE_ID, SESSION_EPOCH);
        old_host.install_key(INITIAL_KEY);
        let old_host_envelope = old_host
            .seal(b"obsolete host key", xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
            .unwrap();
        assert!(tx.open(&old_host_envelope).is_err());

        let mut old_peer = Session::with_source_id(PEER_SOURCE_ID, SESSION_EPOCH);
        old_peer.install_key(INITIAL_KEY);
        let old_peer_envelope = old_peer
            .seal(b"obsolete peer key", xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
            .unwrap();
        assert!(rx.open(&old_peer_envelope).is_err());
    }

    #[tokio::test]
    async fn ambiguous_transport_send_failure_never_restores_authority() {
        let mut rekey = initiator();
        let mut tx = tx_session();
        let mut rx = rx_session();
        let mut transport = RecordingTransport::failing();
        let old_rx_fingerprint = rx.session_fingerprint(7).unwrap();

        let err = prepare_send_commit_interval(
            &mut rekey,
            &mut transport,
            &mut tx,
            &mut rx,
            &REKEY_ROOT,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, RekeyTransportTransactionError::Transport(_)));
        assert!(transport.sent.is_empty());

        // Preparation consumed one old-key transmit nonce, but no local key
        // commit occurred. Crucially, the initiator remains non-Stable, so the
        // caller cannot continue application authority after ambiguous send.
        assert_eq!(tx.nonce_counter(), 1);
        assert_eq!(rx.session_fingerprint(7).unwrap(), old_rx_fingerprint);
        assert!(!rekey.is_pending_ack());
        assert!(!rekey.application_allowed());
        assert!(matches!(
            rekey.prepare_interval(&mut tx, &REKEY_ROOT),
            Err(RekeyInitiatorError::TransitionAlreadyActive)
        ));
    }
}
