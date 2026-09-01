// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed initiator state for the long-lived sealed operator channel.
//!
//! The daemon is the only side allowed to propose an operator-channel rekey.
//! Transport delivery is inherently ambiguous after a successful local send:
//! the peer may have received and installed the new key even if the Ack is then
//! lost. Therefore this state machine deliberately has no rollback transition
//! after a Proposal has been sent. The only successful path back to `Stable`
//! is an Ack authenticated under the exact proposed new key. Any timeout,
//! mismatch, old-key Ack, transport failure, or unexpected control message is
//! session-fatal at the caller.
//!
//! The caller supplies separate transmit and authority-receive `Session`s. On a
//! successful Proposal send, the transmit session rotates normally, while the
//! authority receive session is rebuilt from scratch with only the new key.
//! That deliberately removes xenia-wire's previous-key grace from the
//! authority-bearing receive path: old-key Acks and old-key consent decisions
//! stop being authoritative immediately after the daemon commits the rekey.

use std::fmt;
use std::mem;
use std::time::Duration;

use thiserror::Error;
use tokio::time::Instant;
use xenia_handshake::{OperatorRekeyEpochContext, OperatorRekeyReason as HandshakeRekeyReason};
use xenia_wire::Session;
use xenia_wire::operator_rekey::{self, OperatorRekeyMessage};

/// Maximum time a sent Proposal may remain unacknowledged before the caller
/// tears down the channel and requires a fresh authenticated handshake.
pub(crate) const OPERATOR_REKEY_ACK_TIMEOUT: Duration = Duration::from_secs(10);

const KEY_DIGEST_CONTEXT: &str = "xenia.operator-rekey.current-key-digest.v1";
const ACK_SEQUENCE: u32 = 0;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum RekeyInitiatorError {
    #[error("operator rekey already has an active transition")]
    TransitionAlreadyActive,
    #[error("operator rekey epoch counter exhausted")]
    EpochExhausted,
    #[error("operator rekey root is all zero")]
    ZeroRekeyRoot,
    #[error("operator rekey epoch hash failed: {0}")]
    EpochHash(String),
    #[error("operator rekey proposal encoding failed: {0}")]
    ProposalEncode(String),
    #[error("operator rekey proposal sealing failed: {0}")]
    ProposalSeal(String),
    #[error("operator rekey KDF returned the current AEAD key")]
    RekeyDidNotRotate,
    #[error("operator rekey Proposal was not prepared")]
    ProposalNotPrepared,
    #[error("operator rekey Ack arrived with no outstanding Proposal")]
    NoOutstandingProposal,
    #[error("operator rekey Ack deadline expired")]
    AckDeadlineExpired,
    #[error("operator rekey Ack used the wrong payload type")]
    AckWrongPayloadType,
    #[error("operator rekey Ack used the wrong nonce domain")]
    AckWrongNonceDomain,
    #[error("operator rekey Ack was not the first new-key envelope")]
    AckWrongSequence,
    #[error("operator rekey Ack did not authenticate under the exact proposed new key")]
    AckAuthenticationFailed,
    #[error("operator rekey Ack decoding failed: {0}")]
    AckDecode(String),
    #[error("operator rekey peer sent a Proposal even though only the daemon proposes")]
    UnexpectedPeerProposal,
    #[error("operator rekey Ack did not match the outstanding Proposal")]
    AckMismatch,
}

struct PreparedRekey {
    key_epoch: u64,
    epoch_hash: [u8; 32],
    new_key: [u8; 32],
    proposal_envelope: Vec<u8>,
}

impl fmt::Debug for PreparedRekey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedRekey")
            .field("key_epoch", &self.key_epoch)
            .field("epoch_hash", &self.epoch_hash)
            .field("new_key", &"<redacted>")
            .field("proposal_envelope_len", &self.proposal_envelope.len())
            .finish()
    }
}

impl Drop for PreparedRekey {
    fn drop(&mut self) {
        self.new_key.fill(0);
    }
}

#[derive(Debug, Clone, Copy)]
struct PendingAck {
    key_epoch: u64,
    epoch_hash: [u8; 32],
    deadline: Instant,
}

#[derive(Debug)]
enum Phase {
    Stable,
    Prepared(PreparedRekey),
    PendingAck(PendingAck),
}

/// Daemon-side operator-channel rekey initiator.
///
/// This object intentionally does not retain the live AEAD key or the rekey
/// root. It stores only a domain-separated digest of the current key, enough to
/// reject a KDF regression that would claim a new epoch without changing key
/// material. Exact-current-key receive authentication is owned by the separate
/// authority receive `Session` supplied by the caller.
pub(crate) struct OperatorRekeyInitiator {
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
    current_epoch: u64,
    current_key_digest: [u8; 32],
    peer_source_id: [u8; 8],
    session_epoch: u8,
    phase: Phase,
}

impl OperatorRekeyInitiator {
    pub(crate) fn new(
        base_transcript_hash: [u8; 32],
        initial_key: &[u8; 32],
        peer_source_id: [u8; 8],
        session_epoch: u8,
    ) -> Self {
        Self {
            base_transcript_hash,
            previous_epoch_hash: base_transcript_hash,
            current_epoch: 0,
            current_key_digest: key_digest(initial_key),
            peer_source_id,
            session_epoch,
            phase: Phase::Stable,
        }
    }

    /// Prepare the next interval-driven Proposal while the transmit `Session`
    /// still uses the old key. Every fallible local step happens here, before
    /// the transport send. On success the Proposal envelope is ready to send but
    /// neither local session has changed key yet.
    pub(crate) fn prepare_interval(
        &mut self,
        tx_session: &mut Session,
        rekey_root: &[u8; 32],
    ) -> Result<(), RekeyInitiatorError> {
        if !matches!(self.phase, Phase::Stable) {
            return Err(RekeyInitiatorError::TransitionAlreadyActive);
        }
        if rekey_root.iter().all(|byte| *byte == 0) {
            return Err(RekeyInitiatorError::ZeroRekeyRoot);
        }

        let key_epoch = self
            .current_epoch
            .checked_add(1)
            .ok_or(RekeyInitiatorError::EpochExhausted)?;
        let epoch_hash = OperatorRekeyEpochContext::new(
            key_epoch,
            self.base_transcript_hash,
            self.previous_epoch_hash,
            HandshakeRekeyReason::Interval,
        )
        .epoch_hash()
        .map_err(|err| RekeyInitiatorError::EpochHash(err.to_string()))?;

        let mut new_key = xenia_handshake::derive_operator_rekey_key(rekey_root, &epoch_hash);
        if key_digest(&new_key) == self.current_key_digest {
            new_key.fill(0);
            return Err(RekeyInitiatorError::RekeyDidNotRotate);
        }

        let proposal = OperatorRekeyMessage::Proposal {
            key_epoch,
            base_transcript_hash: self.base_transcript_hash,
            previous_epoch_hash: self.previous_epoch_hash,
            reason: operator_rekey::OperatorRekeyReason::Interval,
            epoch_hash,
        };
        let proposal_bytes = match proposal.encode() {
            Ok(bytes) => bytes,
            Err(err) => {
                new_key.fill(0);
                return Err(RekeyInitiatorError::ProposalEncode(err.to_string()));
            }
        };
        let proposal_envelope = match tx_session.seal(
            &proposal_bytes,
            operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY,
        ) {
            Ok(envelope) => envelope,
            Err(err) => {
                new_key.fill(0);
                return Err(RekeyInitiatorError::ProposalSeal(err.to_string()));
            }
        };

        self.phase = Phase::Prepared(PreparedRekey {
            key_epoch,
            epoch_hash,
            new_key,
            proposal_envelope,
        });
        Ok(())
    }

    pub(crate) fn prepared_envelope(&self) -> Result<&[u8], RekeyInitiatorError> {
        match &self.phase {
            Phase::Prepared(prepared) => Ok(&prepared.proposal_envelope),
            _ => Err(RekeyInitiatorError::ProposalNotPrepared),
        }
    }

    pub(crate) fn prepared_epoch(&self) -> Result<u64, RekeyInitiatorError> {
        match &self.phase {
            Phase::Prepared(prepared) => Ok(prepared.key_epoch),
            _ => Err(RekeyInitiatorError::ProposalNotPrepared),
        }
    }

    /// Commit the proposed key only after `send_envelope` succeeds locally.
    ///
    /// There is intentionally no inverse transition. Once the Proposal may have
    /// escaped the process, ambiguity is resolved only by a matching new-key Ack
    /// or by tearing down the connection and establishing a fresh handshake.
    /// The authority receive session is *replaced*, not rekeyed in place, so it
    /// retains no previous-key grace.
    pub(crate) fn commit_sent(
        &mut self,
        tx_session: &mut Session,
        authority_rx_session: &mut Session,
        deadline: Instant,
    ) -> Result<u64, RekeyInitiatorError> {
        let prior_phase = mem::replace(&mut self.phase, Phase::Stable);
        let mut prepared = match prior_phase {
            Phase::Prepared(prepared) => prepared,
            other => {
                self.phase = other;
                return Err(RekeyInitiatorError::ProposalNotPrepared);
            }
        };

        tx_session.install_key(prepared.new_key);
        let mut fresh_rx = Session::with_source_id(self.peer_source_id, self.session_epoch);
        fresh_rx.install_key(prepared.new_key);
        *authority_rx_session = fresh_rx;

        self.current_key_digest = key_digest(&prepared.new_key);
        let key_epoch = prepared.key_epoch;
        let epoch_hash = prepared.epoch_hash;
        prepared.new_key.fill(0);

        self.phase = Phase::PendingAck(PendingAck {
            key_epoch,
            epoch_hash,
            deadline,
        });
        Ok(key_epoch)
    }

    pub(crate) fn ack_deadline(&self) -> Option<Instant> {
        match self.phase {
            Phase::PendingAck(pending) => Some(pending.deadline),
            _ => None,
        }
    }

    pub(crate) fn is_pending_ack(&self) -> bool {
        matches!(self.phase, Phase::PendingAck(_))
    }

    /// Application authority is intentionally suspended across both the local
    /// prepared-send window and the remote-confirmation window.
    pub(crate) fn application_allowed(&self) -> bool {
        matches!(self.phase, Phase::Stable)
    }

    /// Verify and consume the outstanding Ack through the caller's
    /// exact-current-key authority receive session.
    pub(crate) fn accept_ack(
        &mut self,
        authority_rx_session: &mut Session,
        envelope: &[u8],
        now: Instant,
    ) -> Result<u64, RekeyInitiatorError> {
        let pending = match self.phase {
            Phase::PendingAck(pending) => pending,
            _ => return Err(RekeyInitiatorError::NoOutstandingProposal),
        };
        if now > pending.deadline {
            return Err(RekeyInitiatorError::AckDeadlineExpired);
        }
        if xenia_wire::envelope_payload_type(envelope)
            != Some(operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY)
        {
            return Err(RekeyInitiatorError::AckWrongPayloadType);
        }
        if envelope.len() < 12 + 16
            || envelope[..6] != self.peer_source_id[..6]
            || envelope[7] != self.session_epoch
        {
            return Err(RekeyInitiatorError::AckWrongNonceDomain);
        }
        let sequence = u32::from_le_bytes([
            envelope[8],
            envelope[9],
            envelope[10],
            envelope[11],
        ]);
        if sequence != ACK_SEQUENCE {
            return Err(RekeyInitiatorError::AckWrongSequence);
        }

        let plaintext = authority_rx_session
            .open(envelope)
            .map_err(|_| RekeyInitiatorError::AckAuthenticationFailed)?;
        let message = OperatorRekeyMessage::decode(&plaintext)
            .map_err(|err| RekeyInitiatorError::AckDecode(err.to_string()))?;
        match message {
            OperatorRekeyMessage::Ack {
                key_epoch,
                epoch_hash,
            } if key_epoch == pending.key_epoch && epoch_hash == pending.epoch_hash => {
                self.current_epoch = pending.key_epoch;
                self.previous_epoch_hash = pending.epoch_hash;
                self.phase = Phase::Stable;
                Ok(key_epoch)
            }
            OperatorRekeyMessage::Ack { .. } => Err(RekeyInitiatorError::AckMismatch),
            OperatorRekeyMessage::Proposal { .. } => {
                Err(RekeyInitiatorError::UnexpectedPeerProposal)
            }
        }
    }
}

fn key_digest(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(KEY_DIGEST_CONTEXT);
    hasher.update(key);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_SOURCE_ID: [u8; 8] = *b"xnaophs1";
    const PEER_SOURCE_ID: [u8; 8] = *b"xnaopch1";
    const SESSION_EPOCH: u8 = 1;
    const INITIAL_KEY: [u8; 32] = [0x11; 32];
    const REKEY_ROOT: [u8; 32] = [0x22; 32];
    const TRANSCRIPT_HASH: [u8; 32] = [0x33; 32];

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

    fn pending_identity(initiator: &OperatorRekeyInitiator) -> (u64, [u8; 32]) {
        match initiator.phase {
            Phase::PendingAck(pending) => (pending.key_epoch, pending.epoch_hash),
            _ => panic!("expected PendingAck"),
        }
    }

    fn peer_envelope(
        key: [u8; 32],
        message: OperatorRekeyMessage,
        burn_first_nonce: bool,
    ) -> Vec<u8> {
        let mut sender = Session::with_source_id(PEER_SOURCE_ID, SESSION_EPOCH);
        sender.install_key(key);
        if burn_first_nonce {
            sender
                .seal(b"not-the-ack", operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY)
                .unwrap();
        }
        sender
            .seal(
                &message.encode().unwrap(),
                operator_rekey::PAYLOAD_TYPE_OPERATOR_REKEY,
            )
            .unwrap()
    }

    #[test]
    fn prepared_debug_redacts_future_aead_key() {
        let mut tx = tx_session();
        let mut rekey = initiator();
        rekey.prepare_interval(&mut tx, &REKEY_ROOT).unwrap();

        let (debug, expected_key_debug) = match &rekey.phase {
            Phase::Prepared(prepared) => {
                let expected_key =
                    xenia_handshake::derive_operator_rekey_key(&REKEY_ROOT, &prepared.epoch_hash);
                (format!("{:?}", rekey.phase), format!("{expected_key:?}"))
            }
            _ => panic!("expected Prepared"),
        };

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&expected_key_debug));
    }

    #[test]
    fn prepare_uses_distinct_host_nonce_domain_and_commit_is_one_way() {
        let mut tx = tx_session();
        let mut rx = rx_session();
        let mut rekey = initiator();

        rekey.prepare_interval(&mut tx, &REKEY_ROOT).unwrap();
        assert!(!rekey.application_allowed());
        assert_eq!(rekey.prepared_epoch().unwrap(), 1);

        let proposal_envelope = rekey.prepared_envelope().unwrap().to_vec();
        assert_eq!(&proposal_envelope[..6], &HOST_SOURCE_ID[..6]);
        assert_ne!(&HOST_SOURCE_ID[..6], &PEER_SOURCE_ID[..6]);
        let mut old_key_receiver = Session::with_source_id(PEER_SOURCE_ID, SESSION_EPOCH);
        old_key_receiver.install_key(INITIAL_KEY);
        let proposal_plaintext = old_key_receiver.open(&proposal_envelope).unwrap();
        let proposal = OperatorRekeyMessage::decode(&proposal_plaintext).unwrap();
        assert!(matches!(
            proposal,
            OperatorRekeyMessage::Proposal { key_epoch: 1, .. }
        ));

        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            rekey.commit_sent(&mut tx, &mut rx, deadline).unwrap(),
            1
        );
        assert!(rekey.is_pending_ack());
        assert_eq!(rekey.ack_deadline(), Some(deadline));
        assert!(!rekey.application_allowed());
    }

    #[test]
    fn exact_new_key_ack_is_required_to_confirm() {
        let mut tx = tx_session();
        let mut rx = rx_session();
        let mut rekey = initiator();
        rekey.prepare_interval(&mut tx, &REKEY_ROOT).unwrap();
        rekey
            .commit_sent(
                &mut tx,
                &mut rx,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let (key_epoch, epoch_hash) = pending_identity(&rekey);
        let new_key = xenia_handshake::derive_operator_rekey_key(&REKEY_ROOT, &epoch_hash);
        let ack = peer_envelope(
            new_key,
            OperatorRekeyMessage::Ack {
                key_epoch,
                epoch_hash,
            },
            false,
        );

        assert_eq!(
            rekey.accept_ack(&mut rx, &ack, Instant::now()).unwrap(),
            1
        );
        assert!(rekey.application_allowed());
        assert!(!rekey.is_pending_ack());
    }

    #[test]
    fn old_key_forged_ack_is_rejected_even_during_generic_session_grace() {
        let mut tx = tx_session();
        let mut rx = rx_session();
        let mut rekey = initiator();
        rekey.prepare_interval(&mut tx, &REKEY_ROOT).unwrap();
        rekey
            .commit_sent(
                &mut tx,
                &mut rx,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let (key_epoch, epoch_hash) = pending_identity(&rekey);
        let forged = peer_envelope(
            INITIAL_KEY,
            OperatorRekeyMessage::Ack {
                key_epoch,
                epoch_hash,
            },
            false,
        );

        assert_eq!(
            rekey.accept_ack(&mut rx, &forged, Instant::now()),
            Err(RekeyInitiatorError::AckAuthenticationFailed)
        );
        assert!(rekey.is_pending_ack());
        assert!(!rekey.application_allowed());
    }

    #[test]
    fn old_key_application_authority_is_dropped_immediately_on_commit() {
        let mut tx = tx_session();
        let mut rx = rx_session();
        let mut rekey = initiator();
        rekey.prepare_interval(&mut tx, &REKEY_ROOT).unwrap();
        rekey
            .commit_sent(
                &mut tx,
                &mut rx,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        let mut old_sender = Session::with_source_id(PEER_SOURCE_ID, SESSION_EPOCH);
        old_sender.install_key(INITIAL_KEY);
        let old_application = old_sender
            .seal(b"Approve", xenia_wire::PAYLOAD_TYPE_APPLICATION_MIN)
            .unwrap();
        assert!(rx.open(&old_application).is_err());
    }

    #[test]
    fn matching_ack_after_deadline_is_rejected() {
        let mut tx = tx_session();
        let mut rx = rx_session();
        let mut rekey = initiator();
        rekey.prepare_interval(&mut tx, &REKEY_ROOT).unwrap();
        let deadline = Instant::now();
        rekey.commit_sent(&mut tx, &mut rx, deadline).unwrap();
        let (key_epoch, epoch_hash) = pending_identity(&rekey);
        let new_key = xenia_handshake::derive_operator_rekey_key(&REKEY_ROOT, &epoch_hash);
        let ack = peer_envelope(
            new_key,
            OperatorRekeyMessage::Ack {
                key_epoch,
                epoch_hash,
            },
            false,
        );

        assert_eq!(
            rekey.accept_ack(&mut rx, &ack, deadline + Duration::from_millis(1)),
            Err(RekeyInitiatorError::AckDeadlineExpired)
        );
    }

    #[test]
    fn ack_must_be_first_new_key_envelope() {
        let mut tx = tx_session();
        let mut rx = rx_session();
        let mut rekey = initiator();
        rekey.prepare_interval(&mut tx, &REKEY_ROOT).unwrap();
        rekey
            .commit_sent(
                &mut tx,
                &mut rx,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let (key_epoch, epoch_hash) = pending_identity(&rekey);
        let new_key = xenia_handshake::derive_operator_rekey_key(&REKEY_ROOT, &epoch_hash);
        let ack = peer_envelope(
            new_key,
            OperatorRekeyMessage::Ack {
                key_epoch,
                epoch_hash,
            },
            true,
        );

        assert_eq!(
            rekey.accept_ack(&mut rx, &ack, Instant::now()),
            Err(RekeyInitiatorError::AckWrongSequence)
        );
    }

    #[test]
    fn wrong_ack_identity_is_rejected_without_advancing_lineage() {
        let mut tx = tx_session();
        let mut rx = rx_session();
        let mut rekey = initiator();
        rekey.prepare_interval(&mut tx, &REKEY_ROOT).unwrap();
        rekey
            .commit_sent(
                &mut tx,
                &mut rx,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let (key_epoch, epoch_hash) = pending_identity(&rekey);
        let new_key = xenia_handshake::derive_operator_rekey_key(&REKEY_ROOT, &epoch_hash);
        let ack = peer_envelope(
            new_key,
            OperatorRekeyMessage::Ack {
                key_epoch: key_epoch + 1,
                epoch_hash,
            },
            false,
        );

        assert_eq!(
            rekey.accept_ack(&mut rx, &ack, Instant::now()),
            Err(RekeyInitiatorError::AckMismatch)
        );
        assert_eq!(rekey.current_epoch, 0);
        assert_eq!(rekey.previous_epoch_hash, TRANSCRIPT_HASH);
        assert!(rekey.is_pending_ack());
    }

    #[test]
    fn peer_proposal_is_rejected_while_waiting_for_ack() {
        let mut tx = tx_session();
        let mut rx = rx_session();
        let mut rekey = initiator();
        rekey.prepare_interval(&mut tx, &REKEY_ROOT).unwrap();
        rekey
            .commit_sent(
                &mut tx,
                &mut rx,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let (_, epoch_hash) = pending_identity(&rekey);
        let new_key = xenia_handshake::derive_operator_rekey_key(&REKEY_ROOT, &epoch_hash);
        let proposal = peer_envelope(
            new_key,
            OperatorRekeyMessage::Proposal {
                key_epoch: 2,
                base_transcript_hash: TRANSCRIPT_HASH,
                previous_epoch_hash: epoch_hash,
                reason: operator_rekey::OperatorRekeyReason::Interval,
                epoch_hash: [0x44; 32],
            },
            false,
        );

        assert_eq!(
            rekey.accept_ack(&mut rx, &proposal, Instant::now()),
            Err(RekeyInitiatorError::UnexpectedPeerProposal)
        );
    }

    #[test]
    fn zero_rekey_root_fails_before_consuming_a_nonce() {
        let mut tx = tx_session();
        let mut rekey = initiator();
        let before = tx.nonce_counter();

        assert_eq!(
            rekey.prepare_interval(&mut tx, &[0u8; 32]),
            Err(RekeyInitiatorError::ZeroRekeyRoot)
        );
        assert_eq!(tx.nonce_counter(), before);
        assert!(rekey.application_allowed());
    }
}
