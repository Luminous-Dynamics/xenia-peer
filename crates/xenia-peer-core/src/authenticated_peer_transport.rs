// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Same-transport ownership boundary for authenticated Xenia peer traffic.
//!
//! [`crate::AuthenticatedPeerHandshakeV1`] proves which hybrid peer identity a
//! completed host handshake authenticated, but handshake evidence can outlive
//! the carrier. This module closes the next structural gap by moving the exact
//! [`Transport`] object used for that handshake into an opaque wrapper and by
//! permitting subsequent envelope I/O only through that wrapper.
//!
//! Successful receives yield a non-`Clone`, non-serializable
//! [`PeerBoundInboundEnvelopeV1`] branded to the exact wrapper instance and
//! handshake transcript generation. This proves same-carrier receipt only: the
//! returned bytes remain opaque Xenia carrier-envelope bytes and MUST still pass
//! xenia-wire AEAD/replay verification before any application semantic or
//! authority decision trusts their contents.

use rand::random;
use thiserror::Error;
use xenia_handshake::HandshakeManager;

use crate::{
    AuthenticatedPeerHandshakeV1, perform_host_handshake_authenticated_peer_v1,
    transport::{
        Transport, TransportAvailabilityProfileV1, TransportError, TransportPreSessionProfileV1,
        TransportProfileV1,
    },
};

/// Fail-closed errors while operating an authenticated peer transport.
#[derive(Debug, Error)]
pub enum AuthenticatedPeerTransportErrorV1 {
    /// A previous I/O/profile failure made the authenticated carrier unusable.
    #[error("authenticated peer transport is terminal")]
    Terminal,
    /// The exact transport profile changed after it was bound to the handshake.
    #[error("authenticated peer transport profile drifted from its bound profile")]
    TransportProfileDrift,
    /// The pre-session establishment profile changed after binding.
    #[error("authenticated peer pre-session profile drifted from its bound profile")]
    PreSessionProfileDrift,
    /// The authenticated availability/failure profile changed after binding.
    #[error("authenticated peer availability profile drifted from its bound profile")]
    AvailabilityProfileDrift,
    /// The local monotonic receive-evidence sequence cannot advance safely.
    #[error("authenticated peer receive evidence sequence exhausted")]
    ReceiveSequenceExhausted,
    /// Underlying carrier I/O failed. Xenia transport errors are session-fatal.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// One opaque carrier envelope successfully received from one exact
/// authenticated-peer transport wrapper instance.
///
/// This token proves **same-carrier receipt**, not successful xenia-wire AEAD
/// authentication or semantic decoding. Its bytes must still be opened through
/// the appropriate xenia-wire session/replay state before application code may
/// trust their contents.
///
/// The token is deliberately not `Clone`, `Copy`, serializable, or publicly
/// constructible. Its local binding nonce is private and can be checked only by
/// the [`AuthenticatedPeerTransportV1`] instance that minted it.
#[derive(Debug, PartialEq, Eq)]
pub struct PeerBoundInboundEnvelopeV1 {
    bytes: Vec<u8>,
    binding_nonce: [u8; 16],
    transcript_hash: [u8; 32],
    negotiated_context_hash: Option<[u8; 32]>,
    receive_sequence: u64,
    transport_profile: TransportProfileV1,
}

impl PeerBoundInboundEnvelopeV1 {
    /// Opaque carrier-envelope bytes received after the Xenia handshake.
    ///
    /// These bytes have not been authenticated or decoded by this layer.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact handshake transcript generation of the transport that received
    /// these opaque carrier bytes.
    pub const fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }

    /// Negotiated session-context commitment from the same handshake, when one
    /// was present.
    pub const fn negotiated_context_hash(&self) -> Option<[u8; 32]> {
        self.negotiated_context_hash
    }

    /// Process-local monotonic successful-receive index for this wrapper.
    pub const fn receive_sequence(&self) -> u64 {
        self.receive_sequence
    }

    /// Exact transport profile that remained stable across this receive.
    pub const fn transport_profile(&self) -> &TransportProfileV1 {
        &self.transport_profile
    }
}

/// Exact transport object bound by ownership to one authenticated peer
/// handshake.
///
/// This type intentionally exposes no raw `&mut T`, split operation, or
/// `into_transport` escape hatch. Once authority-bearing traffic begins, all
/// carrier I/O must pass through the profile checks and terminalization rules
/// here. Dropping the wrapper drops the owned transport.
///
/// The type does not claim that a carrier is perpetually live merely because
/// the wrapper exists. A successful [`Self::recv_peer_bound_envelope`] proves
/// only that opaque carrier bytes arrived through the same owned transport.
/// xenia-wire still owns cryptographic envelope authentication and replay
/// protection. Any transport error is terminal.
pub struct AuthenticatedPeerTransportV1<T: Transport> {
    transport: T,
    handshake: AuthenticatedPeerHandshakeV1,
    transport_profile: TransportProfileV1,
    pre_session_profile: TransportPreSessionProfileV1,
    availability_profile: TransportAvailabilityProfileV1,
    binding_nonce: [u8; 16],
    next_receive_sequence: u64,
    terminal: bool,
}

impl<T: Transport> AuthenticatedPeerTransportV1<T> {
    fn from_authenticated_transport(
        transport: T,
        handshake: AuthenticatedPeerHandshakeV1,
        transport_profile: TransportProfileV1,
        pre_session_profile: TransportPreSessionProfileV1,
        availability_profile: TransportAvailabilityProfileV1,
    ) -> Self {
        Self {
            transport,
            handshake,
            transport_profile,
            pre_session_profile,
            availability_profile,
            binding_nonce: random(),
            next_receive_sequence: 0,
            terminal: false,
        }
    }

    /// Sealed handshake evidence produced on this exact owned transport object.
    pub const fn handshake(&self) -> &AuthenticatedPeerHandshakeV1 {
        &self.handshake
    }

    /// Exact carrier profile captured before the handshake and rechecked after
    /// it completed.
    pub const fn bound_transport_profile(&self) -> &TransportProfileV1 {
        &self.transport_profile
    }

    /// Exact pre-session resource/deadline profile captured before handshake.
    pub const fn bound_pre_session_profile(&self) -> &TransportPreSessionProfileV1 {
        &self.pre_session_profile
    }

    /// Exact authenticated availability/failure profile captured before
    /// handshake.
    pub const fn bound_availability_profile(&self) -> &TransportAvailabilityProfileV1 {
        &self.availability_profile
    }

    /// Whether this wrapper has entered a terminal state after an I/O/profile
    /// failure.
    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Return whether an inbound carrier token was minted by this exact wrapper
    /// instance and handshake generation.
    pub fn owns_inbound_envelope(&self, envelope: &PeerBoundInboundEnvelopeV1) -> bool {
        envelope.binding_nonce == self.binding_nonce
            && envelope.transcript_hash == self.handshake.transcript_hash()
    }

    /// Send one already-sealed Xenia envelope through the bound transport.
    ///
    /// Any carrier error or profile drift terminalizes this wrapper before the
    /// error is returned. There is no retry API on the terminal wrapper.
    pub async fn send_envelope(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), AuthenticatedPeerTransportErrorV1> {
        self.ensure_active_profiles()?;
        if let Err(error) = self.transport.send_envelope(bytes).await {
            self.terminal = true;
            return Err(error.into());
        }
        self.ensure_active_profiles()
    }

    /// Receive one opaque carrier envelope through the exact transport that
    /// performed the authenticated handshake.
    ///
    /// Profile stability is checked both before and after I/O. Bytes are not
    /// released if the carrier profile changed while the receive was in flight.
    /// Any I/O/profile failure terminalizes the wrapper.
    ///
    /// The returned token does **not** mean the Xenia application envelope was
    /// cryptographically opened. Callers must still pass `bytes()` through the
    /// correct xenia-wire session/replay state before semantic authorization.
    pub async fn recv_peer_bound_envelope(
        &mut self,
    ) -> Result<PeerBoundInboundEnvelopeV1, AuthenticatedPeerTransportErrorV1> {
        self.ensure_active_profiles()?;
        let bytes = match self.transport.recv_envelope().await {
            Ok(bytes) => bytes,
            Err(error) => {
                self.terminal = true;
                return Err(error.into());
            }
        };
        self.ensure_active_profiles()?;

        let receive_sequence = self.next_receive_sequence;
        self.next_receive_sequence = match receive_sequence.checked_add(1) {
            Some(next) => next,
            None => {
                self.terminal = true;
                return Err(AuthenticatedPeerTransportErrorV1::ReceiveSequenceExhausted);
            }
        };

        Ok(PeerBoundInboundEnvelopeV1 {
            bytes,
            binding_nonce: self.binding_nonce,
            transcript_hash: self.handshake.transcript_hash(),
            negotiated_context_hash: self.handshake.negotiated_context_hash(),
            receive_sequence,
            transport_profile: self.transport_profile.clone(),
        })
    }

    fn ensure_active_profiles(&mut self) -> Result<(), AuthenticatedPeerTransportErrorV1> {
        if self.terminal {
            return Err(AuthenticatedPeerTransportErrorV1::Terminal);
        }
        if self.transport.transport_profile() != self.transport_profile {
            self.terminal = true;
            return Err(AuthenticatedPeerTransportErrorV1::TransportProfileDrift);
        }
        if self.transport.pre_session_profile() != self.pre_session_profile {
            self.terminal = true;
            return Err(AuthenticatedPeerTransportErrorV1::PreSessionProfileDrift);
        }
        if self.transport.availability_profile() != self.availability_profile {
            self.terminal = true;
            return Err(AuthenticatedPeerTransportErrorV1::AvailabilityProfileDrift);
        }
        Ok(())
    }

    #[cfg(test)]
    fn from_test_parts(
        transport: T,
        handshake: AuthenticatedPeerHandshakeV1,
        binding_nonce: [u8; 16],
    ) -> Self {
        let transport_profile = transport.transport_profile();
        let pre_session_profile = transport.pre_session_profile();
        let availability_profile = transport.availability_profile();
        let mut value = Self::from_authenticated_transport(
            transport,
            handshake,
            transport_profile,
            pre_session_profile,
            availability_profile,
        );
        value.binding_nonce = binding_nonce;
        value
    }
}

/// Perform the real host-side Xenia hybrid handshake while taking ownership of
/// the exact transport object used for it.
///
/// The transport, pre-session, and availability profiles are captured before
/// the handshake and must remain exactly equal after it completes. On success
/// the caller receives one opaque wrapper that owns both the carrier and the
/// sealed [`AuthenticatedPeerHandshakeV1`]. On failure the transport is dropped
/// with this function; no authority-bearing raw carrier is returned for reuse.
pub async fn perform_host_handshake_authenticated_transport_v1<T: Transport>(
    mut transport: T,
    manager: &mut HandshakeManager,
    peer_id: &str,
    negotiated_context_hash: Option<[u8; 32]>,
) -> Result<AuthenticatedPeerTransportV1<T>, Box<dyn std::error::Error>> {
    let transport_profile = transport.transport_profile();
    let pre_session_profile = transport.pre_session_profile();
    let availability_profile = transport.availability_profile();

    let handshake = perform_host_handshake_authenticated_peer_v1(
        &mut transport,
        manager,
        peer_id,
        negotiated_context_hash,
    )
    .await?;

    if transport.transport_profile() != transport_profile {
        return Err(Box::new(
            AuthenticatedPeerTransportErrorV1::TransportProfileDrift,
        ));
    }
    if transport.pre_session_profile() != pre_session_profile {
        return Err(Box::new(
            AuthenticatedPeerTransportErrorV1::PreSessionProfileDrift,
        ));
    }
    if transport.availability_profile() != availability_profile {
        return Err(Box::new(
            AuthenticatedPeerTransportErrorV1::AvailabilityProfileDrift,
        ));
    }

    Ok(AuthenticatedPeerTransportV1::from_authenticated_transport(
        transport,
        handshake,
        transport_profile,
        pre_session_profile,
        availability_profile,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::authenticated_peer_handshake::test_authenticated_peer_handshake_v1;
    use crate::transport::TransportKind;

    #[derive(Debug)]
    struct FakeTransport {
        profile: Arc<Mutex<TransportProfileV1>>,
        pre_session: TransportPreSessionProfileV1,
        availability: TransportAvailabilityProfileV1,
        inbound: VecDeque<Result<Vec<u8>, TransportError>>,
        fail_send: bool,
        drift_on_recv: bool,
    }

    impl FakeTransport {
        fn current() -> (Self, Arc<Mutex<TransportProfileV1>>) {
            let profile = Arc::new(Mutex::new(TransportProfileV1::current(TransportKind::Tcp)));
            (
                Self {
                    profile: profile.clone(),
                    pre_session: TransportPreSessionProfileV1::current(TransportKind::Tcp),
                    availability: TransportAvailabilityProfileV1::current(TransportKind::Tcp),
                    inbound: VecDeque::new(),
                    fail_send: false,
                    drift_on_recv: false,
                },
                profile,
            )
        }
    }

    impl Transport for FakeTransport {
        fn transport_profile(&self) -> TransportProfileV1 {
            self.profile.lock().unwrap().clone()
        }

        fn pre_session_profile(&self) -> TransportPreSessionProfileV1 {
            self.pre_session.clone()
        }

        fn availability_profile(&self) -> TransportAvailabilityProfileV1 {
            self.availability.clone()
        }

        async fn send_envelope(&mut self, _bytes: &[u8]) -> Result<(), TransportError> {
            if self.fail_send {
                Err(TransportError::UnexpectedEof)
            } else {
                Ok(())
            }
        }

        async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
            let result = self
                .inbound
                .pop_front()
                .unwrap_or(Err(TransportError::UnexpectedEof));
            if self.drift_on_recv {
                self.profile.lock().unwrap().protocol_version += 1;
            }
            result
        }
    }

    #[tokio::test]
    async fn successful_receive_mints_wrapper_bound_nonclone_carrier_evidence() {
        let (mut fake, _) = FakeTransport::current();
        fake.inbound.push_back(Ok(b"opaque-envelope".to_vec()));
        let mut transport = AuthenticatedPeerTransportV1::from_test_parts(
            fake,
            test_authenticated_peer_handshake_v1([0x11; 32]),
            [0xA1; 16],
        );

        let inbound = transport.recv_peer_bound_envelope().await.unwrap();
        assert_eq!(inbound.bytes(), b"opaque-envelope");
        assert_eq!(inbound.receive_sequence(), 0);
        assert_eq!(inbound.transcript_hash(), [0x11; 32]);
        assert!(transport.owns_inbound_envelope(&inbound));
        assert!(!transport.is_terminal());
    }

    #[tokio::test]
    async fn envelope_from_another_wrapper_is_not_owned_even_for_same_transcript() {
        let (mut first_fake, _) = FakeTransport::current();
        first_fake.inbound.push_back(Ok(b"opaque-envelope".to_vec()));
        let mut first = AuthenticatedPeerTransportV1::from_test_parts(
            first_fake,
            test_authenticated_peer_handshake_v1([0x22; 32]),
            [0xA1; 16],
        );
        let envelope = first.recv_peer_bound_envelope().await.unwrap();

        let (second_fake, _) = FakeTransport::current();
        let second = AuthenticatedPeerTransportV1::from_test_parts(
            second_fake,
            test_authenticated_peer_handshake_v1([0x22; 32]),
            [0xB2; 16],
        );

        assert!(!second.owns_inbound_envelope(&envelope));
    }

    #[tokio::test]
    async fn profile_drift_terminalizes_before_attempting_receive() {
        let (mut fake, profile) = FakeTransport::current();
        fake.inbound.push_back(Ok(b"must-not-release".to_vec()));
        let mut transport = AuthenticatedPeerTransportV1::from_test_parts(
            fake,
            test_authenticated_peer_handshake_v1([0x33; 32]),
            [0xC3; 16],
        );
        profile.lock().unwrap().protocol_version += 1;

        assert!(matches!(
            transport.recv_peer_bound_envelope().await,
            Err(AuthenticatedPeerTransportErrorV1::TransportProfileDrift)
        ));
        assert!(transport.is_terminal());
    }

    #[tokio::test]
    async fn profile_drift_during_receive_discards_returned_bytes_and_terminalizes() {
        let (mut fake, _) = FakeTransport::current();
        fake.inbound.push_back(Ok(b"must-not-release".to_vec()));
        fake.drift_on_recv = true;
        let mut transport = AuthenticatedPeerTransportV1::from_test_parts(
            fake,
            test_authenticated_peer_handshake_v1([0x34; 32]),
            [0xC4; 16],
        );

        assert!(matches!(
            transport.recv_peer_bound_envelope().await,
            Err(AuthenticatedPeerTransportErrorV1::TransportProfileDrift)
        ));
        assert!(transport.is_terminal());
        assert!(matches!(
            transport.recv_peer_bound_envelope().await,
            Err(AuthenticatedPeerTransportErrorV1::Terminal)
        ));
    }

    #[tokio::test]
    async fn receive_error_terminalizes_and_cannot_be_retried() {
        let (mut fake, _) = FakeTransport::current();
        fake.inbound.push_back(Err(TransportError::UnexpectedEof));
        fake.inbound.push_back(Ok(b"later".to_vec()));
        let mut transport = AuthenticatedPeerTransportV1::from_test_parts(
            fake,
            test_authenticated_peer_handshake_v1([0x44; 32]),
            [0xD4; 16],
        );

        assert!(matches!(
            transport.recv_peer_bound_envelope().await,
            Err(AuthenticatedPeerTransportErrorV1::Transport(
                TransportError::UnexpectedEof
            ))
        ));
        assert!(transport.is_terminal());
        assert!(matches!(
            transport.recv_peer_bound_envelope().await,
            Err(AuthenticatedPeerTransportErrorV1::Terminal)
        ));
    }

    #[tokio::test]
    async fn send_error_terminalizes_the_authority_bearing_transport() {
        let (mut fake, _) = FakeTransport::current();
        fake.fail_send = true;
        let mut transport = AuthenticatedPeerTransportV1::from_test_parts(
            fake,
            test_authenticated_peer_handshake_v1([0x55; 32]),
            [0xE5; 16],
        );

        assert!(matches!(
            transport.send_envelope(b"sealed").await,
            Err(AuthenticatedPeerTransportErrorV1::Transport(
                TransportError::UnexpectedEof
            ))
        ));
        assert!(transport.is_terminal());
    }
}
