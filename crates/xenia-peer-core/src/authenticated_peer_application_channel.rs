// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Same-peer, same-carrier, AEAD/replay-checked application channel.
//!
//! [`crate::AuthenticatedPeerTransportV1`] proves that opaque carrier bytes
//! arrived through the exact transport object that completed a hybrid Xenia
//! peer handshake. This module closes the next state-pairing gap by owning the
//! corresponding `xenia_wire::Session` beside that transport and by never
//! exposing either mutable state object separately.
//!
//! The channel is pinned to one Xenia application payload type. It checks that
//! cleartext nonce-domain byte before calling `xenia_wire::Session::open`, so a
//! wrong application domain cannot consume replay-window state through a typed
//! "try until something decodes" path.
//!
//! A successful receive proves carrier binding + AEAD authentication + replay
//! acceptance for the configured payload type. The returned plaintext is still
//! application data: callers must validate its own schema/semantics before
//! assigning higher-level authority.

use thiserror::Error;
use xenia_wire::{
    PAYLOAD_TYPE_APPLICATION_MIN, Session as WireSession, WireError, envelope_payload_type,
};

use crate::{
    AuthenticatedPeerHandshakeV1, AuthenticatedPeerTransportErrorV1, AuthenticatedPeerTransportV1,
    transport::{Transport, TransportProfileV1},
};

/// One Xenia application-range payload type admitted by an authenticated
/// application channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationPayloadTypeV1(u8);

impl ApplicationPayloadTypeV1 {
    /// Validate an application payload type.
    ///
    /// Xenia reserves `0x00..=0x2f`; application protocols own
    /// `0x30..=0xff`.
    pub const fn new(value: u8) -> Result<Self, AuthenticatedPeerApplicationChannelErrorV1> {
        if value < PAYLOAD_TYPE_APPLICATION_MIN {
            return Err(
                AuthenticatedPeerApplicationChannelErrorV1::ReservedPayloadType(value),
            );
        }
        Ok(Self(value))
    }

    /// Exact xenia-wire payload-type byte.
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for ApplicationPayloadTypeV1 {
    type Error = AuthenticatedPeerApplicationChannelErrorV1;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ApplicationPayloadTypeV1> for u8 {
    fn from(value: ApplicationPayloadTypeV1) -> Self {
        value.value()
    }
}

/// Fail-closed failures for an authenticated peer application channel.
#[derive(Debug, Error)]
pub enum AuthenticatedPeerApplicationChannelErrorV1 {
    /// Xenia core/extension payload types may not be claimed as application
    /// channel domains.
    #[error("payload type 0x{0:02x} is reserved by Xenia; application types start at 0x30")]
    ReservedPayloadType(u8),
    /// A previous carrier, wire, domain, or binding failure terminalized this
    /// channel.
    #[error("authenticated peer application channel is terminal")]
    Terminal,
    /// Carrier evidence returned by the owned transport failed its private
    /// same-wrapper ownership check. This is an internal invariant failure and
    /// is always terminal.
    #[error("peer-bound carrier evidence does not belong to the owned authenticated transport")]
    CarrierBindingMismatch,
    /// The sealed envelope declared a different payload domain (or was too
    /// short to declare one) than this channel admits.
    #[error("unexpected application payload type: expected 0x{expected:02x}, got {actual:?}")]
    UnexpectedPayloadType {
        /// Configured channel payload type.
        expected: u8,
        /// Cleartext payload-type byte when the envelope was long enough.
        actual: Option<u8>,
    },
    /// Same-carrier transport failed or its authenticated profile drifted.
    #[error(transparent)]
    Transport(#[from] AuthenticatedPeerTransportErrorV1),
    /// AEAD verification, replay acceptance, consent gating, or wire framing
    /// failed in xenia-wire.
    #[error(transparent)]
    Wire(#[from] WireError),
}

/// Plaintext released only after one peer-bound carrier envelope passed the
/// channel's exact payload-domain check and xenia-wire AEAD/replay validation.
///
/// The value is deliberately non-`Clone`, non-`Copy`, non-serializable, and
/// privately constructed. It is request evidence, not a durable bearer token.
/// Its existence does **not** assign a Mycelix principal, group membership, or
/// resource permission, and it does not validate the plaintext's application
/// schema.
///
/// The type intentionally does not implement `Debug`: authenticated plaintext
/// must not be dumped accidentally by generic debug logging.
#[derive(PartialEq, Eq)]
pub struct OpenedPeerApplicationPayloadV1 {
    plaintext: Vec<u8>,
    payload_type: ApplicationPayloadTypeV1,
    carrier_receive_sequence: u64,
    transcript_hash: [u8; 32],
    negotiated_context_hash: Option<[u8; 32]>,
    peer_ed25519_public_key: [u8; 32],
    peer_ml_dsa_65_public_key: Vec<u8>,
    transport_profile: TransportProfileV1,
}

impl OpenedPeerApplicationPayloadV1 {
    /// AEAD-authenticated, replay-accepted application plaintext.
    ///
    /// Higher layers must still decode and validate the expected application
    /// schema before using these bytes semantically.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// Exact application payload domain that passed the pre-open check.
    pub const fn payload_type(&self) -> ApplicationPayloadTypeV1 {
        self.payload_type
    }

    /// Process-local successful carrier-receive index from the owned transport.
    pub const fn carrier_receive_sequence(&self) -> u64 {
        self.carrier_receive_sequence
    }

    /// Exact hybrid handshake transcript generation bound to this receive.
    pub const fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }

    /// Negotiated authenticated context commitment, when present.
    pub const fn negotiated_context_hash(&self) -> Option<[u8; 32]> {
        self.negotiated_context_hash
    }

    /// Exact Ed25519 peer key authenticated by the same hybrid handshake.
    pub const fn peer_ed25519_public_key(&self) -> [u8; 32] {
        self.peer_ed25519_public_key
    }

    /// Exact ML-DSA-65 peer key authenticated by the same hybrid handshake.
    pub fn peer_ml_dsa_65_public_key(&self) -> &[u8] {
        &self.peer_ml_dsa_65_public_key
    }

    /// Exact transport profile that remained stable across carrier receipt.
    pub const fn transport_profile(&self) -> &TransportProfileV1 {
        &self.transport_profile
    }
}

/// One application-domain wire session structurally bound to an authenticated
/// peer transport.
///
/// Construction consumes [`AuthenticatedPeerTransportV1`]. The channel then
/// creates its own private xenia-wire session and installs the exact
/// `HandshakeOutcome::session_key` produced by that transport's handshake.
/// Xenia's handshake implementation defines that value as the transcript-bound
/// `key_schedule.aead` traffic key.
///
/// No raw transport, `WireSession`, arbitrary-payload seal/open, split, or
/// `install_key` surface is exposed. v1 intentionally has no public rekey
/// mutator; an authority-preserving long-lived rekey protocol is deferred to a
/// separately reviewed tranche.
pub struct AuthenticatedPeerApplicationChannelV1<T: Transport> {
    transport: AuthenticatedPeerTransportV1<T>,
    wire: WireSession,
    payload_type: ApplicationPayloadTypeV1,
    terminal: bool,
}

impl<T: Transport> AuthenticatedPeerApplicationChannelV1<T> {
    /// Consume an authenticated peer transport and bind one Xenia application
    /// payload domain to the handshake's exact existing AEAD traffic key.
    pub fn new(
        transport: AuthenticatedPeerTransportV1<T>,
        payload_type: ApplicationPayloadTypeV1,
    ) -> Self {
        let session_key = transport.handshake().outcome().session_key;
        let mut wire = WireSession::new();
        wire.install_key(session_key);
        Self {
            transport,
            wire,
            payload_type,
            terminal: false,
        }
    }

    /// Exact application payload domain accepted by this channel.
    pub const fn payload_type(&self) -> ApplicationPayloadTypeV1 {
        self.payload_type
    }

    /// Sealed hybrid peer-handshake evidence attached to this exact channel.
    pub const fn handshake(&self) -> &AuthenticatedPeerHandshakeV1 {
        self.transport.handshake()
    }

    /// Whether this application channel or its owned carrier has terminalized.
    pub const fn is_terminal(&self) -> bool {
        self.terminal || self.transport.is_terminal()
    }

    /// Seal application plaintext in the channel's one configured payload
    /// domain and send it through the same authenticated peer transport.
    ///
    /// Any wire or carrier failure terminalizes the channel. Callers cannot
    /// choose a second payload type through this object.
    pub async fn send_payload(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(), AuthenticatedPeerApplicationChannelErrorV1> {
        self.ensure_active()?;
        let sealed = match self.wire.seal(plaintext, self.payload_type.value()) {
            Ok(sealed) => sealed,
            Err(error) => {
                self.terminal = true;
                return Err(error.into());
            }
        };
        if let Err(error) = self.transport.send_envelope(&sealed).await {
            self.terminal = true;
            return Err(error.into());
        }
        Ok(())
    }

    /// Receive, domain-check, AEAD-open, and replay-check one application
    /// payload from the exact peer-bound carrier.
    ///
    /// The cleartext payload type is checked **before** `WireSession::open` so a
    /// wrong-domain envelope never mutates this channel's replay state. Any
    /// domain mismatch, AEAD/replay failure, carrier failure, or internal
    /// binding mismatch terminalizes the dedicated authority-bearing channel.
    pub async fn recv_opened_payload(
        &mut self,
    ) -> Result<OpenedPeerApplicationPayloadV1, AuthenticatedPeerApplicationChannelErrorV1> {
        self.ensure_active()?;
        let carrier = match self.transport.recv_peer_bound_envelope().await {
            Ok(carrier) => carrier,
            Err(error) => {
                self.terminal = true;
                return Err(error.into());
            }
        };
        if !self.transport.owns_inbound_envelope(&carrier) {
            self.terminal = true;
            return Err(AuthenticatedPeerApplicationChannelErrorV1::CarrierBindingMismatch);
        }

        let plaintext = match open_expected_payload(
            &mut self.wire,
            self.payload_type,
            carrier.bytes(),
        ) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                self.terminal = true;
                return Err(error);
            }
        };

        let handshake = self.transport.handshake();
        Ok(OpenedPeerApplicationPayloadV1 {
            plaintext,
            payload_type: self.payload_type,
            carrier_receive_sequence: carrier.receive_sequence(),
            transcript_hash: carrier.transcript_hash(),
            negotiated_context_hash: carrier.negotiated_context_hash(),
            peer_ed25519_public_key: handshake.peer_ed25519_public_key(),
            peer_ml_dsa_65_public_key: handshake.peer_ml_dsa_public_key().to_vec(),
            transport_profile: carrier.transport_profile().clone(),
        })
    }

    fn ensure_active(&mut self) -> Result<(), AuthenticatedPeerApplicationChannelErrorV1> {
        if self.terminal || self.transport.is_terminal() {
            self.terminal = true;
            return Err(AuthenticatedPeerApplicationChannelErrorV1::Terminal);
        }
        Ok(())
    }
}

fn open_expected_payload(
    wire: &mut WireSession,
    expected: ApplicationPayloadTypeV1,
    envelope: &[u8],
) -> Result<Vec<u8>, AuthenticatedPeerApplicationChannelErrorV1> {
    let actual = envelope_payload_type(envelope);
    if actual != Some(expected.value()) {
        return Err(
            AuthenticatedPeerApplicationChannelErrorV1::UnexpectedPayloadType {
                expected: expected.value(),
                actual,
            },
        );
    }
    wire.open(envelope).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paired_wire_sessions() -> (WireSession, WireSession) {
        let key = [0xA5; 32];
        let mut sender = WireSession::with_source_id([0x11; 8], 0x22);
        let mut receiver = WireSession::with_source_id([0x33; 8], 0x44);
        sender.install_key(key);
        receiver.install_key(key);
        (sender, receiver)
    }

    #[test]
    fn application_payload_type_rejects_xenia_reserved_ranges() {
        assert!(matches!(
            ApplicationPayloadTypeV1::new(PAYLOAD_TYPE_APPLICATION_MIN - 1),
            Err(AuthenticatedPeerApplicationChannelErrorV1::ReservedPayloadType(_))
        ));
        assert_eq!(
            ApplicationPayloadTypeV1::new(PAYLOAD_TYPE_APPLICATION_MIN)
                .unwrap()
                .value(),
            PAYLOAD_TYPE_APPLICATION_MIN
        );
        assert_eq!(ApplicationPayloadTypeV1::new(u8::MAX).unwrap().value(), u8::MAX);
    }

    #[test]
    fn wrong_domain_is_rejected_before_replay_state_is_consumed() {
        let (mut sender, mut receiver) = paired_wire_sessions();
        let expected = ApplicationPayloadTypeV1::new(0x30).unwrap();
        let actual = ApplicationPayloadTypeV1::new(0x31).unwrap();
        let sealed = sender.seal(b"domain-separated", actual.value()).unwrap();

        assert!(matches!(
            open_expected_payload(&mut receiver, expected, &sealed),
            Err(
                AuthenticatedPeerApplicationChannelErrorV1::UnexpectedPayloadType {
                    expected: 0x30,
                    actual: Some(0x31),
                }
            )
        ));

        // The rejected pre-open domain check did not advance replay state.
        assert_eq!(
            open_expected_payload(&mut receiver, actual, &sealed).unwrap(),
            b"domain-separated"
        );
    }

    #[test]
    fn successful_open_consumes_replay_state_exactly_once() {
        let (mut sender, mut receiver) = paired_wire_sessions();
        let payload_type = ApplicationPayloadTypeV1::new(0x30).unwrap();
        let sealed = sender.seal(b"once", payload_type.value()).unwrap();

        assert_eq!(
            open_expected_payload(&mut receiver, payload_type, &sealed).unwrap(),
            b"once"
        );
        assert!(matches!(
            open_expected_payload(&mut receiver, payload_type, &sealed),
            Err(AuthenticatedPeerApplicationChannelErrorV1::Wire(_))
        ));
    }

    #[test]
    fn aead_tampering_fails_closed() {
        let (mut sender, mut receiver) = paired_wire_sessions();
        let payload_type = ApplicationPayloadTypeV1::new(0x30).unwrap();
        let mut sealed = sender.seal(b"authenticated", payload_type.value()).unwrap();
        let last = sealed.last_mut().unwrap();
        *last ^= 0x01;

        assert!(matches!(
            open_expected_payload(&mut receiver, payload_type, &sealed),
            Err(AuthenticatedPeerApplicationChannelErrorV1::Wire(_))
        ));
    }

    #[test]
    fn short_envelope_fails_domain_check_before_wire_open() {
        let (_, mut receiver) = paired_wire_sessions();
        let payload_type = ApplicationPayloadTypeV1::new(0x30).unwrap();
        assert!(matches!(
            open_expected_payload(&mut receiver, payload_type, &[0u8; 4]),
            Err(
                AuthenticatedPeerApplicationChannelErrorV1::UnexpectedPayloadType {
                    expected: 0x30,
                    actual: None,
                }
            )
        ));
    }
}
