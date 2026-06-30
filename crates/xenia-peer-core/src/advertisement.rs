// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Pre-handshake transport discovery.
//!
//! This module intentionally lives below the cryptographic session
//! handshake. It only advertises alternate connection paths; it does
//! not authenticate the peer or establish trust.

use serde::{Deserialize, Serialize};

const MAGIC: &[u8] = b"XENIA_TRANSPORT_ADVERTISEMENT_V1\0";

/// Transport families a daemon can advertise before the session
/// handshake starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvertisedTransport {
    /// Raw TCP length-prefixed envelopes.
    Tcp,
    /// Binary WebSocket envelopes.
    WebSocket,
    /// Iroh QUIC bidirectional stream envelopes.
    Quic,
}

/// Audio codecs a daemon can advertise before the session handshake starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvertisedAudioCodec {
    /// Raw 48 kHz S16LE PCM inside RawAudio.
    RawPcm,
    /// Opus packets inside RawAudio timing metadata.
    Opus,
}

/// Non-secret audio lane capabilities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioAdvertisement {
    /// Supported audio codecs.
    pub codecs: Vec<AdvertisedAudioCodec>,
    /// Daemon-selected codec for this session.
    pub selected_codec: AdvertisedAudioCodec,
    /// Audio lane sample rate in Hz.
    pub sample_rate_hz: u32,
    /// Maximum supported channel count.
    pub max_channels: u16,
    /// Supported frame durations in milliseconds.
    pub frame_duration_ms: Vec<u16>,
}

/// A daemon-side transport advertisement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportAdvertisement {
    /// Supported transport families.
    pub transports: Vec<AdvertisedTransport>,
    /// Optional Iroh endpoint address encoded for CLI use.
    pub quic_connect: Option<String>,
    /// Optional audio lane capabilities.
    pub audio: Option<AudioAdvertisement>,
}

impl TransportAdvertisement {
    /// Build the standard auto-mode advertisement.
    pub fn auto(quic_connect: String) -> Self {
        Self {
            transports: vec![
                AdvertisedTransport::Tcp,
                AdvertisedTransport::WebSocket,
                AdvertisedTransport::Quic,
            ],
            quic_connect: Some(quic_connect),
            audio: None,
        }
    }

    /// Attach audio lane capabilities.
    pub fn with_audio(mut self, audio: AudioAdvertisement) -> Self {
        self.audio = Some(audio);
        self
    }

    /// Encode as a magic-prefixed envelope payload.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        let mut out = Vec::with_capacity(MAGIC.len() + 128);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&bincode::serialize(self)?);
        Ok(out)
    }

    /// Decode a magic-prefixed advertisement payload.
    ///
    /// Returns `Ok(None)` when the payload is not an advertisement.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, bincode::Error> {
        let Some(payload) = bytes.strip_prefix(MAGIC) else {
            return Ok(None);
        };
        bincode::deserialize(payload).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement_round_trips_with_magic_prefix() {
        let advert =
            TransportAdvertisement::auto("iroh:test".to_string()).with_audio(AudioAdvertisement {
                codecs: vec![AdvertisedAudioCodec::RawPcm, AdvertisedAudioCodec::Opus],
                selected_codec: AdvertisedAudioCodec::Opus,
                sample_rate_hz: 48_000,
                max_channels: 2,
                frame_duration_ms: vec![10, 20],
            });
        let bytes = advert.encode().unwrap();
        assert!(bytes.starts_with(MAGIC));
        assert_eq!(
            TransportAdvertisement::decode(&bytes).unwrap(),
            Some(advert)
        );
    }

    #[test]
    fn non_advertisement_payload_is_ignored() {
        assert_eq!(
            TransportAdvertisement::decode(b"not an advertisement").unwrap(),
            None
        );
    }
}
