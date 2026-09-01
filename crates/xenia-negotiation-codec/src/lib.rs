// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bounded canonical byte codec for untrusted Xenia capability negotiation.
//!
//! `xenia-negotiation` owns valid semantic protocol state. This crate owns the
//! hostile-byte boundary used when a peer sends an offer or selected context.
//! Decoding is intentionally stricter than "can be parsed": accepted bytes must
//! also be the exact canonical encoding of the decoded value. Inputs with
//! reordered capability names, duplicates, truncation, oversized counts,
//! malformed lengths, or trailing bytes fail closed.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use xenia_negotiation::{
    CAPABILITY_OFFER_V1_DOMAIN, MAX_CAPABILITY_NAME_BYTES, MAX_CAPABILITY_VERSION_BYTES,
    MAX_CAPABILITY_VERSIONS_PER_NAME, MAX_NEGOTIATED_CAPABILITIES, NEGOTIATED_CONTEXT_V1_DOMAIN,
    CapabilityOfferEntryV1, CapabilityOfferV1, NegotiatedCapabilityV1, NegotiatedContextError,
    NegotiatedContextV1,
};

/// Failure while decoding or validating canonical negotiation bytes.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NegotiationCodecError {
    /// Input ended before a declared field was complete.
    #[error("truncated negotiation encoding")]
    Truncated,
    /// The domain prefix does not identify the expected canonical object.
    #[error("invalid negotiation encoding domain")]
    InvalidDomain,
    /// Bytes remain after the canonical object is complete.
    #[error("trailing bytes after canonical negotiation object")]
    TrailingBytes,
    /// The bytes parse to valid semantic state but are not its canonical encoding.
    #[error("negotiation encoding is not canonical")]
    NonCanonicalEncoding,
    /// Semantic bounds or uniqueness rules were violated.
    #[error(transparent)]
    Semantic(#[from] NegotiatedContextError),
}

/// Encode one canonical peer capability offer.
pub fn encode_capability_offer(offer: &CapabilityOfferV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(CAPABILITY_OFFER_V1_DOMAIN.len() + 4 + 64);
    out.extend_from_slice(CAPABILITY_OFFER_V1_DOMAIN);
    out.extend_from_slice(
        &u32::try_from(offer.entries().len())
            .expect("capability count is protocol-bounded below u32::MAX")
            .to_be_bytes(),
    );
    for entry in offer.entries() {
        push_len_prefixed(&mut out, entry.name());
        out.extend_from_slice(
            &u16::try_from(entry.versions_by_preference().len())
                .expect("version count is protocol-bounded below u16::MAX")
                .to_be_bytes(),
        );
        for version in entry.versions_by_preference() {
            push_len_prefixed(&mut out, version);
        }
    }
    out
}

/// Decode a peer capability offer and require its exact canonical byte form.
///
/// Capability-name order must already be canonical on the wire. The semantic
/// constructor canonicalizes local values for convenience, so the decoder
/// round-trips the parsed value and compares bytes to prevent a peer from using
/// alternate encodings for the same semantic offer.
pub fn decode_capability_offer(bytes: &[u8]) -> Result<CapabilityOfferV1, NegotiationCodecError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(CAPABILITY_OFFER_V1_DOMAIN.len())? != CAPABILITY_OFFER_V1_DOMAIN {
        return Err(NegotiationCodecError::InvalidDomain);
    }

    let count = cursor.read_u32()?;
    if count > MAX_NEGOTIATED_CAPABILITIES as u32 {
        return Err(NegotiatedContextError::TooManyCapabilities.into());
    }

    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name_len = cursor.read_u16()? as usize;
        validate_name_len(name_len)?;
        let name = cursor.take(name_len)?.to_vec();

        let version_count = cursor.read_u16()?;
        if version_count == 0 {
            return Err(NegotiatedContextError::EmptyCapabilityVersions.into());
        }
        if version_count > MAX_CAPABILITY_VERSIONS_PER_NAME as u16 {
            return Err(NegotiatedContextError::TooManyCapabilityVersions.into());
        }

        let mut versions = Vec::with_capacity(version_count as usize);
        for _ in 0..version_count {
            let version_len = cursor.read_u16()? as usize;
            validate_version_len(version_len)?;
            versions.push(cursor.take(version_len)?.to_vec());
        }
        entries.push(CapabilityOfferEntryV1::new(name, versions)?);
    }

    if !cursor.is_empty() {
        return Err(NegotiationCodecError::TrailingBytes);
    }

    let offer = CapabilityOfferV1::from_entries(entries)?;
    if encode_capability_offer(&offer) != bytes {
        return Err(NegotiationCodecError::NonCanonicalEncoding);
    }
    Ok(offer)
}

/// Encode one canonical deterministic selected capability context.
pub fn encode_negotiated_context(context: &NegotiatedContextV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(NEGOTIATED_CONTEXT_V1_DOMAIN.len() + 4 + 64);
    out.extend_from_slice(NEGOTIATED_CONTEXT_V1_DOMAIN);
    out.extend_from_slice(
        &u32::try_from(context.capabilities().len())
            .expect("capability count is protocol-bounded below u32::MAX")
            .to_be_bytes(),
    );
    for capability in context.capabilities() {
        push_len_prefixed(&mut out, capability.name());
        push_len_prefixed(&mut out, capability.version());
    }
    out
}

/// Decode a selected capability context and require its exact canonical bytes.
pub fn decode_negotiated_context(
    bytes: &[u8],
) -> Result<NegotiatedContextV1, NegotiationCodecError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(NEGOTIATED_CONTEXT_V1_DOMAIN.len())? != NEGOTIATED_CONTEXT_V1_DOMAIN {
        return Err(NegotiationCodecError::InvalidDomain);
    }

    let count = cursor.read_u32()?;
    if count > MAX_NEGOTIATED_CAPABILITIES as u32 {
        return Err(NegotiatedContextError::TooManyCapabilities.into());
    }

    let mut selected = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name_len = cursor.read_u16()? as usize;
        validate_name_len(name_len)?;
        let name = cursor.take(name_len)?.to_vec();
        let version_len = cursor.read_u16()? as usize;
        validate_version_len(version_len)?;
        let version = cursor.take(version_len)?.to_vec();
        selected.push(NegotiatedCapabilityV1::new(name, version)?);
    }

    if !cursor.is_empty() {
        return Err(NegotiationCodecError::TrailingBytes);
    }

    let context = NegotiatedContextV1::from_capabilities(selected)?;
    if encode_negotiated_context(&context) != bytes {
        return Err(NegotiationCodecError::NonCanonicalEncoding);
    }
    Ok(context)
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &u16::try_from(bytes.len())
            .expect("capability component is protocol-bounded below u16::MAX")
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
}

fn validate_name_len(len: usize) -> Result<(), NegotiationCodecError> {
    if len == 0 {
        return Err(NegotiatedContextError::EmptyCapabilityName.into());
    }
    if len > MAX_CAPABILITY_NAME_BYTES {
        return Err(NegotiatedContextError::CapabilityNameTooLong.into());
    }
    Ok(())
}

fn validate_version_len(len: usize) -> Result<(), NegotiationCodecError> {
    if len == 0 {
        return Err(NegotiatedContextError::EmptyCapabilityVersion.into());
    }
    if len > MAX_CAPABILITY_VERSION_BYTES {
        return Err(NegotiatedContextError::CapabilityVersionTooLong.into());
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], NegotiationCodecError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(NegotiationCodecError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(NegotiationCodecError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16, NegotiationCodecError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| NegotiationCodecError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, NegotiationCodecError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| NegotiationCodecError::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenia_negotiation::{
        causal_authority_draft04_capability, causal_authority_draft04_offer_entry,
    };

    fn offer_entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
        CapabilityOfferEntryV1::new(
            name.to_vec(),
            versions.iter().map(|version| version.to_vec()),
        )
        .unwrap()
    }

    fn raw_offer(entries: &[(&[u8], &[&[u8]])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CAPABILITY_OFFER_V1_DOMAIN);
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (name, versions) in entries {
            push_len_prefixed(&mut out, name);
            out.extend_from_slice(&(versions.len() as u16).to_be_bytes());
            for version in *versions {
                push_len_prefixed(&mut out, version);
            }
        }
        out
    }

    fn raw_selected(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(NEGOTIATED_CONTEXT_V1_DOMAIN);
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (name, version) in entries {
            push_len_prefixed(&mut out, name);
            push_len_prefixed(&mut out, version);
        }
        out
    }

    #[test]
    fn canonical_offer_round_trips() {
        let offer = CapabilityOfferV1::from_entries([
            causal_authority_draft04_offer_entry(),
            offer_entry(b"xenia.operator-rekey", &[b"v1"]),
        ])
        .unwrap();
        let bytes = encode_capability_offer(&offer);
        assert_eq!(decode_capability_offer(&bytes).unwrap(), offer);
    }

    #[test]
    fn canonical_selected_context_round_trips() {
        let context = NegotiatedContextV1::from_capabilities([
            causal_authority_draft04_capability(),
            NegotiatedCapabilityV1::new(b"xenia.operator-rekey".to_vec(), b"v1".to_vec())
                .unwrap(),
        ])
        .unwrap();
        let bytes = encode_negotiated_context(&context);
        assert_eq!(decode_negotiated_context(&bytes).unwrap(), context);
    }

    #[test]
    fn out_of_order_offer_is_valid_semantics_but_rejected_as_noncanonical_bytes() {
        let bytes = raw_offer(&[
            (b"xenia.operator-rekey", &[b"v1"]),
            (b"xenia.causal-authority", &[b"draft-04"]),
        ]);
        assert_eq!(
            decode_capability_offer(&bytes).unwrap_err(),
            NegotiationCodecError::NonCanonicalEncoding
        );
    }

    #[test]
    fn out_of_order_selected_context_is_rejected_as_noncanonical_bytes() {
        let bytes = raw_selected(&[
            (b"xenia.operator-rekey", b"v1"),
            (b"xenia.causal-authority", b"draft-04"),
        ]);
        assert_eq!(
            decode_negotiated_context(&bytes).unwrap_err(),
            NegotiationCodecError::NonCanonicalEncoding
        );
    }

    #[test]
    fn duplicate_name_and_duplicate_version_fail_closed() {
        let duplicate_name = raw_offer(&[
            (b"xenia.causal-authority", &[b"draft-04"]),
            (b"xenia.causal-authority", &[b"draft-03"]),
        ]);
        assert!(matches!(
            decode_capability_offer(&duplicate_name),
            Err(NegotiationCodecError::Semantic(
                NegotiatedContextError::DuplicateCapabilityName
            ))
        ));

        let duplicate_version = raw_offer(&[(
            b"xenia.causal-authority",
            &[b"draft-04", b"draft-04"],
        )]);
        assert!(matches!(
            decode_capability_offer(&duplicate_version),
            Err(NegotiationCodecError::Semantic(
                NegotiatedContextError::DuplicateOfferedVersion
            ))
        ));
    }

    #[test]
    fn trailing_and_truncated_bytes_fail_closed() {
        let offer = CapabilityOfferV1::from_entries([causal_authority_draft04_offer_entry()]).unwrap();
        let mut trailing = encode_capability_offer(&offer);
        trailing.push(0xA5);
        assert_eq!(
            decode_capability_offer(&trailing).unwrap_err(),
            NegotiationCodecError::TrailingBytes
        );

        let mut truncated = encode_capability_offer(&offer);
        truncated.pop();
        assert_eq!(
            decode_capability_offer(&truncated).unwrap_err(),
            NegotiationCodecError::Truncated
        );
    }

    #[test]
    fn invalid_domain_fails_before_semantic_parsing() {
        let offer = CapabilityOfferV1::from_entries([causal_authority_draft04_offer_entry()]).unwrap();
        let mut bytes = encode_capability_offer(&offer);
        bytes[0] ^= 0x01;
        assert_eq!(
            decode_capability_offer(&bytes).unwrap_err(),
            NegotiationCodecError::InvalidDomain
        );
    }

    #[test]
    fn declared_counts_are_bounded_before_allocation_or_iteration() {
        let mut too_many_names = CAPABILITY_OFFER_V1_DOMAIN.to_vec();
        too_many_names.extend_from_slice(&((MAX_NEGOTIATED_CAPABILITIES as u32) + 1).to_be_bytes());
        assert!(matches!(
            decode_capability_offer(&too_many_names),
            Err(NegotiationCodecError::Semantic(
                NegotiatedContextError::TooManyCapabilities
            ))
        ));

        let mut too_many_versions = CAPABILITY_OFFER_V1_DOMAIN.to_vec();
        too_many_versions.extend_from_slice(&1u32.to_be_bytes());
        push_len_prefixed(&mut too_many_versions, b"xenia.test");
        too_many_versions.extend_from_slice(
            &((MAX_CAPABILITY_VERSIONS_PER_NAME as u16) + 1).to_be_bytes(),
        );
        assert!(matches!(
            decode_capability_offer(&too_many_versions),
            Err(NegotiationCodecError::Semantic(
                NegotiatedContextError::TooManyCapabilityVersions
            ))
        ));
    }

    #[test]
    fn component_lengths_are_rejected_before_copying() {
        let mut empty_name = CAPABILITY_OFFER_V1_DOMAIN.to_vec();
        empty_name.extend_from_slice(&1u32.to_be_bytes());
        empty_name.extend_from_slice(&0u16.to_be_bytes());
        assert!(matches!(
            decode_capability_offer(&empty_name),
            Err(NegotiationCodecError::Semantic(
                NegotiatedContextError::EmptyCapabilityName
            ))
        ));

        let mut oversized_name = CAPABILITY_OFFER_V1_DOMAIN.to_vec();
        oversized_name.extend_from_slice(&1u32.to_be_bytes());
        oversized_name.extend_from_slice(&((MAX_CAPABILITY_NAME_BYTES as u16) + 1).to_be_bytes());
        assert!(matches!(
            decode_capability_offer(&oversized_name),
            Err(NegotiationCodecError::Semantic(
                NegotiatedContextError::CapabilityNameTooLong
            ))
        ));
    }
}
