// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// License exception: this crate is AGPL-3.0-or-later, unlike its sibling
// library crates in the xenia-peer workspace (xenia-peer-core, xenia-
// capture, xenia-handshake, xenia-inject) which ship under Apache-2.0 OR
// MIT per ADR-001 Decision 3. The exception is deliberate — xenia-ledger
// is the cryptographic moat of the Mycelix Sovereign commercial suite and
// is treated as application-layer rather than permissive-commons
// infrastructure. See README.md for the full rationale.

//! # xenia-ledger
//!
//! Append-only, hash-chained consent ledger with explicit signature-envelope agility.
//!
//! Every privileged session that flows through a Xenia peer produces a
//! sequence of [`ConsentEventRecord`]s (Request, Approval, Denial,
//! Revocation, Violation). Those records are appended to a
//! [`Chain`], which computes a blake3-based hash link to the previous
//! entry and signs the resulting `entry_hash` with the operator's
//! Ed25519 signing key. The current in-memory entry shape remains Ed25519-only,
//! but exported evidence can carry a tagged [`SignatureEnvelope`] so downstream
//! verifiers can distinguish today's hybrid/pre-PQC posture from future
//! ML-DSA/SLH-DSA ledger profiles without another schema break.
//! [`Verifier::verify_evidence_bundle`] then binds the declared manifest to
//! the exported chain so an artifact cannot claim a stronger ledger signature
//! suite than its entry envelopes actually use.
//! [`Verifier::verify_transcript_bound_evidence_bundle`] additionally binds
//! the ledger to a stable session-transcript hash so a valid consent chain
//! cannot be replayed beside the wrong handshake or session transcript.
//!
//! Reciprocal-accountability callers can additionally use
//! [`AccountabilityExecutionBinding`] and [`AccountabilityExecutionAttestation`]
//! to bind a higher-layer access receipt to the authenticated session and
//! current signed-ledger frontier without placing citizen/case identifiers in
//! the Xenia ledger itself. [`verify_accountability_execution_for_expectation`]
//! then closes the adapter boundary by requiring the signed binding to match the
//! exact higher-layer receipt/query/purpose/policy/result commitments.
//!
//! A witnessed Mycelix bundle crosses the runtime trust boundary through
//! [`SifReleaseCredential`]. [`verify_release_credential`] authenticates configured
//! release-authority roots and trust domains, then
//! [`bind_release_credential_to_execution`] proves that credential names the exact
//! Xenia execution — including its semantic policy — before the disclosure layer can
//! consume it.
//!
//! The release layer uses [`AccountabilityDisclosurePermit`], but the permit is not
//! itself a release token. The public [`DisclosureReleaseState`] is a CAS-enforced
//! wrapper: every Commit/Outcome transition must atomically compare the durable
//! [`DisclosureReleaseFrontier`] before persistence. Only a successful durable Commit
//! returns the move-only [`CommittedDisclosurePermit`].
//!
//! For bounded outbound files, [`CommittedFileDisclosure`] consumes that generic
//! permit only when [`sif_file_result_digest`] matches the exact wire-visible filename,
//! byte length, and BLAKE3 content hash. Successful carrier sends are accounted exactly;
//! an ambiguous carrier failure can instead be conservatively charged as an upper bound
//! through [`CommittedFileDisclosure::note_transport_uncertain`]. The local terminal
//! artifact exposes [`FileDisclosureByteAccounting`] so audit code never has to pretend
//! such a Partial count is exact.
//!
//! [`SifProtectedFileOffer`] defines the semantic live-transfer boundary above that
//! durable Commit. The Offer binds the single-use release ID, signed release-entry hash,
//! canonical file result and exact wire metadata; every response/chunk/completion binds
//! the Offer digest. [`SifProtectedFileReceiver`] then enforces one contiguous content
//! stream and whole-file verification before producing typed receiver observations.
//! Transport integration must carry these objects under a dedicated authenticated
//! payload type rather than treating legacy transfer messages as SIF.
//!
//! Receiver-side custody is a separate claim. [`SifDeliveryReceipt`] is the historical
//! v1 statement binding release/session/file custody. [`SifDeliveryReceiptV2`] retains
//! that exact validated statement and additionally signs the authenticated SIF profile
//! digest, allowing independent archives to prove which negotiated security contract
//! governed the movement. Verifiers must still supply the trusted receiver key and an
//! explicit sender-owned expectation; neither receipt version self-authorizes its signer.
//!
//! A downstream auditor — including a non-operator third party —
//! can use [`Verifier::verify_chain`] to reconstruct every hash link
//! and every signature offline, using only the operator's public key.
//! The operator cannot produce a chain with a rewritten past unless
//! they also re-sign every affected entry, which requires the
//! private key and is by construction visible to anyone holding the
//! public key.
//! This is the "admin cannot rewrite the audit log" claim made in the
//! Mycelix Sovereign threat model, enforced cryptographically.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

mod accountability;
mod accountability_interop;
mod archive;
mod binding;
mod chain;
mod checkpoint;
mod compaction;
mod delivery_receipt;
mod delivery_receipt_v2;
mod disclosure_v2;
mod entry;
mod errors;
mod file_disclosure;
mod hash;
mod key_transition;
mod policy;
mod protected_file_protocol;
mod protected_file_receiver;
mod release_cas;
mod release_credential;
mod seal;
mod signature;
mod verify;
mod witness;

#[cfg(test)]
mod tests;

pub use accountability::{
    ACCOUNTABILITY_COMMITMENT_ALGORITHM, ACCOUNTABILITY_EXECUTION_ATTESTATION_SCHEMA,
    ACCOUNTABILITY_EXECUTION_BINDING_SCHEMA, AccountabilityBindingError,
    AccountabilityExecutionAttestation, AccountabilityExecutionBinding,
    AccountabilityExecutionPhase, accountability_execution_binding_digest,
    accountability_execution_message, sign_accountability_execution_ed25519,
};
#[cfg(feature = "pqc-signatures")]
pub use accountability::{
    sign_accountability_execution_ml_dsa_65, sign_accountability_execution_ml_dsa_87,
};
pub use accountability_interop::{
    AccountabilityExecutionExpectation, AccountabilityInteropError,
    VerifiedAccountabilityExecutionRef, accountability_execution_scheme,
    accountability_verifier_key_id, verify_accountability_execution_for_expectation,
};

pub use archive::{
    LEDGER_ARCHIVE_SEGMENT_SCHEMA, LedgerArchiveError, LedgerArchiveSegment,
    MAX_LEDGER_ARCHIVE_SEGMENT_ENTRIES, MAX_LEDGER_ARCHIVE_SEQUENCE_SEGMENTS,
    ledger_archive_segment_digest, ledger_archive_sequence_digest,
};

pub use binding::{
    EVIDENCE_PUBLIC_KEY_BINDING_SCHEMA, EVIDENCE_PUBLIC_KEY_FINGERPRINT_ALGORITHM,
    EvidencePublicKeyBinding, EvidencePublicKeyBindingError, SESSION_TRANSCRIPT_BINDING_SCHEMA,
    SESSION_TRANSCRIPT_HASH_ALGORITHM, SESSION_TRANSCRIPT_SIGNATURE_SCHEMA,
    SessionTranscriptBinding, SessionTranscriptSignature, compute_evidence_public_key_fingerprint,
    session_transcript_signature_message, sign_session_transcript_binding_ed25519,
};
#[cfg(feature = "pqc-signatures")]
pub use binding::{
    sign_session_transcript_binding_ml_dsa_65, sign_session_transcript_binding_ml_dsa_87,
};

pub use chain::Chain;

pub use checkpoint::{
    CheckpointContinuityError, CheckpointError, CheckpointFreshnessPolicy,
    LEDGER_CHECKPOINT_SCHEMA, LedgerCheckpoint, checkpoint_fingerprint, checkpoint_message,
};

pub use compaction::{
    LEDGER_COMPACTION_MANIFEST_SCHEMA, LedgerCompactionError, LedgerCompactionManifest,
    ledger_compaction_manifest_message,
};

pub use delivery_receipt::{
    SIF_DELIVERY_RECEIPT_COMMITMENT_ALGORITHM, SIF_DELIVERY_RECEIPT_SCHEMA,
    SifDeliveryDisposition, SifDeliveryReceipt, SifDeliveryReceiptBinding,
    SifDeliveryReceiptError, SifDeliveryReceiptExpectation, sif_delivery_receipt_digest,
    sif_delivery_receipt_message, sif_delivery_receiver_key_id,
    sign_sif_delivery_receipt_ed25519,
};
pub use delivery_receipt_v2::{
    SIF_DELIVERY_RECEIPT_V2_COMMITMENT_ALGORITHM, SIF_DELIVERY_RECEIPT_V2_SCHEMA,
    SifDeliveryReceiptBindingV2, SifDeliveryReceiptExpectationV2, SifDeliveryReceiptV2,
    SifDeliveryReceiptV2Error, sif_delivery_receipt_v2_digest,
    sif_delivery_receipt_v2_message, sign_sif_delivery_receipt_v2_ed25519,
};

pub use disclosure_v2::{
    ACCOUNTABILITY_DISCLOSURE_BINDING_SCHEMA, ACCOUNTABILITY_DISCLOSURE_COMMITMENT_ALGORITHM,
    ACCOUNTABILITY_DISCLOSURE_PERMIT_SCHEMA, ACCOUNTABILITY_RELEASE_ENTRY_SCHEMA,
    AccountabilityDisclosureBinding, AccountabilityDisclosureError, AccountabilityDisclosurePermit,
    AccountabilityDisclosurePhase, CommittedDisclosurePermit, DisclosureReleaseEntry,
    DisclosureReleaseEvent, DisclosureReleaseOutcome, TransactionalDisclosureError,
    accountability_disclosure_message, accountability_disclosure_permit_digest,
    verify_disclosure_release_entries,
};

pub use entry::{
    ConsentEventRecord, ConsentKind, LedgerEntry, LedgerEntryExport, TranscriptBindingError,
    TranscriptSignatureError, compute_session_transcript_hash,
};
#[cfg(feature = "pqc-signatures")]
pub use entry::{
    MlDsa65EvidenceChain, MlDsa87EvidenceChain, MlDsaEvidenceChain, new_ml_dsa_65_evidence_chain,
    new_ml_dsa_87_evidence_chain,
};

pub use errors::{EvidenceBundleVerifyError, LedgerError, TransactionalAppendError, VerifyError};

pub use file_disclosure::{
    CommittedFileDisclosure, FileDisclosureByteAccounting, FileDisclosureError,
    FileDisclosureTerminal, SIF_FILE_RESULT_PROFILE, sif_file_result_digest,
};

pub use key_transition::{
    LEDGER_KEY_TRANSITION_SCHEMA, LedgerKeyTransition, LedgerKeyTransitionError,
    ledger_key_transition_message,
};

pub use policy::{
    CURRENT_EVIDENCE_CRYPTO_MANIFEST, CURRENT_LEDGER_EVIDENCE_PROFILE, CryptoPolicyProfile,
    DowngradePolicy, EvidenceCryptoManifest, EvidencePolicyError, LedgerEvidenceProfile,
};

pub use protected_file_protocol::{
    MAX_SIF_PROTECTED_FILE_CHUNK_BYTES, MAX_SIF_PROTECTED_FILE_NAME_BYTES,
    MAX_SIF_PROTECTED_FILE_REJECT_REASON_BYTES, SIF_PROTECTED_FILE_CHUNK_SCHEMA,
    SIF_PROTECTED_FILE_COMPLETE_SCHEMA, SIF_PROTECTED_FILE_OFFER_DIGEST_ALGORITHM,
    SIF_PROTECTED_FILE_OFFER_SCHEMA, SIF_PROTECTED_FILE_PROTOCOL_SCHEMA,
    SIF_PROTECTED_FILE_RESPONSE_SCHEMA, SifProtectedFileChunk, SifProtectedFileComplete,
    SifProtectedFileOffer, SifProtectedFileOfferDecision, SifProtectedFileOfferResponse,
    SifProtectedFileProtocolError, sif_protected_file_offer_digest,
};

pub use protected_file_receiver::{
    IncompleteSifProtectedFileReceive, IntegrityMismatchSifProtectedFileReceive,
    SifProtectedFileReceiveError, SifProtectedFileReceiveTerminal, SifProtectedFileReceiver,
    VerifiedSifPersistenceOutcome, VerifiedSifProtectedFileReceive,
};

pub use release_cas::{
    CasDisclosureReleaseState as DisclosureReleaseState, DisclosureReleaseFrontier,
    DisclosureReleaseStore,
};

pub use release_credential::{
    ExecutionBoundReleaseCredential, ReleaseCredentialError, ReleaseCredentialTrustPolicy,
    SIF_RELEASE_CREDENTIAL_CODEC, SIF_RELEASE_CREDENTIAL_ED25519, SIF_RELEASE_CREDENTIAL_SCHEMA,
    SifReleaseCredential, SifReleaseCredentialSignature, SifReleaseCredentialStatement,
    TrustedReleaseAuthority, VerifiedReleaseCredential, bind_release_credential_to_execution,
    release_authority_key_id, release_credential_message, verify_release_credential,
};

pub use seal::{
    EVIDENCE_BUNDLE_SEAL_SCHEMA, EvidenceBundleSeal, EvidenceBundleSealError,
    evidence_bundle_seal_message, evidence_bundle_seal_message_from_parts,
    sign_evidence_bundle_seal_ed25519,
};
#[cfg(feature = "pqc-signatures")]
pub use seal::{sign_evidence_bundle_seal_ml_dsa_65, sign_evidence_bundle_seal_ml_dsa_87};

pub use signature::{
    CURRENT_LEDGER_SIGNATURE_SUITE, Ed25519EvidenceSignatureBackend, EvidenceSignatureBackend,
    EvidenceSignatureBackendError, SignatureEnvelope, SignatureEnvelopeError, SignatureSuite,
};
#[cfg(feature = "pqc-signatures")]
pub use signature::{
    MlDsa65EvidenceSignatureBackend, MlDsa87EvidenceSignatureBackend, PQC_SIGNATURE_BACKEND_STATUS,
};
pub use witness::{
    CHECKPOINT_WITNESS_BUNDLE_SCHEMA, CheckpointWitnessBundle, CheckpointWitnessError,
    CheckpointWitnessSignature, MAX_CHECKPOINT_WITNESSES, checkpoint_witness_message,
};

pub use verify::Verifier;
