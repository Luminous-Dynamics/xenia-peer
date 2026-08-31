// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Provider-neutral immutable external-retention backend contract for Xenia operation authority.
//!
//! This crate maps storage-provider behavior onto ADR-027's append-only retention model without
//! allowing timeouts, conditional-write races, or provider keyspace mistakes to redefine Xenia's
//! security semantics. It is synchronous and runtime-free on purpose; a concrete async SDK adapter
//! should perform its network calls and expose the exact outcomes defined here.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use xenia_operation_authority_retention_lineage_v2::{
    AuthorityRetentionAppendResultV2, AuthorityRetentionErrorV2,
    OperationAuthorityRetentionModelV2, OperationAuthorityRetentionRecordV2,
    PersistenceOutcomeV2,
};

/// Exact namespace schema.
pub const AUTHORITY_RETENTION_NAMESPACE_SCHEMA_V1: &str =
    "xenia-operation-authority-retention-namespace-v1";
/// Exact externally stored object schema.
pub const AUTHORITY_RETENTION_OBJECT_SCHEMA_V1: &str =
    "xenia-operation-authority-retention-object-v1";
/// Domain separator for exact namespace commitments.
pub const AUTHORITY_RETENTION_NAMESPACE_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-authority-retention-namespace-digest-v1";
/// Domain separator for exact externally stored object commitments.
pub const AUTHORITY_RETENTION_OBJECT_DIGEST_DOMAIN_V1: &[u8] =
    b"xenia-operation-authority-retention-object-digest-v1";

/// Stable external-retention namespace for one operation-authority evidence lineage.
///
/// `retention_policy_digest` commits the deployment's provider/immutability/administrative policy
/// profile. Moving the same logical lineage into a weaker backend profile therefore cannot be
/// silently described as the same V1 namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRetentionNamespaceV1 {
    /// Exact namespace schema.
    pub schema: String,
    /// Stable Xenia operation-authority domain protected by this namespace.
    pub authority_domain_id: [u8; 16],
    /// Random identity of this external-retention lineage.
    pub retention_lineage_id: [u8; 16],
    /// Commitment to provider profile, immutability policy, credentials/admin domain and region.
    pub retention_policy_digest: [u8; 32],
}

impl AuthorityRetentionNamespaceV1 {
    /// Validate unset sentinels and schema.
    pub fn validate(&self) -> Result<(), AuthorityRetentionBackendErrorV1> {
        if self.schema != AUTHORITY_RETENTION_NAMESPACE_SCHEMA_V1 {
            return Err(AuthorityRetentionBackendErrorV1::UnsupportedNamespaceSchema);
        }
        if self.authority_domain_id == [0u8; 16] {
            return Err(AuthorityRetentionBackendErrorV1::ZeroAuthorityDomainId);
        }
        if self.retention_lineage_id == [0u8; 16] {
            return Err(AuthorityRetentionBackendErrorV1::ZeroRetentionLineageId);
        }
        if self.retention_policy_digest == [0u8; 32] {
            return Err(AuthorityRetentionBackendErrorV1::ZeroRetentionPolicyDigest);
        }
        Ok(())
    }

    /// Canonical namespace bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityRetentionBackendErrorV1> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable exact namespace commitment.
    pub fn namespace_digest(&self) -> Result<[u8; 32], AuthorityRetentionBackendErrorV1> {
        Ok(domain_digest(
            AUTHORITY_RETENTION_NAMESPACE_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Provider-independent locator for one immutable retained object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthorityRetentionObjectLocatorV1 {
    /// Exact namespace commitment.
    pub namespace_digest: [u8; 32],
    /// Exact V2 external retention sequence.
    pub retention_sequence: u64,
}

/// Canonical object bytes handed to an immutable external backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRetentionObjectV1 {
    /// Exact object schema.
    pub schema: String,
    /// Full namespace, not merely a provider path prefix.
    pub namespace: AuthorityRetentionNamespaceV1,
    /// Exact V2 authority-retention record.
    pub record: OperationAuthorityRetentionRecordV2,
}

impl AuthorityRetentionObjectV1 {
    /// Construct an externally stored object and reject authority-domain misbinding.
    pub fn new(
        namespace: AuthorityRetentionNamespaceV1,
        record: OperationAuthorityRetentionRecordV2,
    ) -> Result<Self, AuthorityRetentionBackendErrorV1> {
        let value = Self {
            schema: AUTHORITY_RETENTION_OBJECT_SCHEMA_V1.to_string(),
            namespace,
            record,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate object-local schema, retained record, and namespace/authority binding.
    pub fn validate(&self) -> Result<(), AuthorityRetentionBackendErrorV1> {
        if self.schema != AUTHORITY_RETENTION_OBJECT_SCHEMA_V1 {
            return Err(AuthorityRetentionBackendErrorV1::UnsupportedObjectSchema);
        }
        self.namespace.validate()?;
        self.record.validate_local()?;
        let terminal_domain = self
            .record
            .payload
            .terminal_state()
            .authority_epoch
            .authority_domain_id;
        if terminal_domain != self.namespace.authority_domain_id {
            return Err(AuthorityRetentionBackendErrorV1::AuthorityDomainMismatch);
        }
        if let Some(initial) = self.record.payload.initial_state()
            && initial.authority_epoch.authority_domain_id != self.namespace.authority_domain_id
        {
            return Err(AuthorityRetentionBackendErrorV1::AuthorityDomainMismatch);
        }
        Ok(())
    }

    /// Canonical exact object bytes persisted by a provider backend.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityRetentionBackendErrorV1> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Stable object digest for diagnostics/provider metadata.
    pub fn object_digest(&self) -> Result<[u8; 32], AuthorityRetentionBackendErrorV1> {
        Ok(domain_digest(
            AUTHORITY_RETENTION_OBJECT_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }

    /// Deterministic provider-independent locator.
    pub fn locator(&self) -> Result<AuthorityRetentionObjectLocatorV1, AuthorityRetentionBackendErrorV1> {
        Ok(AuthorityRetentionObjectLocatorV1 {
            namespace_digest: self.namespace.namespace_digest()?,
            retention_sequence: self.record.retention_sequence,
        })
    }
}

/// Outcome of a provider's atomic create-if-absent operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendCreateOutcomeV1 {
    /// Provider positively confirms the exact supplied bytes are durably created.
    DurableCreated,
    /// Provider positively reports that the immutable key already exists.
    AlreadyExists,
    /// Provider positively confirms this attempt did not create the object.
    Rejected,
    /// Provider cannot prove whether the object was created.
    Unknown,
}

/// Outcome of an authoritative exact-object read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendReadOutcomeV1 {
    /// Exact bytes currently retained under the locator.
    Found(Vec<u8>),
    /// Backend positively reports no object at the locator.
    NotFound,
    /// Read was positively rejected and returned no authoritative object state.
    Rejected,
    /// Backend cannot prove the current object state.
    Unknown,
}

/// Outcome of namespace enumeration used during recovery/readback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendEnumerateOutcomeV1 {
    /// Complete authoritative sequence listing for the quiescent namespace.
    Complete(Vec<u64>),
    /// Enumeration was positively rejected.
    Rejected,
    /// Backend cannot prove the listing is complete/current.
    Unknown,
}

/// Minimal provider contract required by Xenia's V1 adapter.
///
/// Implementations must map provider-specific HTTP/RPC/status behavior conservatively. In
/// particular, any error that could have occurred after commit must become `Unknown`, not
/// `Rejected`.
pub trait ImmutableAuthorityRetentionBackendV1 {
    /// Atomically create the exact object only if the locator does not already exist.
    fn create_if_absent(
        &mut self,
        locator: &AuthorityRetentionObjectLocatorV1,
        bytes: &[u8],
    ) -> BackendCreateOutcomeV1;

    /// Authoritatively read the exact immutable object currently stored at `locator`.
    fn read_exact(
        &mut self,
        locator: &AuthorityRetentionObjectLocatorV1,
    ) -> BackendReadOutcomeV1;

    /// Return a complete authoritative sequence listing for a quiescent namespace.
    ///
    /// Eventual/best-effort listing must return `Unknown`, never `Complete`.
    fn enumerate_complete(
        &mut self,
        namespace_digest: [u8; 32],
    ) -> BackendEnumerateOutcomeV1;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedCreateV1 {
    DurableExact,
    Rejected,
    Conflict,
    Unknown,
}

/// Append one V2 authority-retention record through a concrete immutable backend.
///
/// Exact lost-ack duplicate recovery is supported: `AlreadyExists`, or even an `Unknown` create
/// outcome, is accepted as durable only when an authoritative read returns byte-for-byte the exact
/// canonical object. Conflicting bytes or unresolved state fail-stop the in-memory model.
pub fn append_via_backend_v1<B: ImmutableAuthorityRetentionBackendV1>(
    model: &mut OperationAuthorityRetentionModelV2,
    namespace: &AuthorityRetentionNamespaceV1,
    backend: &mut B,
    candidate: OperationAuthorityRetentionRecordV2,
) -> Result<AuthorityRetentionAppendResultV2, AuthorityRetentionBackendErrorV1> {
    namespace.validate()?;
    let mut resolved = None;
    let result = model.append(candidate, |record| {
        let resolution = match AuthorityRetentionObjectV1::new(namespace.clone(), record.clone()) {
            Ok(object) => resolve_create(backend, &object),
            Err(_) => ResolvedCreateV1::Rejected,
        };
        resolved = Some(resolution);
        match resolution {
            ResolvedCreateV1::DurableExact => PersistenceOutcomeV2::Durable,
            ResolvedCreateV1::Rejected => PersistenceOutcomeV2::Rejected,
            ResolvedCreateV1::Conflict | ResolvedCreateV1::Unknown => PersistenceOutcomeV2::Unknown,
        }
    });

    match resolved {
        None => result.map_err(AuthorityRetentionBackendErrorV1::Retention),
        Some(ResolvedCreateV1::DurableExact) => {
            result.map_err(AuthorityRetentionBackendErrorV1::Retention)
        }
        Some(ResolvedCreateV1::Rejected) => {
            Err(AuthorityRetentionBackendErrorV1::BackendRejected)
        }
        Some(ResolvedCreateV1::Conflict) => {
            Err(AuthorityRetentionBackendErrorV1::ExternalObjectConflict)
        }
        Some(ResolvedCreateV1::Unknown) => {
            Err(AuthorityRetentionBackendErrorV1::BackendStateUnknown)
        }
    }
}

fn resolve_create<B: ImmutableAuthorityRetentionBackendV1>(
    backend: &mut B,
    object: &AuthorityRetentionObjectV1,
) -> ResolvedCreateV1 {
    let Ok(locator) = object.locator() else {
        return ResolvedCreateV1::Rejected;
    };
    let Ok(expected) = object.canonical_bytes() else {
        return ResolvedCreateV1::Rejected;
    };
    match backend.create_if_absent(&locator, &expected) {
        BackendCreateOutcomeV1::DurableCreated => ResolvedCreateV1::DurableExact,
        BackendCreateOutcomeV1::Rejected => ResolvedCreateV1::Rejected,
        BackendCreateOutcomeV1::AlreadyExists | BackendCreateOutcomeV1::Unknown => {
            match backend.read_exact(&locator) {
                BackendReadOutcomeV1::Found(observed) if observed == expected => {
                    ResolvedCreateV1::DurableExact
                }
                BackendReadOutcomeV1::Found(_) => ResolvedCreateV1::Conflict,
                BackendReadOutcomeV1::NotFound
                | BackendReadOutcomeV1::Rejected
                | BackendReadOutcomeV1::Unknown => ResolvedCreateV1::Unknown,
            }
        }
    }
}

/// Read back and validate a complete external namespace into a fresh healthy V2 retention model.
///
/// Callers must quiesce writers before using this recovery path unless the concrete provider profile
/// supplies an equally strong snapshot/enumeration mechanism. Empty readback is structurally valid
/// but provides no anti-rollback anchor and must not satisfy recovery policy by itself.
pub fn readback_complete_lineage_v1<B: ImmutableAuthorityRetentionBackendV1>(
    namespace: &AuthorityRetentionNamespaceV1,
    backend: &mut B,
) -> Result<OperationAuthorityRetentionModelV2, AuthorityRetentionBackendErrorV1> {
    namespace.validate()?;
    let namespace_digest = namespace.namespace_digest()?;
    let sequences = match backend.enumerate_complete(namespace_digest) {
        BackendEnumerateOutcomeV1::Complete(sequences) => sequences,
        BackendEnumerateOutcomeV1::Rejected => {
            return Err(AuthorityRetentionBackendErrorV1::EnumerationRejected);
        }
        BackendEnumerateOutcomeV1::Unknown => {
            return Err(AuthorityRetentionBackendErrorV1::EnumerationUnknown);
        }
    };

    for (index, sequence) in sequences.iter().enumerate() {
        if *sequence != index as u64 {
            return Err(AuthorityRetentionBackendErrorV1::ExternalSequenceGapOrDuplicate);
        }
    }

    let mut records = Vec::with_capacity(sequences.len());
    for sequence in sequences {
        let locator = AuthorityRetentionObjectLocatorV1 {
            namespace_digest,
            retention_sequence: sequence,
        };
        let bytes = match backend.read_exact(&locator) {
            BackendReadOutcomeV1::Found(bytes) => bytes,
            BackendReadOutcomeV1::NotFound => {
                return Err(AuthorityRetentionBackendErrorV1::EnumeratedObjectMissing);
            }
            BackendReadOutcomeV1::Rejected => {
                return Err(AuthorityRetentionBackendErrorV1::ReadbackRejected);
            }
            BackendReadOutcomeV1::Unknown => {
                return Err(AuthorityRetentionBackendErrorV1::ReadbackUnknown);
            }
        };
        let object: AuthorityRetentionObjectV1 = bincode::deserialize(&bytes)?;
        object.validate()?;
        if object.namespace != *namespace || object.locator()? != locator {
            return Err(AuthorityRetentionBackendErrorV1::ObjectLocatorMismatch);
        }
        if object.canonical_bytes()? != bytes {
            return Err(AuthorityRetentionBackendErrorV1::NonCanonicalExternalObject);
        }
        records.push(object.record);
    }

    Ok(OperationAuthorityRetentionModelV2::from_retained_lineage(records)?)
}

/// Provider-neutral backend/adapter errors.
#[derive(Debug, Error)]
pub enum AuthorityRetentionBackendErrorV1 {
    /// Namespace schema mismatch.
    #[error("unsupported authority retention namespace schema")]
    UnsupportedNamespaceSchema,
    /// Namespace has no authority-domain identity.
    #[error("authority retention namespace requires authority domain id")]
    ZeroAuthorityDomainId,
    /// Namespace has no lineage identity.
    #[error("authority retention namespace requires retention lineage id")]
    ZeroRetentionLineageId,
    /// Namespace has no provider/immutability policy commitment.
    #[error("authority retention namespace requires retention policy digest")]
    ZeroRetentionPolicyDigest,
    /// External object schema mismatch.
    #[error("unsupported authority retention object schema")]
    UnsupportedObjectSchema,
    /// Record authority domain differs from the configured external namespace.
    #[error("authority retention object is bound to a different authority domain")]
    AuthorityDomainMismatch,
    /// V2 retention model rejected the record/lineage operation.
    #[error("authority retention model rejected backend operation: {0}")]
    Retention(#[from] AuthorityRetentionErrorV2),
    /// Provider positively rejected creation without committing the candidate.
    #[error("external retention backend positively rejected append")]
    BackendRejected,
    /// Immutable locator already contains different bytes.
    #[error("external retention object conflict / fork evidence")]
    ExternalObjectConflict,
    /// Provider state could not be resolved after a potentially committed create.
    #[error("external retention backend state is unknown; immutable readback required")]
    BackendStateUnknown,
    /// Complete enumeration was positively rejected.
    #[error("external retention enumeration rejected")]
    EnumerationRejected,
    /// Provider cannot prove enumeration is complete/current.
    #[error("external retention enumeration is unknown/incomplete")]
    EnumerationUnknown,
    /// Enumeration contained a sequence gap, duplicate or out-of-order member.
    #[error("external retention sequence listing is not exactly contiguous")]
    ExternalSequenceGapOrDuplicate,
    /// Provider enumerated an object that an authoritative exact read could not find.
    #[error("enumerated external retention object is missing")]
    EnumeratedObjectMissing,
    /// Provider rejected exact object readback.
    #[error("external retention readback rejected")]
    ReadbackRejected,
    /// Provider cannot prove exact object readback state.
    #[error("external retention readback state is unknown")]
    ReadbackUnknown,
    /// Stored object's embedded namespace/sequence differs from its provider locator.
    #[error("external retention object locator/namespace mismatch")]
    ObjectLocatorMismatch,
    /// Stored bytes deserialize but are not the exact canonical representation of the object.
    #[error("external retention object bytes are non-canonical")]
    NonCanonicalExternalObject,
    /// Canonical object/namespace serialization or external object decoding failed.
    #[error("authority retention backend serialization failed: {0}")]
    Serialization(#[from] bincode::Error),
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
