// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authority-gated asynchronous Google Cloud Storage composition for Xenia operation retention.
//!
//! This is the first layer intended to be called by application orchestration. It consumes ADR-029's
//! single-use verified namespace, proves that namespace commits the exact ADR-030 GCS profile,
//! performs semantic ADR-027 preflight before cloud I/O, and then replays observed async provider
//! outcomes through ADR-028's existing synchronous durability adapter. Provider primitives therefore
//! cannot redefine Xenia's rollback/fail-stop semantics.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use google_cloud_storage::{
    client::{Storage, StorageControl},
    stub::Storage as StorageStub,
};
use std::collections::BTreeMap;
use thiserror::Error;
use xenia_operation_authority_retention_backend::{
    AuthorityRetentionBackendErrorV1, AuthorityRetentionNamespaceV1,
    AuthorityRetentionObjectLocatorV1, AuthorityRetentionObjectV1, BackendCreateOutcomeV1,
    BackendEnumerateOutcomeV1, BackendReadOutcomeV1, ImmutableAuthorityRetentionBackendV1,
    append_via_backend_v1, readback_complete_lineage_v1,
};
use xenia_operation_authority_retention_gcs_create_transport::{
    GcsAuthorityCreateTransportV1, GcsCreateTransportErrorV1,
};
use xenia_operation_authority_retention_gcs_profile::{
    GcsAuthorityRetentionProfileV1, GcsProfileErrorV1,
};
use xenia_operation_authority_retention_gcs_readback_transport::{
    GcsAuthorityReadbackTransportV1, GcsReadbackTransportErrorV1,
};
use xenia_operation_authority_retention_lineage_v2::{
    AuthorityRetentionAppendResultV2, AuthorityRetentionErrorV2,
    OperationAuthorityRetentionModelV2, OperationAuthorityRetentionRecordV2, PersistenceOutcomeV2,
};
use xenia_operation_authority_retention_namespace_gate::{
    NamespaceGateErrorV1, VerifiedAuthorityRetentionNamespaceV1, consume_verified_namespace_v1,
};

/// Authority-gated GCS retention composition using one exact ADR-030 provider profile.
#[derive(Debug, Clone)]
pub struct GcsAuthorityRetentionBridgeV1<W, R>
where
    W: StorageStub + 'static,
    R: StorageStub + 'static,
{
    profile: GcsAuthorityRetentionProfileV1,
    create: GcsAuthorityCreateTransportV1<W>,
    readback: GcsAuthorityReadbackTransportV1<R>,
}

impl<W, R> GcsAuthorityRetentionBridgeV1<W, R>
where
    W: StorageStub + 'static,
    R: StorageStub + 'static,
{
    /// Construct create/read transports from one exact profile so they cannot silently target
    /// different GCS buckets or provider-policy commitments.
    pub fn new(
        write_client: Storage<W>,
        read_client: Storage<R>,
        control_client: StorageControl,
        profile: GcsAuthorityRetentionProfileV1,
    ) -> Result<Self, GcsAuthorityBridgeErrorV1> {
        profile.validate()?;
        let create = GcsAuthorityCreateTransportV1::new(write_client, profile.clone())?;
        let readback =
            GcsAuthorityReadbackTransportV1::new(read_client, control_client, profile.clone())?;
        Ok(Self {
            profile,
            create,
            readback,
        })
    }

    /// Append one semantic ADR-027 record through the independently authenticated namespace.
    ///
    /// Ordering is fixed:
    ///
    /// 1. consume/recheck ADR-029 token liveness;
    /// 2. prove ADR-030 profile is exactly committed by the namespace;
    /// 3. run the real ADR-027 append semantics on a disposable clone;
    /// 4. construct ADR-028 canonical external bytes/locator;
    /// 5. perform the one-shot ADR-032 create;
    /// 6. if create is ambiguous/already present, perform ADR-033 exact read;
    /// 7. replay those observed outcomes through ADR-028 to mutate the live model.
    pub async fn append_verified(
        &self,
        model: &mut OperationAuthorityRetentionModelV2,
        verified_namespace: VerifiedAuthorityRetentionNamespaceV1,
        candidate: OperationAuthorityRetentionRecordV2,
        now_unix_ms: u64,
    ) -> Result<AuthorityRetentionAppendResultV2, GcsAuthorityBridgeErrorV1> {
        let namespace = consume_verified_namespace_v1(verified_namespace, now_unix_ms)?;
        self.profile.validate_namespace(&namespace)?;

        let mut shadow = model.clone();
        match shadow.append(candidate.clone(), |_| PersistenceOutcomeV2::Durable)? {
            AuthorityRetentionAppendResultV2::DuplicateSame => {
                return Ok(AuthorityRetentionAppendResultV2::DuplicateSame);
            }
            AuthorityRetentionAppendResultV2::Appended => {}
        }

        let object = AuthorityRetentionObjectV1::new(namespace.clone(), candidate.clone())?;
        let locator = object.locator()?;
        let expected_bytes = object.canonical_bytes()?;

        let create_outcome = self
            .create
            .create_if_absent(&locator, &expected_bytes)
            .await?;

        let read_outcome = match create_outcome {
            BackendCreateOutcomeV1::AlreadyExists | BackendCreateOutcomeV1::Unknown => {
                match self.readback.read_exact(&locator).await {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        self.fail_stop_after_unresolved_create(
                            model,
                            &namespace,
                            candidate,
                            &locator,
                            &expected_bytes,
                        )?;
                        return Err(GcsAuthorityBridgeErrorV1::ReadbackTransport(error));
                    }
                }
            }
            BackendCreateOutcomeV1::DurableCreated | BackendCreateOutcomeV1::Rejected => {
                BackendReadOutcomeV1::Unknown
            }
        };

        let mut observed = ObservedCreateBackend::new(
            locator,
            expected_bytes,
            create_outcome,
            read_outcome,
        );
        let result = append_via_backend_v1(model, &namespace, &mut observed, candidate);
        if observed.binding_mismatch {
            return Err(GcsAuthorityBridgeErrorV1::ObservedReplayBindingMismatch);
        }
        Ok(result?)
    }

    /// Read the complete externally retained lineage through one freshly authenticated namespace.
    ///
    /// Async GCS enumeration/read results are materialized in memory and then passed to ADR-028's
    /// existing complete-lineage verifier. Canonical object/namespace/locator validation and the
    /// ADR-027 reconstruction therefore remain owned by the provider-neutral contract.
    pub async fn readback_verified(
        &self,
        verified_namespace: VerifiedAuthorityRetentionNamespaceV1,
        now_unix_ms: u64,
    ) -> Result<OperationAuthorityRetentionModelV2, GcsAuthorityBridgeErrorV1> {
        let namespace = consume_verified_namespace_v1(verified_namespace, now_unix_ms)?;
        self.profile.validate_namespace(&namespace)?;
        let namespace_digest = namespace.namespace_digest()?;

        let sequences = match self.readback.enumerate_complete(namespace_digest).await? {
            BackendEnumerateOutcomeV1::Complete(sequences) => sequences,
            BackendEnumerateOutcomeV1::Rejected => {
                return Err(AuthorityRetentionBackendErrorV1::EnumerationRejected.into());
            }
            BackendEnumerateOutcomeV1::Unknown => {
                return Err(AuthorityRetentionBackendErrorV1::EnumerationUnknown.into());
            }
        };

        for (index, sequence) in sequences.iter().enumerate() {
            if *sequence != index as u64 {
                return Err(
                    AuthorityRetentionBackendErrorV1::ExternalSequenceGapOrDuplicate.into(),
                );
            }
        }

        let mut objects = BTreeMap::new();
        for sequence in &sequences {
            let locator = AuthorityRetentionObjectLocatorV1 {
                namespace_digest,
                retention_sequence: *sequence,
            };
            let bytes = match self.readback.read_exact(&locator).await? {
                BackendReadOutcomeV1::Found(bytes) => bytes,
                BackendReadOutcomeV1::NotFound => {
                    return Err(AuthorityRetentionBackendErrorV1::EnumeratedObjectMissing.into());
                }
                BackendReadOutcomeV1::Rejected => {
                    return Err(AuthorityRetentionBackendErrorV1::ReadbackRejected.into());
                }
                BackendReadOutcomeV1::Unknown => {
                    return Err(AuthorityRetentionBackendErrorV1::ReadbackUnknown.into());
                }
            };
            objects.insert(locator, bytes);
        }

        let mut materialized = MaterializedReadbackBackend {
            namespace_digest,
            sequences,
            objects,
        };
        Ok(readback_complete_lineage_v1(
            &namespace,
            &mut materialized,
        )?)
    }

    fn fail_stop_after_unresolved_create(
        &self,
        model: &mut OperationAuthorityRetentionModelV2,
        namespace: &AuthorityRetentionNamespaceV1,
        candidate: OperationAuthorityRetentionRecordV2,
        locator: &AuthorityRetentionObjectLocatorV1,
        expected_bytes: &[u8],
    ) -> Result<(), GcsAuthorityBridgeErrorV1> {
        let mut observed = ObservedCreateBackend::new(
            locator.clone(),
            expected_bytes.to_vec(),
            BackendCreateOutcomeV1::Unknown,
            BackendReadOutcomeV1::Unknown,
        );
        match append_via_backend_v1(model, namespace, &mut observed, candidate) {
            Err(AuthorityRetentionBackendErrorV1::BackendStateUnknown) if !observed.binding_mismatch => {
                Ok(())
            }
            Err(error) => Err(GcsAuthorityBridgeErrorV1::FailStopReplay(error)),
            Ok(_) => Err(GcsAuthorityBridgeErrorV1::FailStopReplayUnexpectedSuccess),
        }
    }
}

#[derive(Debug)]
struct ObservedCreateBackend {
    expected_locator: AuthorityRetentionObjectLocatorV1,
    expected_bytes: Vec<u8>,
    create_outcome: BackendCreateOutcomeV1,
    read_outcome: BackendReadOutcomeV1,
    binding_mismatch: bool,
}

impl ObservedCreateBackend {
    fn new(
        expected_locator: AuthorityRetentionObjectLocatorV1,
        expected_bytes: Vec<u8>,
        create_outcome: BackendCreateOutcomeV1,
        read_outcome: BackendReadOutcomeV1,
    ) -> Self {
        Self {
            expected_locator,
            expected_bytes,
            create_outcome,
            read_outcome,
            binding_mismatch: false,
        }
    }
}

impl ImmutableAuthorityRetentionBackendV1 for ObservedCreateBackend {
    fn create_if_absent(
        &mut self,
        locator: &AuthorityRetentionObjectLocatorV1,
        bytes: &[u8],
    ) -> BackendCreateOutcomeV1 {
        if locator != &self.expected_locator || bytes != self.expected_bytes.as_slice() {
            self.binding_mismatch = true;
            return BackendCreateOutcomeV1::Rejected;
        }
        self.create_outcome
    }

    fn read_exact(
        &mut self,
        locator: &AuthorityRetentionObjectLocatorV1,
    ) -> BackendReadOutcomeV1 {
        if locator != &self.expected_locator {
            self.binding_mismatch = true;
            return BackendReadOutcomeV1::Unknown;
        }
        self.read_outcome.clone()
    }

    fn enumerate_complete(&mut self, _namespace_digest: [u8; 32]) -> BackendEnumerateOutcomeV1 {
        BackendEnumerateOutcomeV1::Unknown
    }
}

#[derive(Debug)]
struct MaterializedReadbackBackend {
    namespace_digest: [u8; 32],
    sequences: Vec<u64>,
    objects: BTreeMap<AuthorityRetentionObjectLocatorV1, Vec<u8>>,
}

impl ImmutableAuthorityRetentionBackendV1 for MaterializedReadbackBackend {
    fn create_if_absent(
        &mut self,
        _locator: &AuthorityRetentionObjectLocatorV1,
        _bytes: &[u8],
    ) -> BackendCreateOutcomeV1 {
        BackendCreateOutcomeV1::Rejected
    }

    fn read_exact(
        &mut self,
        locator: &AuthorityRetentionObjectLocatorV1,
    ) -> BackendReadOutcomeV1 {
        self.objects
            .get(locator)
            .cloned()
            .map(BackendReadOutcomeV1::Found)
            .unwrap_or(BackendReadOutcomeV1::NotFound)
    }

    fn enumerate_complete(&mut self, namespace_digest: [u8; 32]) -> BackendEnumerateOutcomeV1 {
        if namespace_digest != self.namespace_digest {
            return BackendEnumerateOutcomeV1::Unknown;
        }
        BackendEnumerateOutcomeV1::Complete(self.sequences.clone())
    }
}

/// Authority-gated GCS composition errors.
#[derive(Debug, Error)]
pub enum GcsAuthorityBridgeErrorV1 {
    /// ADR-029 namespace trust/liveness failed.
    #[error("GCS authority bridge rejected namespace trust: {0}")]
    NamespaceGate(#[from] NamespaceGateErrorV1),
    /// ADR-030 provider profile or namespace/profile binding failed.
    #[error("GCS authority bridge rejected provider profile: {0}")]
    Profile(#[from] GcsProfileErrorV1),
    /// ADR-032 create transport failed before returning a provider outcome.
    #[error("GCS authority bridge create transport failed: {0}")]
    CreateTransport(#[from] GcsCreateTransportErrorV1),
    /// ADR-033 read/list transport failed local validation/composition.
    #[error("GCS authority bridge readback transport failed: {0}")]
    ReadbackTransport(#[from] GcsReadbackTransportErrorV1),
    /// ADR-027 semantic preflight rejected the candidate before cloud I/O.
    #[error("GCS authority bridge semantic preflight rejected candidate: {0}")]
    Retention(#[from] AuthorityRetentionErrorV2),
    /// ADR-028 canonical object/durability/readback contract failed.
    #[error("GCS authority bridge provider-neutral retention contract failed: {0}")]
    Backend(#[from] AuthorityRetentionBackendErrorV1),
    /// Replayed provider observation did not bind the exact canonical locator/bytes ADR-028 rebuilt.
    #[error("GCS authority bridge observed-result replay binding mismatch")]
    ObservedReplayBindingMismatch,
    /// An ambiguous create could not be fail-stopped through the ADR-028 replay path.
    #[error("GCS authority bridge failed to enter durability-uncertain state: {0}")]
    FailStopReplay(AuthorityRetentionBackendErrorV1),
    /// Fail-stop replay unexpectedly reported a successful append.
    #[error("GCS authority bridge fail-stop replay unexpectedly succeeded")]
    FailStopReplayUnexpectedSuccess,
}
