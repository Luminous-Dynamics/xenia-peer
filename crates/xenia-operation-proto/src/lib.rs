// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Runtime-free contracts for Xenia privileged-operation grants.
//!
//! This crate is intentionally not an IAM database, policy engine, credential
//! store, process runtime, network proxy, or bearer-token implementation. It
//! defines the finite authorization lease that sits between an upstream policy/
//! approval decision and a protocol-specific Xenia enforcement adapter.
//!
//! V1 grants are bound to one authenticated session and one subject. A child
//! grant may only attenuate the same subject's authority; cross-subject
//! delegation is deliberately outside V1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable schema label for [`CapabilityGrantV1`].
pub const OPERATION_GRANT_SCHEMA_V1: &str = "xenia-operation-grant-v1";
/// Stable schema label for [`CapabilityUseV1`].
pub const OPERATION_USE_SCHEMA_V1: &str = "xenia-operation-use-v1";
/// Domain separator for grant commitments.
pub const OPERATION_GRANT_DIGEST_DOMAIN_V1: &[u8] = b"xenia-operation-grant-digest-v1";
/// Domain separator for per-use commitments/evidence.
pub const OPERATION_USE_DIGEST_DOMAIN_V1: &[u8] = b"xenia-operation-use-digest-v1";
/// Maximum exact rules carried by one V1 grant.
pub const MAX_OPERATION_RULES_V1: usize = 256;
/// Maximum resource namespace bytes.
pub const MAX_RESOURCE_NAMESPACE_BYTES_V1: usize = 128;
/// Maximum resource identifier bytes.
pub const MAX_RESOURCE_ID_BYTES_V1: usize = 4 * 1024;
/// Maximum action-label bytes.
pub const MAX_ACTION_BYTES_V1: usize = 256;
/// Maximum lifetime of one V1 privileged grant: 24 hours.
pub const MAX_GRANT_LIFETIME_MS_V1: u64 = 24 * 60 * 60 * 1000;
/// Maximum number of privileged uses authorized by one V1 grant.
pub const MAX_GRANT_USES_V1: u32 = 65_536;

/// Broad semantic class of a privileged operation.
///
/// The exact authority is still defined by [`OperationRuleV1::action`] and its
/// resource/parameter commitment. These classes are intentionally not roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OperationClassV1 {
    /// Observe information without requesting a target-side state change.
    Observe,
    /// Mutate target state without generic process execution semantics.
    Mutate,
    /// Execute an exact structured operation such as `ExecRequestV1`.
    Execute,
    /// Establish access to one explicitly named service endpoint.
    ConnectService,
    /// Use/inject a credential without disclosing the credential value.
    UseCredential,
    /// Perform an explicitly modeled recovery/out-of-band action.
    Recover,
}

/// Resource category for a privileged operation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ResourceKindV1 {
    /// A Xenia-managed host/machine identity.
    Host,
    /// A service endpoint such as a database or application service.
    Service,
    /// A concrete running workload/process identity.
    Workload,
    /// A hardware/device-management resource.
    Device,
    /// A file or file-like artifact.
    File,
    /// A datastore/database resource.
    DataStore,
}

/// Canonical resource identity used by an exact operation rule.
///
/// `namespace` states which identity semantics apply to `id`; examples include
/// `xenia-host`, `spiffe`, `redfish`, `nix-store`, and `tcp-service`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceRefV1 {
    /// Broad resource category.
    pub kind: ResourceKindV1,
    /// Canonical identity namespace.
    pub namespace: String,
    /// Namespace-specific canonical resource identifier.
    pub id: String,
}

impl ResourceRefV1 {
    /// Validate bounded canonical V1 resource identity syntax.
    pub fn validate(&self) -> Result<(), OperationProtocolError> {
        validate_namespace(&self.namespace)?;
        validate_text(
            "resource id",
            &self.id,
            MAX_RESOURCE_ID_BYTES_V1,
            false,
        )
    }
}

/// One exact resource/action authority rule.
///
/// `parameter_digest` is `Some` when the operation has privilege-relevant
/// parameters that must be committed exactly. For native execution this should
/// be the digest of the exact structured execution request/invocation. `None`
/// means the canonical resource+action pair is itself the complete operation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OperationRuleV1 {
    /// Exact resource identity.
    pub resource: ResourceRefV1,
    /// Broad semantic class.
    pub class: OperationClassV1,
    /// Stable lower-case action label, e.g. `exec.v1` or `read.logs`.
    pub action: String,
    /// Optional exact commitment to privilege-relevant operation parameters.
    pub parameter_digest: Option<[u8; 32]>,
}

impl OperationRuleV1 {
    /// Validate bounded canonical V1 rule syntax.
    pub fn validate(&self) -> Result<(), OperationProtocolError> {
        self.resource.validate()?;
        validate_action(&self.action)
    }
}

/// Sorted, unique exact operation rules authorized by a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationScopeV1 {
    /// Exact allowed rules. Must be non-empty, sorted, and unique.
    pub rules: Vec<OperationRuleV1>,
}

impl OperationScopeV1 {
    /// Construct a scope without silently sorting caller input.
    ///
    /// Callers should deliberately produce canonical order; validation rejects
    /// accidental reordering so byte commitments cannot vary by construction
    /// path.
    pub fn new(rules: Vec<OperationRuleV1>) -> Self {
        Self { rules }
    }

    /// Validate the finite canonical scope representation.
    pub fn validate(&self) -> Result<(), OperationProtocolError> {
        if self.rules.is_empty() {
            return Err(OperationProtocolError::EmptyScope);
        }
        if self.rules.len() > MAX_OPERATION_RULES_V1 {
            return Err(OperationProtocolError::TooManyRules);
        }
        for rule in &self.rules {
            rule.validate()?;
        }
        if self.rules.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(OperationProtocolError::NonCanonicalScope);
        }
        Ok(())
    }

    /// Whether this exact rule is present in the canonical scope.
    pub fn contains(&self, rule: &OperationRuleV1) -> bool {
        self.rules.binary_search(rule).is_ok()
    }

    /// Whether every rule in `child` is also present in this scope.
    pub fn contains_scope(&self, child: &Self) -> bool {
        child.rules.iter().all(|rule| self.contains(rule))
    }
}

/// How often a live runtime must reevaluate authorization while using a grant.
///
/// V1 deliberately supports only per-use reevaluation. Any cached/interval
/// optimization must be an explicit future protocol change rather than an
/// implementation shortcut that weakens the security contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReevaluationPolicyV1 {
    /// Re-check live authorization state before every privileged operation use.
    BeforeEveryUse,
}

/// Session-bound finite authorization lease for privileged operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrantV1 {
    /// Exact V1 schema label.
    pub schema: String,
    /// Grant identifier, unique within the issuing authority's evidence domain.
    pub grant_id: [u8; 16],
    /// Hash of the exact authenticated Xenia session context this grant belongs to.
    pub session_context_hash: [u8; 32],
    /// Fingerprint of the authenticated subject allowed to exercise the grant.
    pub subject_fingerprint: [u8; 32],
    /// Exact finite operation scope.
    pub scope: OperationScopeV1,
    /// Commitment to the policy revision/decision that authorized this grant.
    pub policy_digest: [u8; 32],
    /// Commitment to the human/organizational approval evidence.
    pub approval_digest: [u8; 32],
    /// Commitment to the stated purpose/reason for the authority.
    pub purpose_digest: [u8; 32],
    /// Issuer timestamp in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Earliest Unix-millisecond instant at which the grant may be exercised.
    pub not_before_unix_ms: u64,
    /// Exclusive Unix-millisecond expiration instant.
    pub expires_at_unix_ms: u64,
    /// Maximum successful/admitted operation uses of this grant.
    pub max_uses: u32,
    /// Required live reevaluation behavior.
    pub reevaluation: ReevaluationPolicyV1,
    /// Exact parent grant commitment for an attenuated child; `None` for roots.
    pub parent_grant_digest: Option<[u8; 32]>,
}

impl CapabilityGrantV1 {
    /// Validate bounded canonical grant syntax independent of live runtime state.
    pub fn validate(&self) -> Result<(), OperationProtocolError> {
        if self.schema != OPERATION_GRANT_SCHEMA_V1 {
            return Err(OperationProtocolError::UnsupportedGrantSchema);
        }
        if self.grant_id == [0u8; 16] {
            return Err(OperationProtocolError::ZeroGrantId);
        }
        self.scope.validate()?;
        if self.max_uses == 0 || self.max_uses > MAX_GRANT_USES_V1 {
            return Err(OperationProtocolError::InvalidUseLimit);
        }
        if self.issued_at_unix_ms > self.not_before_unix_ms
            || self.not_before_unix_ms >= self.expires_at_unix_ms
        {
            return Err(OperationProtocolError::InvalidTimeWindow);
        }
        let lifetime = self
            .expires_at_unix_ms
            .checked_sub(self.not_before_unix_ms)
            .ok_or(OperationProtocolError::InvalidTimeWindow)?;
        if lifetime > MAX_GRANT_LIFETIME_MS_V1 {
            return Err(OperationProtocolError::GrantLifetimeTooLong);
        }
        match self.reevaluation {
            ReevaluationPolicyV1::BeforeEveryUse => {}
        }
        Ok(())
    }

    /// Validate syntax and whether `now_unix_ms` is inside the grant window.
    pub fn validate_at(&self, now_unix_ms: u64) -> Result<(), OperationProtocolError> {
        self.validate()?;
        if now_unix_ms < self.not_before_unix_ms {
            return Err(OperationProtocolError::GrantNotYetValid);
        }
        if now_unix_ms >= self.expires_at_unix_ms {
            return Err(OperationProtocolError::GrantExpired);
        }
        Ok(())
    }

    /// Whether the grant contains this exact rule.
    pub fn authorizes_rule(&self, rule: &OperationRuleV1) -> bool {
        self.scope.contains(rule)
    }

    /// Deterministic canonical bincode-v1 bytes for signature/evidence binding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OperationProtocolError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Domain-separated BLAKE3-256 commitment to the complete grant.
    pub fn grant_digest(&self) -> Result<[u8; 32], OperationProtocolError> {
        Ok(domain_digest(
            OPERATION_GRANT_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// One attempted use of a privileged-operation grant.
///
/// The runtime must separately maintain replay/use-count state and reject a
/// duplicate `operation_id` or already-consumed `use_index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityUseV1 {
    /// Exact V1 use schema label.
    pub schema: String,
    /// Unique operation identifier within the live session/evidence domain.
    pub operation_id: [u8; 16],
    /// Exact digest of the grant being exercised.
    pub grant_digest: [u8; 32],
    /// Exact rule selected from the grant scope.
    pub rule: OperationRuleV1,
    /// Zero-based use slot consumed by this operation.
    pub use_index: u32,
    /// Adapter-specific request commitment, e.g. exact `ExecRequestV1` digest.
    pub request_digest: [u8; 32],
}

impl CapabilityUseV1 {
    /// Validate this use against one live grant at `now_unix_ms`.
    ///
    /// This proves structural authorization only. The runtime must still perform
    /// the V1-required live consent/policy/posture reevaluation and atomically
    /// reserve the `use_index` before causing side effects.
    pub fn validate_against(
        &self,
        grant: &CapabilityGrantV1,
        now_unix_ms: u64,
    ) -> Result<(), OperationProtocolError> {
        if self.schema != OPERATION_USE_SCHEMA_V1 {
            return Err(OperationProtocolError::UnsupportedUseSchema);
        }
        if self.operation_id == [0u8; 16] {
            return Err(OperationProtocolError::ZeroOperationId);
        }
        self.rule.validate()?;
        grant.validate_at(now_unix_ms)?;
        if self.grant_digest != grant.grant_digest()? {
            return Err(OperationProtocolError::GrantDigestMismatch);
        }
        if !grant.authorizes_rule(&self.rule) {
            return Err(OperationProtocolError::RuleNotAuthorized);
        }
        if self.use_index >= grant.max_uses {
            return Err(OperationProtocolError::UseIndexOutOfRange);
        }
        Ok(())
    }

    /// Return deterministic canonical use bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OperationProtocolError> {
        if self.schema != OPERATION_USE_SCHEMA_V1 {
            return Err(OperationProtocolError::UnsupportedUseSchema);
        }
        if self.operation_id == [0u8; 16] {
            return Err(OperationProtocolError::ZeroOperationId);
        }
        self.rule.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Domain-separated BLAKE3-256 use/evidence commitment.
    pub fn use_digest(&self) -> Result<[u8; 32], OperationProtocolError> {
        Ok(domain_digest(
            OPERATION_USE_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Verify that `child` only attenuates `parent` and cannot widen authority.
///
/// V1 intentionally requires the same subject. Cross-subject delegation needs
/// a separate signed delegation protocol and is rejected here.
pub fn validate_attenuation(
    parent: &CapabilityGrantV1,
    child: &CapabilityGrantV1,
) -> Result<(), OperationProtocolError> {
    parent.validate()?;
    child.validate()?;

    let expected_parent = parent.grant_digest()?;
    if child.parent_grant_digest != Some(expected_parent) {
        return Err(OperationProtocolError::ParentDigestMismatch);
    }
    if child.session_context_hash != parent.session_context_hash {
        return Err(OperationProtocolError::SessionChangedDuringAttenuation);
    }
    if child.subject_fingerprint != parent.subject_fingerprint {
        return Err(OperationProtocolError::SubjectChangedDuringAttenuation);
    }
    if child.policy_digest != parent.policy_digest {
        return Err(OperationProtocolError::PolicyChangedDuringAttenuation);
    }
    if child.approval_digest != parent.approval_digest {
        return Err(OperationProtocolError::ApprovalChangedDuringAttenuation);
    }
    if child.purpose_digest != parent.purpose_digest {
        return Err(OperationProtocolError::PurposeChangedDuringAttenuation);
    }
    if !parent.scope.contains_scope(&child.scope) {
        return Err(OperationProtocolError::ScopeWidenedDuringAttenuation);
    }
    if child.issued_at_unix_ms < parent.issued_at_unix_ms
        || child.not_before_unix_ms < parent.not_before_unix_ms
        || child.expires_at_unix_ms > parent.expires_at_unix_ms
    {
        return Err(OperationProtocolError::TimeWidenedDuringAttenuation);
    }
    if child.max_uses > parent.max_uses {
        return Err(OperationProtocolError::UsesWidenedDuringAttenuation);
    }
    Ok(())
}

/// Contract-validation failure for privileged-operation grants/uses.
#[derive(Debug, Error)]
pub enum OperationProtocolError {
    /// Grant schema is not the exact V1 schema.
    #[error("unsupported operation grant schema")]
    UnsupportedGrantSchema,
    /// Use schema is not the exact V1 schema.
    #[error("unsupported operation use schema")]
    UnsupportedUseSchema,
    /// Grant identifier is the reserved all-zero value.
    #[error("operation grant id must not be all zero")]
    ZeroGrantId,
    /// Operation identifier is the reserved all-zero value.
    #[error("operation id must not be all zero")]
    ZeroOperationId,
    /// Grant scope is empty.
    #[error("operation grant scope must not be empty")]
    EmptyScope,
    /// Grant carries too many exact operation rules.
    #[error("operation grant contains too many rules")]
    TooManyRules,
    /// Scope is not strictly sorted and unique.
    #[error("operation grant scope must be sorted and unique")]
    NonCanonicalScope,
    /// Resource namespace is not canonical lower-case token syntax.
    #[error("invalid resource namespace")]
    InvalidNamespace,
    /// Action label is not canonical lower-case token syntax.
    #[error("invalid operation action")]
    InvalidAction,
    /// Required text field was empty.
    #[error("operation field {0} must not be empty")]
    EmptyField(&'static str),
    /// Text field exceeded its finite V1 byte bound.
    #[error("operation field {0} exceeds its V1 byte ceiling")]
    FieldTooLarge(&'static str),
    /// Text field contains NUL.
    #[error("operation field {0} contains NUL")]
    NulInField(&'static str),
    /// Grant time ordering is invalid.
    #[error("invalid operation grant time window")]
    InvalidTimeWindow,
    /// Grant exceeds the V1 maximum lifetime.
    #[error("operation grant lifetime exceeds V1 ceiling")]
    GrantLifetimeTooLong,
    /// Grant use count is zero or exceeds the V1 ceiling.
    #[error("invalid operation grant use limit")]
    InvalidUseLimit,
    /// Current time precedes the grant validity window.
    #[error("operation grant is not yet valid")]
    GrantNotYetValid,
    /// Current time is at or beyond grant expiration.
    #[error("operation grant has expired")]
    GrantExpired,
    /// Child did not name the exact parent grant commitment.
    #[error("attenuated grant parent digest mismatch")]
    ParentDigestMismatch,
    /// Child attempted to move authority to another session.
    #[error("attenuation cannot change session context")]
    SessionChangedDuringAttenuation,
    /// Child attempted to change subject; V1 delegation is forbidden.
    #[error("attenuation cannot change subject in V1")]
    SubjectChangedDuringAttenuation,
    /// Child attempted to change policy commitment.
    #[error("attenuation cannot change policy commitment")]
    PolicyChangedDuringAttenuation,
    /// Child attempted to change approval commitment.
    #[error("attenuation cannot change approval commitment")]
    ApprovalChangedDuringAttenuation,
    /// Child attempted to change purpose commitment.
    #[error("attenuation cannot change purpose commitment")]
    PurposeChangedDuringAttenuation,
    /// Child scope contains authority absent from the parent.
    #[error("attenuation cannot widen operation scope")]
    ScopeWidenedDuringAttenuation,
    /// Child widened issuance/not-before/expiry bounds.
    #[error("attenuation cannot widen operation time bounds")]
    TimeWidenedDuringAttenuation,
    /// Child increased the maximum use budget.
    #[error("attenuation cannot increase operation use budget")]
    UsesWidenedDuringAttenuation,
    /// Use named a grant digest other than the actual grant commitment.
    #[error("operation use grant digest mismatch")]
    GrantDigestMismatch,
    /// Use selected a rule outside the exact grant scope.
    #[error("operation rule is not authorized by the grant")]
    RuleNotAuthorized,
    /// Use index cannot be consumed under this grant's use budget.
    #[error("operation use index is outside the grant budget")]
    UseIndexOutOfRange,
    /// Deterministic bincode encoding failed.
    #[error("failed to encode operation contract: {0}")]
    Encoding(#[from] bincode::Error),
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn validate_namespace(value: &str) -> Result<(), OperationProtocolError> {
    validate_text(
        "resource namespace",
        value,
        MAX_RESOURCE_NAMESPACE_BYTES_V1,
        false,
    )?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err(OperationProtocolError::InvalidNamespace);
    }
    Ok(())
}

fn validate_action(value: &str) -> Result<(), OperationProtocolError> {
    validate_text("action", value, MAX_ACTION_BYTES_V1, false)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
    }) {
        return Err(OperationProtocolError::InvalidAction);
    }
    Ok(())
}

fn validate_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), OperationProtocolError> {
    if !allow_empty && value.is_empty() {
        return Err(OperationProtocolError::EmptyField(field));
    }
    if value.len() > max_bytes {
        return Err(OperationProtocolError::FieldTooLarge(field));
    }
    if value.as_bytes().contains(&0) {
        return Err(OperationProtocolError::NulInField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> ResourceRefV1 {
        ResourceRefV1 {
            kind: ResourceKindV1::Host,
            namespace: "xenia-host".into(),
            id: "host:example:001".into(),
        }
    }

    fn read_logs_rule() -> OperationRuleV1 {
        OperationRuleV1 {
            resource: host(),
            class: OperationClassV1::Observe,
            action: "read.logs".into(),
            parameter_digest: Some([0x11; 32]),
        }
    }

    fn exec_rule() -> OperationRuleV1 {
        OperationRuleV1 {
            resource: host(),
            class: OperationClassV1::Execute,
            action: "exec.v1".into(),
            parameter_digest: Some([0x22; 32]),
        }
    }

    fn root_grant() -> CapabilityGrantV1 {
        let mut rules = vec![read_logs_rule(), exec_rule()];
        rules.sort();
        CapabilityGrantV1 {
            schema: OPERATION_GRANT_SCHEMA_V1.into(),
            grant_id: [1; 16],
            session_context_hash: [2; 32],
            subject_fingerprint: [3; 32],
            scope: OperationScopeV1::new(rules),
            policy_digest: [4; 32],
            approval_digest: [5; 32],
            purpose_digest: [6; 32],
            issued_at_unix_ms: 1_000,
            not_before_unix_ms: 1_000,
            expires_at_unix_ms: 61_000,
            max_uses: 8,
            reevaluation: ReevaluationPolicyV1::BeforeEveryUse,
            parent_grant_digest: None,
        }
    }

    #[test]
    fn grant_is_finite_canonical_and_valid() {
        let grant = root_grant();
        grant.validate().unwrap();
        grant.validate_at(30_000).unwrap();
        assert!(grant.authorizes_rule(&exec_rule()));
    }

    #[test]
    fn scope_rejects_reordered_or_duplicate_rules() {
        let mut reordered = root_grant();
        reordered.scope.rules.reverse();
        assert!(matches!(
            reordered.validate(),
            Err(OperationProtocolError::NonCanonicalScope)
        ));

        let mut duplicate = root_grant();
        duplicate.scope.rules = vec![exec_rule(), exec_rule()];
        assert!(matches!(
            duplicate.validate(),
            Err(OperationProtocolError::NonCanonicalScope)
        ));
    }

    #[test]
    fn grant_digest_commits_to_scope_policy_and_session() {
        let first = root_grant();

        let mut scope_changed = first.clone();
        scope_changed.scope.rules = vec![exec_rule()];
        assert_ne!(
            first.grant_digest().unwrap(),
            scope_changed.grant_digest().unwrap()
        );

        let mut policy_changed = first.clone();
        policy_changed.policy_digest[0] ^= 1;
        assert_ne!(
            first.grant_digest().unwrap(),
            policy_changed.grant_digest().unwrap()
        );

        let mut session_changed = first.clone();
        session_changed.session_context_hash[0] ^= 1;
        assert_ne!(
            first.grant_digest().unwrap(),
            session_changed.grant_digest().unwrap()
        );
    }

    #[test]
    fn grant_window_is_short_and_exclusive_at_expiry() {
        let grant = root_grant();
        assert!(matches!(
            grant.validate_at(999),
            Err(OperationProtocolError::GrantNotYetValid)
        ));
        grant.validate_at(1_000).unwrap();
        assert!(matches!(
            grant.validate_at(61_000),
            Err(OperationProtocolError::GrantExpired)
        ));

        let mut too_long = grant;
        too_long.expires_at_unix_ms =
            too_long.not_before_unix_ms + MAX_GRANT_LIFETIME_MS_V1 + 1;
        assert!(matches!(
            too_long.validate(),
            Err(OperationProtocolError::GrantLifetimeTooLong)
        ));
    }

    #[test]
    fn attenuation_can_only_shrink_same_subject_authority() {
        let parent = root_grant();
        let mut child = parent.clone();
        child.grant_id = [7; 16];
        child.scope.rules = vec![exec_rule()];
        child.issued_at_unix_ms = 2_000;
        child.not_before_unix_ms = 2_000;
        child.expires_at_unix_ms = 20_000;
        child.max_uses = 1;
        child.parent_grant_digest = Some(parent.grant_digest().unwrap());

        validate_attenuation(&parent, &child).unwrap();
    }

    #[test]
    fn attenuation_rejects_cross_subject_delegation() {
        let parent = root_grant();
        let mut child = parent.clone();
        child.grant_id = [7; 16];
        child.subject_fingerprint = [0xAA; 32];
        child.parent_grant_digest = Some(parent.grant_digest().unwrap());

        assert!(matches!(
            validate_attenuation(&parent, &child),
            Err(OperationProtocolError::SubjectChangedDuringAttenuation)
        ));
    }

    #[test]
    fn attenuation_rejects_scope_time_and_use_widening() {
        let parent = {
            let mut parent = root_grant();
            parent.scope.rules = vec![exec_rule()];
            parent
        };

        let mut scope_widened = parent.clone();
        let mut wider = vec![read_logs_rule(), exec_rule()];
        wider.sort();
        scope_widened.scope.rules = wider;
        scope_widened.grant_id = [8; 16];
        scope_widened.parent_grant_digest = Some(parent.grant_digest().unwrap());
        assert!(matches!(
            validate_attenuation(&parent, &scope_widened),
            Err(OperationProtocolError::ScopeWidenedDuringAttenuation)
        ));

        let mut time_widened = parent.clone();
        time_widened.grant_id = [9; 16];
        time_widened.expires_at_unix_ms = parent.expires_at_unix_ms + 1;
        time_widened.parent_grant_digest = Some(parent.grant_digest().unwrap());
        assert!(matches!(
            validate_attenuation(&parent, &time_widened),
            Err(OperationProtocolError::TimeWidenedDuringAttenuation)
        ));

        let mut uses_widened = parent.clone();
        uses_widened.grant_id = [10; 16];
        uses_widened.max_uses = parent.max_uses + 1;
        uses_widened.parent_grant_digest = Some(parent.grant_digest().unwrap());
        assert!(matches!(
            validate_attenuation(&parent, &uses_widened),
            Err(OperationProtocolError::UsesWidenedDuringAttenuation)
        ));
    }

    #[test]
    fn use_is_bound_to_exact_grant_rule_request_and_use_slot() {
        let grant = root_grant();
        let use_record = CapabilityUseV1 {
            schema: OPERATION_USE_SCHEMA_V1.into(),
            operation_id: [0x33; 16],
            grant_digest: grant.grant_digest().unwrap(),
            rule: exec_rule(),
            use_index: 0,
            request_digest: [0x44; 32],
        };

        use_record.validate_against(&grant, 30_000).unwrap();

        let mut changed_request = use_record.clone();
        changed_request.request_digest[0] ^= 1;
        assert_ne!(
            use_record.use_digest().unwrap(),
            changed_request.use_digest().unwrap()
        );

        let mut out_of_budget = use_record;
        out_of_budget.use_index = grant.max_uses;
        assert!(matches!(
            out_of_budget.validate_against(&grant, 30_000),
            Err(OperationProtocolError::UseIndexOutOfRange)
        ));
    }

    #[test]
    fn namespaces_and_actions_are_canonical_lowercase_tokens() {
        let mut bad_namespace = exec_rule();
        bad_namespace.resource.namespace = "SPIFFE".into();
        assert!(matches!(
            bad_namespace.validate(),
            Err(OperationProtocolError::InvalidNamespace)
        ));

        let mut bad_action = exec_rule();
        bad_action.action = "Exec V1".into();
        assert!(matches!(
            bad_action.validate(),
            Err(OperationProtocolError::InvalidAction)
        ));
    }
}
