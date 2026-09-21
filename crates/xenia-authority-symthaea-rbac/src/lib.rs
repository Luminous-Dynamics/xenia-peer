// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed Xenia RBAC policy for Symthaea verification-receipt attestation.
//!
//! This crate deliberately consumes Xenia's canonical [`OperatorRole`] rather
//! than defining a parallel identity/role model. It maps that authoritative
//! role into the narrow typed Symthaea attestation scope used by
//! XENIA-SYM-001C.
//!
//! It does **not** verify signatures, establish enrollment, read daemon state,
//! mint portable authority receipts, admit evidence in Symthaea/Mycelix, or
//! qualify assurance claims.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use xenia_operator_proto::OperatorRole;
use xenia_symthaea_attestation_authority::SymthaeaAuthorityScopeV1;

/// Policy version for the first Xenia→Symthaea attestation RBAC mapping.
pub const SYMTHAEA_ATTESTATION_RBAC_POLICY_VERSION_V1: u16 = 1;

/// Positive policy result proving only that one canonical Xenia role maps to
/// one typed Symthaea authority scope under policy v1.
///
/// Fields are private so callers cannot construct a positive result without
/// executing this crate's policy function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermittedSymthaeaAttestationScopeV1 {
    role: OperatorRole,
    scope: SymthaeaAuthorityScopeV1,
}

impl PermittedSymthaeaAttestationScopeV1 {
    /// Canonical Xenia role evaluated by the policy.
    pub const fn role(self) -> OperatorRole {
        self.role
    }

    /// Exact typed Symthaea authority scope permitted by policy v1.
    pub const fn scope(self) -> SymthaeaAuthorityScopeV1 {
        self.scope
    }
}

/// Evaluate the v1 RBAC rule for one requested Symthaea authority scope.
///
/// V1 is intentionally conservative: only [`OperatorRole::Admin`] may receive
/// [`SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1`]. Lower roles
/// fail closed. The requested scope is typed; free-form caller strings never
/// participate in the policy decision.
pub const fn permit_symthaea_attestation_scope_v1(
    role: OperatorRole,
    requested_scope: SymthaeaAuthorityScopeV1,
) -> Option<PermittedSymthaeaAttestationScopeV1> {
    match (role, requested_scope) {
        (
            OperatorRole::Admin,
            SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1,
        ) => Some(PermittedSymthaeaAttestationScopeV1 {
            role,
            scope: requested_scope,
        }),
        _ => None,
    }
}

/// Derive every Symthaea authority scope granted to `role` under policy v1.
///
/// The returned list is policy-derived, not caller-supplied. The future live
/// daemon adapter should use this function when constructing the authoritative
/// enrollment snapshot consumed by XENIA-SYM-001C.
pub fn symthaea_attestation_scopes_for_role_v1(
    role: OperatorRole,
) -> Vec<SymthaeaAuthorityScopeV1> {
    let requested = SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1;
    permit_symthaea_attestation_scope_v1(role, requested)
        .map(|permit| vec![permit.scope()])
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOPE: SymthaeaAuthorityScopeV1 =
        SymthaeaAuthorityScopeV1::VerificationReceiptAttestationV1;

    #[test]
    fn admin_is_the_only_v1_role_permitted_to_attest() {
        for role in [
            OperatorRole::Viewer,
            OperatorRole::Approver,
            OperatorRole::Operator,
        ] {
            assert_eq!(permit_symthaea_attestation_scope_v1(role, SCOPE), None);
            assert!(symthaea_attestation_scopes_for_role_v1(role).is_empty());
        }

        let permit = permit_symthaea_attestation_scope_v1(OperatorRole::Admin, SCOPE)
            .expect("admin is the sole v1 attestation role");
        assert_eq!(permit.role(), OperatorRole::Admin);
        assert_eq!(permit.scope(), SCOPE);
        assert_eq!(
            symthaea_attestation_scopes_for_role_v1(OperatorRole::Admin),
            vec![SCOPE]
        );
    }

    #[test]
    fn policy_version_and_scope_spelling_are_frozen() {
        assert_eq!(SYMTHAEA_ATTESTATION_RBAC_POLICY_VERSION_V1, 1);
        assert_eq!(SCOPE.id(), "attest:symthaea-verification-receipt:v1");
    }

    #[test]
    fn lower_roles_do_not_inherit_cross_domain_authority_from_other_permissions() {
        assert!(
            OperatorRole::Operator.permits(xenia_operator_proto::OperatorAction::InitiateSession)
        );
        assert!(
            !symthaea_attestation_scopes_for_role_v1(OperatorRole::Operator).contains(&SCOPE)
        );

        assert!(
            OperatorRole::Approver.permits(xenia_operator_proto::OperatorAction::ApproveConsent)
        );
        assert!(
            !symthaea_attestation_scopes_for_role_v1(OperatorRole::Approver).contains(&SCOPE)
        );
    }
}
