// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator-action audit entries (Phase 4 of
//! `docs/security/OPERATOR_RBAC_PLAN.md`).
//!
//! When a consent decision is made by an authenticated operator, this builds
//! the signed ledger entry that attributes it: *who* (the operator's Ed25519
//! key as `source_id`) authorized *what* (the action, mapped to a
//! `ConsentKind`) under which role. Appending it to the daemon's hash-chained
//! ledger makes "operator X (role Y) approved/denied/revoked session Z" a
//! tamper-evident, offline-verifiable record -- the audit trail a PAM product
//! is sold on. The mapping is pure and unit-tested; the append is done by the
//! caller against the shared ledger.

use uuid::Uuid;

use xenia_ledger::{ConsentEventRecord, ConsentKind};

use crate::operator_auth::{AuthorizedConsentAction, ConsentAction};

/// Build the ledger event attributing an authorized operator consent action.
/// `source_id` is the operator's Ed25519 public key; the scope carries the
/// operator id + role + action for human-readable audit.
pub(crate) fn operator_consent_audit_event(
    authorized: &AuthorizedConsentAction,
    session_id: Uuid,
    request_id: Uuid,
) -> ConsentEventRecord {
    let kind = match authorized.action {
        ConsentAction::Approve => ConsentKind::Approval,
        ConsentAction::Deny => ConsentKind::Denial,
        ConsentAction::Revoke => ConsentKind::Revocation,
    };
    ConsentEventRecord {
        source_id: authorized.ed25519_pubkey,
        session_id,
        request_id,
        kind,
        scope: format!(
            "operator {:?} (role {:?}) authorized {:?}",
            authorized.operator_id, authorized.role, authorized.action
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::OperatorRole;

    fn authorized(action: ConsentAction) -> AuthorizedConsentAction {
        AuthorizedConsentAction {
            action,
            operator_id: "alice".to_string(),
            role: OperatorRole::Approver,
            ed25519_pubkey: [0x11; 32],
        }
    }

    #[test]
    fn audit_event_attributes_operator_and_maps_action() {
        let session = Uuid::from_u128(1);
        let request = Uuid::from_u128(2);

        for (action, kind) in [
            (ConsentAction::Approve, ConsentKind::Approval),
            (ConsentAction::Deny, ConsentKind::Denial),
            (ConsentAction::Revoke, ConsentKind::Revocation),
        ] {
            let event = operator_consent_audit_event(&authorized(action), session, request);
            assert_eq!(event.source_id, [0x11; 32], "attributes the operator key");
            assert_eq!(event.session_id, session);
            assert_eq!(event.request_id, request);
            assert_eq!(event.kind, kind, "maps {action:?} to the right ConsentKind");
            assert!(event.scope.contains("alice"));
            assert!(event.scope.contains("Approver"));
        }
    }
}
