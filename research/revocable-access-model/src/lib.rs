//! Deterministic reference model for revocable delegated authority.
//!
//! Policy semantics only: this crate does not authenticate records, verify
//! signatures/content commitments, communicate with Holochain, prove DHT
//! convergence, or enforce operating-system effects. Callers must enforce
//! decisions at every lane and effect-commit boundary.

use std::collections::{BTreeMap, BTreeSet};

pub type DelegationId = String;

/// Exact-match resource identity; no wildcard or prefix semantics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Resource {
    pub domain: String,
    pub id: String,
}

/// Independently delegable operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Right {
    View,
    Input,
    ClipboardRead,
    ClipboardWrite,
    FileRead,
    FileWrite,
    Administer,
}

/// Proposal-only authority cannot be upgraded to execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthorityMode {
    ProposeOnly,
    Execute,
}

/// Immutable delegation statement. Times are Unix milliseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// Must commit cryptographically to every field in an integrating system.
    pub id: DelegationId,
    pub principal: String,
    /// Root issuer equals principal; child issuer equals parent holder.
    pub issuer: String,
    pub holder: String,
    pub resource: Resource,
    pub rights: BTreeSet<Right>,
    pub purpose: String,
    pub mode: AuthorityMode,
    pub not_before_ms: u64,
    /// Exclusive expiry.
    pub expires_at_ms: u64,
    pub authority_epoch: u64,
    pub parent: Option<DelegationId>,
    pub may_subdelegate: bool,
    /// Maximum remaining child edges; must strictly decrease.
    pub remaining_depth: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Denied,
    /// Missing or incomplete authority is never permission.
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    MissingRecord,
    IncompleteAuthority,
    Revoked,
    StaleEpoch,
    NotYetValid,
    Expired,
    Cycle,
    SubdelegationForbidden,
    ScopeAmplification,
    IssuerMismatch,
    RootIssuerMismatch,
    InvalidStatement,
    WrongResource,
    RightNotGranted,
    PurposeMismatch,
    ExecutionNotGranted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluation {
    pub decision: Decision,
    pub failure: Option<Failure>,
}

/// Concrete operation to authorize against a valid delegation lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    pub resource: Resource,
    pub right: Right,
    pub purpose: String,
    pub requires_execution: bool,
}

impl Evaluation {
    const fn allowed() -> Self { Self { decision: Decision::Allowed, failure: None } }
    const fn denied(f: Failure) -> Self { Self { decision: Decision::Denied, failure: Some(f) } }
    const fn unknown(f: Failure) -> Self { Self { decision: Decision::Indeterminate, failure: Some(f) } }
}

impl Delegation {
    fn well_formed(&self) -> bool {
        !self.id.is_empty()
            && !self.principal.is_empty()
            && !self.issuer.is_empty()
            && !self.holder.is_empty()
            && !self.purpose.is_empty()
            && !self.resource.domain.is_empty()
            && !self.resource.id.is_empty()
            && !self.rights.is_empty()
            && self.not_before_ms < self.expires_at_ms
    }

    /// Prove that this child is no broader than its parent.
    pub fn validate_child(&self, parent: &Self) -> Result<(), Failure> {
        if !self.well_formed() || !parent.well_formed() {
            return Err(Failure::InvalidStatement);
        }
        if !parent.may_subdelegate || parent.remaining_depth == 0 {
            return Err(Failure::SubdelegationForbidden);
        }
        if self.issuer != parent.holder {
            return Err(Failure::IssuerMismatch);
        }
        let mode_attenuates =
            parent.mode == AuthorityMode::Execute || self.mode == AuthorityMode::ProposeOnly;
        let contained = self.principal == parent.principal
            && self.resource == parent.resource
            && self.rights.is_subset(&parent.rights)
            && self.purpose == parent.purpose
            && mode_attenuates
            && self.not_before_ms >= parent.not_before_ms
            && self.expires_at_ms <= parent.expires_at_ms
            && self.authority_epoch == parent.authority_epoch
            && self.remaining_depth < parent.remaining_depth;
        if contained { Ok(()) } else { Err(Failure::ScopeAmplification) }
    }
}

/// Authority facts visible to one enforcement point. Revocation here means
/// this point has observed the revocation; it is not a global convergence claim.
#[derive(Debug, Clone, Default)]
pub struct AuthorityState {
    pub grants: BTreeMap<DelegationId, Delegation>,
    pub revoked: BTreeSet<DelegationId>,
    pub epochs: BTreeMap<String, u64>,
    pub complete: bool,
}

impl AuthorityState {
    /// Evaluate a grant and its entire lineage at the supplied instant.
    pub fn evaluate(&self, id: &str, now_ms: u64) -> Evaluation {
        if !self.complete { return Evaluation::unknown(Failure::IncompleteAuthority); }
        self.evaluate_inner(id, now_ms, &mut Vec::with_capacity(16))
    }

    fn evaluate_inner<'a>(
        &'a self,
        id: &'a str,
        now_ms: u64,
        visited: &mut Vec<&'a str>,
    ) -> Evaluation {
        if visited.contains(&id) { return Evaluation::denied(Failure::Cycle); }
        visited.push(id);
        let Some(grant) = self.grants.get(id) else {
            return Evaluation::unknown(Failure::MissingRecord);
        };
        if grant.id != id || !grant.well_formed() {
            return Evaluation::denied(Failure::InvalidStatement);
        }
        if self.revoked.contains(id) { return Evaluation::denied(Failure::Revoked); }
        match self.epochs.get(&grant.resource.domain) {
            Some(epoch) if *epoch == grant.authority_epoch => {}
            Some(_) => return Evaluation::denied(Failure::StaleEpoch),
            None => return Evaluation::unknown(Failure::MissingRecord),
        }
        if now_ms < grant.not_before_ms { return Evaluation::denied(Failure::NotYetValid); }
        if now_ms >= grant.expires_at_ms { return Evaluation::denied(Failure::Expired); }

        if let Some(parent_id) = &grant.parent {
            let Some(parent) = self.grants.get(parent_id) else {
                return Evaluation::unknown(Failure::MissingRecord);
            };
            // Walk first so a malformed cycle cannot be masked by a secondary
            // attenuation error. Parent authority must itself be current.
            let parent_result = self.evaluate_inner(parent_id, now_ms, visited);
            if parent_result.decision != Decision::Allowed { return parent_result; }
            if let Err(failure) = grant.validate_child(parent) {
                return Evaluation::denied(failure);
            }
        } else if grant.issuer != grant.principal {
            return Evaluation::denied(Failure::RootIssuerMismatch);
        }
        Evaluation::allowed()
    }

    /// Evaluate lineage and the concrete requested effect. A valid grant is
    /// not enough by itself: resource, right, purpose and execution mode must match.
    pub fn evaluate_request(&self, id: &str, request: &AccessRequest, now_ms: u64) -> Evaluation {
        let lineage = self.evaluate(id, now_ms);
        if lineage.decision != Decision::Allowed { return lineage; }
        let grant = &self.grants[id];
        if grant.resource != request.resource { return Evaluation::denied(Failure::WrongResource); }
        if !grant.rights.contains(&request.right) { return Evaluation::denied(Failure::RightNotGranted); }
        if grant.purpose != request.purpose { return Evaluation::denied(Failure::PurposeMismatch); }
        if request.requires_execution && grant.mode != AuthorityMode::Execute {
            return Evaluation::denied(Failure::ExecutionNotGranted);
        }
        Evaluation::allowed()
    }

    /// Alternative grants: any grant authorizing this exact request suffices.
    pub fn evaluate_independent_request(&self, ids: &[&str], request: &AccessRequest, now_ms: u64) -> Evaluation {
        let mut unknown = false;
        for id in ids {
            let result = self.evaluate_request(id, request, now_ms);
            match result.decision {
                Decision::Allowed => return result,
                Decision::Denied => {}
                Decision::Indeterminate => unknown = true,
            }
        }
        if unknown { Evaluation::unknown(Failure::MissingRecord) }
        else { Evaluation::denied(Failure::RightNotGranted) }
    }

    /// Every grant in a required bundle must authorize this exact request.
    pub fn evaluate_required_request(&self, ids: &[&str], request: &AccessRequest, now_ms: u64) -> Evaluation {
        if ids.is_empty() { return Evaluation::denied(Failure::InvalidStatement); }
        let mut unknown = false;
        for id in ids {
            let result = self.evaluate_request(id, request, now_ms);
            match result.decision {
                Decision::Denied => return result,
                Decision::Indeterminate => unknown = true,
                Decision::Allowed => {}
            }
        }
        if unknown { Evaluation::unknown(Failure::MissingRecord) } else { Evaluation::allowed() }
    }

    /// Alternative grants: any independently valid grant suffices (OR).
    /// An unknown candidate cannot override a known allowed grant.
    pub fn evaluate_independent(&self, ids: &[&str], now_ms: u64) -> Evaluation {
        let mut unknown = false;
        for id in ids {
            let result = self.evaluate(id, now_ms);
            match result.decision {
                Decision::Allowed => return result,
                Decision::Denied => {}
                Decision::Indeterminate => unknown = true,
            }
        }
        if unknown { Evaluation::unknown(Failure::MissingRecord) }
        else { Evaluation::denied(Failure::Revoked) }
    }

    /// Required bundle: every named grant must be current (AND).
    pub fn evaluate_required_bundle(&self, ids: &[&str], now_ms: u64) -> Evaluation {
        if ids.is_empty() { return Evaluation::denied(Failure::InvalidStatement); }
        let mut unknown = false;
        for id in ids {
            let result = self.evaluate(id, now_ms);
            match result.decision {
                Decision::Denied => return result,
                Decision::Indeterminate => unknown = true,
                Decision::Allowed => {}
            }
        }
        if unknown { Evaluation::unknown(Failure::MissingRecord) } else { Evaluation::allowed() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(id: &str, issuer: &str, holder: &str, parent: Option<&str>) -> Delegation {
        Delegation {
            id: id.into(), principal: "alice".into(), issuer: issuer.into(), holder: holder.into(),
            resource: Resource { domain: "home-a".into(), id: "host-1".into() },
            rights: [Right::View, Right::Input].into_iter().collect(),
            purpose: "support-session".into(), mode: AuthorityMode::Execute,
            not_before_ms: 100, expires_at_ms: 10_000, authority_epoch: 7,
            parent: parent.map(str::to_owned), may_subdelegate: true,
            remaining_depth: if parent.is_some() { 1 } else { 2 },
        }
    }

    fn state() -> AuthorityState {
        let root = grant("root", "alice", "bob", None);
        let mut child = grant("child", "bob", "carol", Some("root"));
        child.rights = [Right::View].into_iter().collect();
        let mut s = AuthorityState { complete: true, ..Default::default() };
        s.epochs.insert("home-a".into(), 7);
        s.grants.insert(root.id.clone(), root);
        s.grants.insert(child.id.clone(), child);
        s
    }

    #[test]
    fn valid_attenuating_child_is_allowed() {
        assert_eq!(state().evaluate("child", 500).decision, Decision::Allowed);
    }

    #[test]
    fn child_cannot_add_rights_or_extend_expiry() {
        let root = grant("root", "alice", "bob", None);
        let mut child = grant("child", "bob", "carol", Some("root"));
        child.rights.insert(Right::Administer);
        assert_eq!(child.validate_child(&root), Err(Failure::ScopeAmplification));
        child.rights.remove(&Right::Administer);
        child.expires_at_ms += 1;
        assert_eq!(child.validate_child(&root), Err(Failure::ScopeAmplification));
    }

    #[test]
    fn revoked_parent_invalidates_child() {
        let mut s = state();
        s.revoked.insert("root".into());
        assert_eq!(s.evaluate("child", 500).failure, Some(Failure::Revoked));
    }

    #[test]
    fn missing_parent_is_indeterminate() {
        let mut s = state();
        s.grants.remove("root");
        assert_eq!(s.evaluate("child", 500).decision, Decision::Indeterminate);
    }

    #[test]
    fn stale_epoch_denies() {
        let mut s = state();
        s.epochs.insert("home-a".into(), 8);
        assert_eq!(s.evaluate("root", 500).failure, Some(Failure::StaleEpoch));
    }

    #[test]
    fn incomplete_authority_is_indeterminate() {
        let mut s = state();
        s.complete = false;
        assert_eq!(s.evaluate("root", 500).decision, Decision::Indeterminate);
    }

    #[test]
    fn independent_grants_are_or_composed() {
        let mut s = state();
        s.grants.insert("other".into(), grant("other", "alice", "dave", None));
        s.revoked.insert("root".into());
        assert_eq!(s.evaluate_independent(&["root", "other"], 500).decision, Decision::Allowed);
    }

    #[test]
    fn required_bundle_is_and_composed() {
        let mut s = state();
        s.grants.insert("other".into(), grant("other", "alice", "dave", None));
        assert_eq!(s.evaluate_required_bundle(&["root", "other"], 500).decision, Decision::Allowed);
        s.revoked.insert("other".into());
        assert_eq!(s.evaluate_required_bundle(&["root", "other"], 500).failure, Some(Failure::Revoked));
    }

    #[test]
    fn time_bounds_are_enforced() {
        let s = state();
        assert_eq!(s.evaluate("root", 99).failure, Some(Failure::NotYetValid));
        assert_eq!(s.evaluate("root", 10_000).failure, Some(Failure::Expired));
    }

    #[test]
    fn cycle_is_detected_before_attenuation_checks() {
        let mut s = state();
        let mut root = s.grants.remove("root").unwrap();
        root.parent = Some("child".into());
        root.issuer = "carol".into();
        s.grants.insert("root".into(), root);
        assert_eq!(s.evaluate("root", 500).failure, Some(Failure::Cycle));
    }

    #[test]
    fn proposal_only_parent_cannot_delegate_execution() {
        let mut root = grant("root", "alice", "bob", None);
        root.mode = AuthorityMode::ProposeOnly;
        let child = grant("child", "bob", "carol", Some("root"));
        assert_eq!(child.validate_child(&root), Err(Failure::ScopeAmplification));
    }

    #[test]
    fn request_must_match_resource_right_and_purpose() {
        let s = state();
        let request = AccessRequest {
            resource: Resource { domain: "home-a".into(), id: "host-1".into() },
            right: Right::Input, purpose: "support-session".into(), requires_execution: true,
        };
        assert_eq!(s.evaluate_request("child", &request, 500).decision, Decision::Denied);
        let mut view = request.clone();
        view.right = Right::View;
        assert_eq!(s.evaluate_request("child", &view, 500).decision, Decision::Allowed);
        view.resource.id = "host-2".into();
        assert_eq!(s.evaluate_request("child", &view, 500).failure, Some(Failure::WrongResource));
    }

    #[test]
    fn proposal_only_grant_cannot_commit_effect() {
        let mut s = state();
        s.grants.get_mut("root").unwrap().mode = AuthorityMode::ProposeOnly;
        let request = AccessRequest {
            resource: Resource { domain: "home-a".into(), id: "host-1".into() },
            right: Right::View, purpose: "support-session".into(), requires_execution: true,
        };
        assert_eq!(s.evaluate_request("root", &request, 500).failure, Some(Failure::ExecutionNotGranted));
    }

    #[test]
    fn map_key_must_match_content_identifier() {
        let mut s = state();
        let mut altered = s.grants.remove("root").unwrap();
        altered.id = "different-id".into();
        s.grants.insert("root".into(), altered);
        assert_eq!(s.evaluate("root", 500).failure, Some(Failure::InvalidStatement));
    }

}
