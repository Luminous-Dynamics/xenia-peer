// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # xenia-operator-proto
//!
//! The **shared** operator-RBAC protocol: the role/action model and the exact
//! domain-separated byte transcripts an operator signs. Both the `xenia-peer`
//! daemon (which verifies) and the `sovereign-admin` browser console (which
//! signs) depend on this crate, so a signature produced in the browser is
//! byte-identical to what the daemon expects. If these transcripts lived in
//! two places they would drift; here they cannot.
//!
//! This crate is deliberately **signing-key-free and I/O-free** — roles,
//! actions, canonical transcript construction, and domain-separated hashing —
//! so it compiles unchanged for `wasm32-unknown-unknown` (the console) and
//! native (the daemon + tests). Each side brings its own Ed25519 / ML-DSA
//! implementation and signs/verifies the bytes this crate produces.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// Domain-separation tag for the challenge an operator signs to prove key
/// possession. Bump the `-vN` suffix on any breaking transcript change.
pub const CHALLENGE_DOMAIN: &[u8] = b"xenia-operator-auth-challenge-v1";

/// Domain-separation tag for a per-consent-action signature. Version 4
/// adds an explicit action id to the daemon-attested-offer binding, making
/// retries and replays independently attributable.
pub const CONSENT_ACTION_DOMAIN: &[u8] = b"xenia-operator-consent-action-v4";

/// Domain separator for a daemon-attested consent offer.
pub const CONSENT_OFFER_DOMAIN: &[u8] = b"xenia-operator-consent-offer-v2";

/// Domain-separation tag for an admin's signature authorizing the revocation of
/// another operator (the `/operator/revoke` admin action).
pub const REVOKE_OPERATOR_DOMAIN: &[u8] = b"xenia-operator-revoke-operator-v1";

/// Domain-separation tag for the daemon's *host identity* delegating trust
/// to its separate HTTP-auth signing key (see [`DaemonIdentityCertificate`]).
pub const DAEMON_DELEGATION_DOMAIN: &[u8] = b"xenia-daemon-identity-delegation-v1";

/// Domain-separation tag for the daemon's host-identity attestation over an
/// issued `/auth/challenge` nonce (see [`challenge_host_attestation_transcript`]).
pub const CHALLENGE_HOST_ATTESTATION_DOMAIN: &[u8] = b"xenia-challenge-host-attestation-v1";

/// Domain-separation tag for an operator session token's daemon signature
/// (see [`operator_token_canonical_bytes`]).
pub const OPERATOR_TOKEN_DOMAIN: &[u8] = b"xenia-operator-token-v1";

/// Domain-separation tag for an admin's signature authorizing a live
/// replacement of another operator's enrolled key material (the
/// `/operator/replace-key` admin action -- operator-key recovery).
pub const REPLACE_OPERATOR_KEY_DOMAIN: &[u8] = b"xenia-operator-replace-key-v1";

/// An operator's role. Strictly hierarchical: a higher role can do everything
/// a lower one can, plus more (see [`OperatorRole::rank`]). Serializes to the
/// variant name (`"Viewer"`, `"Admin"`, …) — the console gates its UI on the
/// same value the daemon authorizes against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorRole {
    /// Read-only: see inventory and the audit ledger.
    Viewer,
    /// Viewer + approve/deny/revoke a consent ceremony.
    Approver,
    /// Approver + initiate sessions.
    Operator,
    /// Operator + enroll/revoke operators, change trust policy, rotate keys.
    Admin,
}

impl OperatorRole {
    /// Ordering rank. Authorization is `actor.rank() >= action.min_role().rank()`.
    pub fn rank(self) -> u8 {
        match self {
            OperatorRole::Viewer => 0,
            OperatorRole::Approver => 1,
            OperatorRole::Operator => 2,
            OperatorRole::Admin => 3,
        }
    }

    /// Whether this role is permitted to perform `action`. Total and
    /// fail-closed by construction — identical logic on daemon and console.
    pub fn permits(self, action: OperatorAction) -> bool {
        self.rank() >= action.min_role().rank()
    }

    /// The role's stable string name (matches the serde representation).
    pub fn as_str(self) -> &'static str {
        match self {
            OperatorRole::Viewer => "Viewer",
            OperatorRole::Approver => "Approver",
            OperatorRole::Operator => "Operator",
            OperatorRole::Admin => "Admin",
        }
    }
}

/// A privileged operator action the daemon can be asked to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorAction {
    /// View device/session inventory.
    ViewInventory,
    /// Read the audit ledger.
    ReadAudit,
    /// Approve a consent ceremony.
    ApproveConsent,
    /// Deny a consent ceremony.
    DenyConsent,
    /// Revoke consent for a live session.
    RevokeConsent,
    /// Initiate a new session.
    InitiateSession,
    /// Change the sealed-evidence / consent trust policy.
    ChangePolicy,
    /// Enroll or revoke an operator.
    EnrollOperator,
    /// Rotate the host / consent signing keys.
    RotateKeys,
}

impl OperatorAction {
    /// The minimum role that may perform this action.
    pub fn min_role(self) -> OperatorRole {
        match self {
            OperatorAction::ViewInventory | OperatorAction::ReadAudit => OperatorRole::Viewer,
            OperatorAction::ApproveConsent
            | OperatorAction::DenyConsent
            | OperatorAction::RevokeConsent => OperatorRole::Approver,
            OperatorAction::InitiateSession => OperatorRole::Operator,
            OperatorAction::ChangePolicy
            | OperatorAction::EnrollOperator
            | OperatorAction::RotateKeys => OperatorRole::Admin,
        }
    }
}

/// Whether `role` is permitted to perform `action`. Free-function form of
/// [`OperatorRole::permits`], kept for call-site readability.
pub fn role_permits(role: OperatorRole, action: OperatorAction) -> bool {
    role.permits(action)
}

/// A consent decision an operator can authorize on a live/pending session.
/// Serializes to the variant name (`"Approve"`, `"Deny"`, `"Revoke"`),
/// byte-identical to [`Self::as_str`] -- used directly (not just via
/// `as_str`) by `xenia-operator-agent-proto`'s typed signing requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentAction {
    /// Grant the session.
    Approve,
    /// Refuse the session.
    Deny,
    /// End a session already granted (mid-session revocation).
    Revoke,
}

impl ConsentAction {
    /// The one-byte tag bound into the signed transcript. Stable wire value —
    /// do not renumber.
    pub fn tag(self) -> u8 {
        match self {
            ConsentAction::Approve => 1,
            ConsentAction::Deny => 2,
            ConsentAction::Revoke => 3,
        }
    }

    /// The RBAC action a consent decision requires.
    pub fn required_permission(self) -> OperatorAction {
        match self {
            ConsentAction::Approve => OperatorAction::ApproveConsent,
            ConsentAction::Deny => OperatorAction::DenyConsent,
            ConsentAction::Revoke => OperatorAction::RevokeConsent,
        }
    }

    /// The stable wire string for this action.
    pub fn as_str(self) -> &'static str {
        match self {
            ConsentAction::Approve => "Approve",
            ConsentAction::Deny => "Deny",
            ConsentAction::Revoke => "Revoke",
        }
    }

    /// Parse the wire string back into an action (exact, case-sensitive).
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "Approve" => Some(ConsentAction::Approve),
            "Deny" => Some(ConsentAction::Deny),
            "Revoke" => Some(ConsentAction::Revoke),
            _ => None,
        }
    }
}

/// Domain separator for the canonical consent-scope commitment.
pub const CONSENT_SCOPE_DOMAIN: &[u8] = b"xenia-operator-consent-scope-v1";

/// Display access granted by a consent offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentDisplayScope {
    /// Stream the host display to the viewer.
    ScreenStream,
}

impl ConsentDisplayScope {
    const fn tag(self) -> u8 {
        match self {
            Self::ScreenStream => 1,
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::ScreenStream => "screen stream",
        }
    }
}

/// Telemetry access granted by a consent offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentTelemetryScope {
    /// No host telemetry.
    Off,
    /// Basic CPU and memory performance telemetry.
    BasicHostPerformance,
    /// System identity and performance telemetry.
    SystemIdentityAndPerformance,
}

impl ConsentTelemetryScope {
    const fn tag(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::BasicHostPerformance => 1,
            Self::SystemIdentityAndPerformance => 2,
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::BasicHostPerformance => "basic host performance",
            Self::SystemIdentityAndPerformance => "system identity and performance",
        }
    }
}

/// Audio access granted by a consent offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentAudioScope {
    /// No audio.
    Off,
    /// A synthetic test signal generated by the daemon.
    SyntheticTestSignal,
    /// Capture audio from a host device.
    HostDeviceCapture,
}

impl ConsentAudioScope {
    const fn tag(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::SyntheticTestSignal => 1,
            Self::HostDeviceCapture => 2,
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::SyntheticTestSignal => "synthetic test signal",
            Self::HostDeviceCapture => "host device capture",
        }
    }
}

/// Remote input authority granted by a consent offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentInputScope {
    /// The viewer cannot inject input into the host.
    Off,
    /// The viewer may inject keyboard/pointer input into the host.
    RemoteInputInjection,
}

impl ConsentInputScope {
    const fn tag(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::RemoteInputInjection => 1,
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::RemoteInputInjection => "remote input injection",
        }
    }
}

/// Clipboard direction granted by a consent offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentClipboardScope {
    /// No clipboard exchange.
    Off,
    /// Host clipboard contents may be sent to the viewer.
    HostToViewer,
    /// Clipboard contents may flow in both directions.
    Bidirectional,
    /// Viewer clipboard contents may be applied to the host without exposing
    /// host clipboard contents in the reverse direction.
    ViewerToHost,
}

impl ConsentClipboardScope {
    const fn tag(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::HostToViewer => 1,
            Self::Bidirectional => 2,
            // Appended after the published v1 tags so existing canonical
            // Bidirectional commitments remain byte-for-byte stable.
            Self::ViewerToHost => 3,
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::HostToViewer => "host to viewer",
            Self::Bidirectional => "bidirectional",
            Self::ViewerToHost => "viewer to host",
        }
    }
}

/// File-transfer direction granted by a consent offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentFileTransferScope {
    /// No file transfer.
    Off,
    /// The host may send files to the viewer.
    HostToViewer,
    /// The viewer may send files to the host.
    ViewerToHost,
    /// Files may flow in both directions.
    Bidirectional,
}

impl ConsentFileTransferScope {
    const fn tag(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::HostToViewer => 1,
            Self::ViewerToHost => 2,
            Self::Bidirectional => 3,
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::HostToViewer => "host to viewer",
            Self::ViewerToHost => "viewer to host",
            Self::Bidirectional => "bidirectional",
        }
    }
}

/// Canonical, machine-readable consent scope. Human-readable text, audit
/// records, native confirmation prompts, and signature commitments must all
/// be derived from this value rather than parsed back from presentation text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentScopeV1 {
    /// Display access.
    pub display: ConsentDisplayScope,
    /// Telemetry access.
    pub telemetry: ConsentTelemetryScope,
    /// Audio access.
    pub audio: ConsentAudioScope,
    /// Remote input authority.
    pub input: ConsentInputScope,
    /// Clipboard direction.
    pub clipboard: ConsentClipboardScope,
    /// File-transfer direction.
    pub file_transfer: ConsentFileTransferScope,
}

impl ConsentScopeV1 {
    /// Construct the current screen-stream scope with selected telemetry and
    /// audio access.
    pub const fn screen(
        telemetry: ConsentTelemetryScope,
        audio: ConsentAudioScope,
    ) -> Self {
        Self {
            display: ConsentDisplayScope::ScreenStream,
            telemetry,
            audio,
            input: ConsentInputScope::Off,
            clipboard: ConsentClipboardScope::Off,
            file_transfer: ConsentFileTransferScope::Off,
        }
    }

    /// Construct a complete screen-stream scope. Every capability that an M1
    /// approval can unlock is explicit here, so the signed commitment cannot
    /// under-describe the actual grant.
    pub const fn screen_with_capabilities(
        telemetry: ConsentTelemetryScope,
        audio: ConsentAudioScope,
        input: ConsentInputScope,
        clipboard: ConsentClipboardScope,
        file_transfer: ConsentFileTransferScope,
    ) -> Self {
        Self {
            display: ConsentDisplayScope::ScreenStream,
            telemetry,
            audio,
            input,
            clipboard,
            file_transfer,
        }
    }

    /// The minimal screen-only scope used by focused protocol tests.
    pub const fn screen_only() -> Self {
        Self::screen(ConsentTelemetryScope::Off, ConsentAudioScope::Off)
    }

    /// Stable canonical bytes used for cryptographic commitments. The layout
    /// is deliberately independent of serde names and human-facing wording.
    ///
    /// Layout: `CONSENT_SCOPE_DOMAIN || version(1) || display(1) ||
    /// telemetry(1) || audio(1) || input(1) || clipboard(1) ||
    /// file_transfer(1)`.
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONSENT_SCOPE_DOMAIN.len() + 7);
        out.extend_from_slice(CONSENT_SCOPE_DOMAIN);
        out.push(1);
        out.push(self.display.tag());
        out.push(self.telemetry.tag());
        out.push(self.audio.tag());
        out.push(self.input.tag());
        out.push(self.clipboard.tag());
        out.push(self.file_transfer.tag());
        out
    }

    /// Domain-separated digest bound into a consent-action transcript.
    pub fn digest(self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// Human-readable summary derived from the canonical scope.
    pub fn summary(self) -> String {
        format!(
            "display: {}; telemetry: {}; audio: {}; input: {}; clipboard: {}; file transfer: {}",
            self.display.description(),
            self.telemetry.description(),
            self.audio.description(),
            self.input.description(),
            self.clipboard.description(),
            self.file_transfer.description()
        )
    }

}

/// Versioned local policy for classifying which factual consent scopes need an
/// additional native confirmation. This is deliberately separate from
/// [`ConsentScopeV1`]: the scope is stable protocol data, while organizations
/// may tighten or relax confirmation policy without changing canonical bytes or
/// invalidating existing signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRiskPolicyV1 {
    /// Confirm before exposing system identity telemetry.
    pub confirm_system_identity_telemetry: bool,
    /// Confirm before capturing a host audio device.
    pub confirm_host_device_audio: bool,
    /// Confirm before enabling remote input injection.
    pub confirm_remote_input: bool,
    /// Confirm before granting any clipboard direction.
    pub confirm_clipboard: bool,
    /// Confirm before granting any file-transfer direction.
    pub confirm_file_transfer: bool,
}

impl ConsentRiskPolicyV1 {
    /// The native operator-agent policy used by default.
    pub const fn operator_agent_default() -> Self {
        Self {
            confirm_system_identity_telemetry: true,
            confirm_host_device_audio: true,
            confirm_remote_input: true,
            confirm_clipboard: true,
            confirm_file_transfer: true,
        }
    }

    /// Whether approving `scope` requires native confirmation under this
    /// policy. Denial and revocation remain fail-safe actions handled by the
    /// caller and should not be blocked by this classification.
    pub const fn requires_native_confirmation(self, scope: ConsentScopeV1) -> bool {
        (self.confirm_system_identity_telemetry
            && matches!(
                scope.telemetry,
                ConsentTelemetryScope::SystemIdentityAndPerformance
            ))
            || (self.confirm_host_device_audio
                && matches!(scope.audio, ConsentAudioScope::HostDeviceCapture))
            || (self.confirm_remote_input
                && matches!(scope.input, ConsentInputScope::RemoteInputInjection))
            || (self.confirm_clipboard
                && !matches!(scope.clipboard, ConsentClipboardScope::Off))
            || (self.confirm_file_transfer
                && !matches!(scope.file_transfer, ConsentFileTransferScope::Off))
    }
}

impl Default for ConsentRiskPolicyV1 {
    fn default() -> Self {
        Self::operator_agent_default()
    }
}

/// Default policy used by the native operator signing agent.
pub const DEFAULT_CONSENT_RISK_POLICY: ConsentRiskPolicyV1 =
    ConsentRiskPolicyV1::operator_agent_default();

/// A daemon-authored consent offer. The host identity signs the canonical
/// bytes of this structure before the browser sees it, allowing the native
/// agent to reject fabricated or modified session/transcript/scope data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentOfferV2 {
    /// Session to which the offer applies.
    pub session_id: [u8; 16],
    /// Canonical viewer-handshake transcript hash for the session being granted.
    /// This commits the offer to the actual authenticated transport/session, not
    /// only to an application-generated session identifier.
    pub session_transcript_hash: [u8; 32],
    /// Canonical access scope.
    pub scope: ConsentScopeV1,
    /// Offer creation time, Unix seconds.
    pub issued_at: u64,
    /// Last Unix second at which the offer may be approved. A later `Revoke`
    /// remains valid for the live session: expiry closes the grant window, not
    /// the operator's ability to withdraw an already-issued grant.
    pub expires_at: u64,
}

impl ConsentOfferV2 {
    /// Construct an offer. Callers should ensure `expires_at >= issued_at`.
    pub const fn new(
        session_id: [u8; 16],
        session_transcript_hash: [u8; 32],
        scope: ConsentScopeV1,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            session_id,
            session_transcript_hash,
            scope,
            issued_at,
            expires_at,
        }
    }

    /// Stable canonical bytes signed by the daemon host identity.
    ///
    /// Layout: `CONSENT_OFFER_DOMAIN || session_id(16) ||
    /// session_transcript_hash(32) || scope_digest(32) || issued_at(8, be) ||
    /// expires_at(8, be)`.
    pub fn canonical_bytes(self) -> Vec<u8> {
        let scope_digest = self.scope.digest();
        let mut out = Vec::with_capacity(CONSENT_OFFER_DOMAIN.len() + 16 + 32 + 32 + 8 + 8);
        out.extend_from_slice(CONSENT_OFFER_DOMAIN);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.session_transcript_hash);
        out.extend_from_slice(&scope_digest);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    /// Digest bound into an operator consent-action signature.
    pub fn digest(self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// Whether the offer's time interval is internally well formed.
    pub const fn has_valid_interval(self) -> bool {
        self.expires_at >= self.issued_at
    }

    /// Whether the offer's issuance time is plausible at `now`, allowing a
    /// bounded positive clock skew between daemon and agent.
    pub const fn is_issued_by(self, now: u64, clock_skew_secs: u64) -> bool {
        self.has_valid_interval() && self.issued_at <= now.saturating_add(clock_skew_secs)
    }

    /// Validate the approval window using caller-supplied wall-clock time and
    /// bounded clock skew. This check is intentionally approval-specific:
    /// revocation must remain possible after the original grant window closes.
    pub const fn can_approve_at(self, now: u64, clock_skew_secs: u64) -> bool {
        self.is_issued_by(now, clock_skew_secs)
            && now <= self.expires_at.saturating_add(clock_skew_secs)
    }

    /// Strict approval-window validation with no clock-skew allowance.
    pub const fn is_valid_at(self, now: u64) -> bool {
        self.can_approve_at(now, 0) && now >= self.issued_at
    }
}

/// A consent offer plus the daemon host identity's hybrid signatures over its
/// canonical bytes. The browser relays this envelope but cannot modify it
/// without invalidating both signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedConsentOfferV2 {
    /// The typed offer.
    pub offer: ConsentOfferV2,
    /// Host Ed25519 signature over [`ConsentOfferV2::canonical_bytes`], hex.
    pub host_ed_signature_hex: String,
    /// Host ML-DSA-65 signature over the same bytes, hex.
    pub host_ml_dsa_signature_hex: String,
}

/// The transcript an operator signs to prove possession of their key for a
/// given challenge. Domain-separated and bound to the exact keys presented, so
/// a signature can't be replayed against a different challenge or key.
///
/// Layout: `CHALLENGE_DOMAIN || nonce(32) || ed_pubkey(32) || ml_dsa_pubkey`.
pub fn challenge_transcript(
    nonce: &[u8; 32],
    ed_pubkey: &[u8; 32],
    ml_dsa_pubkey: &[u8],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(CHALLENGE_DOMAIN.len() + 32 + 32 + ml_dsa_pubkey.len());
    t.extend_from_slice(CHALLENGE_DOMAIN);
    t.extend_from_slice(nonce);
    t.extend_from_slice(ed_pubkey);
    t.extend_from_slice(ml_dsa_pubkey);
    t
}

/// The bytes an operator signs to authorize a specific consent action.
/// The daemon-attested offer digest commits to the exact session, canonical
/// scope, and offer lifetime; the token nonce prevents reuse under another
/// operator session token, while the action id identifies this exact decision.
///
/// Layout: `CONSENT_ACTION_DOMAIN || action.tag()(1) || action_id(16) ||
/// token_nonce(16) || offer_digest(32)`.
///
/// `action_id` is a caller-generated UUID encoded as 16 raw bytes. Binding it
/// makes every intentional decision independently attributable and lets the
/// daemon distinguish a replay from a fresh operator action even when action,
/// token, and offer are otherwise identical.
pub fn consent_action_transcript(
    action: ConsentAction,
    action_id: &[u8; 16],
    token_nonce: &[u8; 16],
    offer_digest: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(CONSENT_ACTION_DOMAIN.len() + 1 + 16 + 16 + 32);
    t.extend_from_slice(CONSENT_ACTION_DOMAIN);
    t.push(action.tag());
    t.extend_from_slice(action_id);
    t.extend_from_slice(token_nonce);
    t.extend_from_slice(offer_digest);
    t
}

/// The bytes an Admin signs to authorize revoking `target_operator_id`. Bound to
/// the admin's current token (via `token_nonce`) so a captured signature can't
/// be replayed against a different token; the target id is length-prefixed so it
/// can't be ambiguously concatenated with the trailing nonce.
///
/// Layout: `REVOKE_OPERATOR_DOMAIN || len(target)(4, be) || target || token_nonce(16)`.
pub fn revoke_operator_transcript(target_operator_id: &str, token_nonce: &[u8; 16]) -> Vec<u8> {
    let target = target_operator_id.as_bytes();
    let mut t = Vec::with_capacity(REVOKE_OPERATOR_DOMAIN.len() + 4 + target.len() + 16);
    t.extend_from_slice(REVOKE_OPERATOR_DOMAIN);
    t.extend_from_slice(&(target.len() as u32).to_be_bytes());
    t.extend_from_slice(target);
    t.extend_from_slice(token_nonce);
    t
}

/// The bytes an Admin signs to authorize replacing `target_operator_id`'s
/// enrolled key material -- operator-key recovery: an operator who lost
/// their signing key gets a fresh identity re-enrolled under the same id
/// and role, authorized by a *different*, still-enrolled Admin. Bound to
/// the admin's current token (via `token_nonce`) and to every byte of the
/// new key material, so a captured signature can't be replayed against a
/// different token, target, or key.
///
/// This crate deliberately carries no cryptographic key-length constants
/// (see the module doc comment), so every variable-length field --
/// including the two fixed-length keys, whose lengths differ by suite --
/// is explicitly length-prefixed rather than assumed.
///
/// Layout: `REPLACE_OPERATOR_KEY_DOMAIN || len(target)(4, be) || target ||
/// len(new_ed25519_pubkey)(4, be) || new_ed25519_pubkey ||
/// len(new_ml_dsa_pubkey)(4, be) || new_ml_dsa_pubkey || has_87(1) ||
/// [len(new_ml_dsa_87_pubkey)(4, be) || new_ml_dsa_87_pubkey if has_87] ||
/// token_nonce(16)`.
pub fn replace_operator_key_transcript(
    target_operator_id: &str,
    new_ed25519_pubkey: &[u8],
    new_ml_dsa_pubkey: &[u8],
    new_ml_dsa_87_pubkey: Option<&[u8]>,
    token_nonce: &[u8; 16],
) -> Vec<u8> {
    let target = target_operator_id.as_bytes();
    let mut t = Vec::with_capacity(
        REPLACE_OPERATOR_KEY_DOMAIN.len()
            + 4
            + target.len()
            + 4
            + new_ed25519_pubkey.len()
            + 4
            + new_ml_dsa_pubkey.len()
            + 1
            + new_ml_dsa_87_pubkey.map(|k| 4 + k.len()).unwrap_or(0)
            + 16,
    );
    t.extend_from_slice(REPLACE_OPERATOR_KEY_DOMAIN);
    t.extend_from_slice(&(target.len() as u32).to_be_bytes());
    t.extend_from_slice(target);
    t.extend_from_slice(&(new_ed25519_pubkey.len() as u32).to_be_bytes());
    t.extend_from_slice(new_ed25519_pubkey);
    t.extend_from_slice(&(new_ml_dsa_pubkey.len() as u32).to_be_bytes());
    t.extend_from_slice(new_ml_dsa_pubkey);
    match new_ml_dsa_87_pubkey {
        Some(k) => {
            t.push(1);
            t.extend_from_slice(&(k.len() as u32).to_be_bytes());
            t.extend_from_slice(k);
        }
        None => t.push(0),
    }
    t.extend_from_slice(token_nonce);
    t
}

/// The bytes the daemon's *host identity* signs to delegate trust to its
/// separate HTTP-auth signing identity: "this Ed25519 key and this ML-DSA-65
/// key together issue this daemon's HTTP auth tokens and challenge
/// attestations." Exists because the daemon deliberately uses different keys
/// for different roles -- `host_identity_key_path` (the sealed-channel
/// identity, the one thing peers already pin) and `operator_key_path`
/// (`daemon_key`, which signs HTTP session tokens -- and the ledger's hash
/// chain, so it can't simply be replaced wholesale) -- and a caller with no
/// live connection to the daemon (e.g. the operator agent) has no other way
/// to learn that the HTTP-auth identity is genuinely vouched for by the host
/// identity. See [`DaemonIdentityCertificate`].
///
/// `http_auth_ml_dsa_pubkey` is a *separate* key from `daemon_key`'s own
/// Ed25519 key, not a second algorithm bolted onto the same keypair --
/// `xenia-peer`'s `operator_key_path` predates this hybridization and stays
/// Ed25519-only (see above), so the ML-DSA half of HTTP-auth token signing
/// lives in its own dedicated `xenia_handshake::MlDsaIdentity`.
///
/// Layout: `DAEMON_DELEGATION_DOMAIN || http_auth_ed25519_pubkey(32) ||
/// http_auth_ml_dsa_pubkey(1952)`.
pub fn daemon_delegation_transcript(
    http_auth_ed25519_pubkey: &[u8; 32],
    http_auth_ml_dsa_pubkey: &[u8],
) -> Vec<u8> {
    let mut t =
        Vec::with_capacity(DAEMON_DELEGATION_DOMAIN.len() + 32 + http_auth_ml_dsa_pubkey.len());
    t.extend_from_slice(DAEMON_DELEGATION_DOMAIN);
    t.extend_from_slice(http_auth_ed25519_pubkey);
    t.extend_from_slice(http_auth_ml_dsa_pubkey);
    t
}

/// The bytes the daemon's host identity signs to attest that it issued a
/// specific `/auth/challenge` nonce. Lets a caller with no live connection
/// to the daemon (the operator agent) verify that a *specific* nonce really
/// came from a host it trusts, rather than trusting a caller-supplied label
/// detached from the bytes actually being signed.
///
/// Layout: `CHALLENGE_HOST_ATTESTATION_DOMAIN || nonce(32)`.
pub fn challenge_host_attestation_transcript(nonce: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(CHALLENGE_HOST_ATTESTATION_DOMAIN.len() + 32);
    t.extend_from_slice(CHALLENGE_HOST_ATTESTATION_DOMAIN);
    t.extend_from_slice(nonce);
    t
}

/// The canonical bytes an operator session token's daemon signature covers.
/// Exposed here (rather than living only inside the daemon's own auth
/// module) so a caller that never talks to the daemon directly -- the
/// operator agent, verifying a token the browser relayed to it -- can
/// reconstruct the exact same bytes and independently check the token's
/// signature, with no risk of the two implementations drifting apart.
///
/// Layout: `OPERATOR_TOKEN_DOMAIN || len(operator_id)(8, le) || operator_id
/// || role_tag(1) || issued_at(8, le) || expires_at(8, le) || token_nonce(16)`.
pub fn operator_token_canonical_bytes(
    operator_id: &str,
    role: OperatorRole,
    issued_at: u64,
    expires_at: u64,
    token_nonce: &[u8; 16],
) -> Vec<u8> {
    let id = operator_id.as_bytes();
    let mut b = Vec::with_capacity(OPERATOR_TOKEN_DOMAIN.len() + 8 + id.len() + 1 + 8 + 8 + 16);
    b.extend_from_slice(OPERATOR_TOKEN_DOMAIN);
    b.extend_from_slice(&(id.len() as u64).to_le_bytes());
    b.extend_from_slice(id);
    b.push(role_tag(role));
    b.extend_from_slice(&issued_at.to_le_bytes());
    b.extend_from_slice(&expires_at.to_le_bytes());
    b.extend_from_slice(token_nonce);
    b
}

/// Stable one-byte wire tag for a role, used inside
/// [`operator_token_canonical_bytes`]. Not the same as any serde
/// representation -- this is a fixed-width tag inside a signed byte
/// transcript, not JSON.
fn role_tag(role: OperatorRole) -> u8 {
    match role {
        OperatorRole::Viewer => 0,
        OperatorRole::Approver => 1,
        OperatorRole::Operator => 2,
        OperatorRole::Admin => 3,
    }
}

/// The daemon's host identity vouching for its separate HTTP-auth signing
/// key (see [`daemon_delegation_transcript`]). Computed once by the daemon
/// at startup (both keys are static for the process's lifetime) and served
/// over `GET /auth/daemon-identity` -- no authentication required, since
/// this *is* the daemon's own public, independently-verifiable identity
/// evidence, the same trust model as the sealed-channel handshake's host
/// identity.
///
/// A caller verifies both signatures against the presented host public
/// keys, then computes the daemon's fingerprint itself via
/// `xenia_handshake::host_identity_fingerprint(host_ed25519_pubkey,
/// host_ml_dsa_pubkey)` -- never accepting a fingerprint asserted directly
/// by an untrusted caller. Both Ed25519 and ML-DSA-65 signatures are
/// required (no classical-only fallback), matching this project's hybrid
/// posture everywhere else a daemon or peer identity is proven.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonIdentityCertificate {
    /// The daemon's host (sealed-channel) identity Ed25519 public key, hex.
    pub host_ed25519_pubkey: String,
    /// The daemon's host (sealed-channel) identity ML-DSA-65 public key, hex.
    pub host_ml_dsa_pubkey: String,
    /// The daemon's separate HTTP-auth signing identity's Ed25519 public
    /// key, hex -- together with `http_auth_ml_dsa_pubkey`, the pair that
    /// actually signs issued session tokens and challenge attestations.
    pub http_auth_ed25519_pubkey: String,
    /// The daemon's separate HTTP-auth signing identity's ML-DSA-65 public
    /// key, hex. A distinct key from `http_auth_ed25519_pubkey`'s pair, not
    /// the same key under a different algorithm -- see
    /// [`daemon_delegation_transcript`]'s doc comment for why.
    pub http_auth_ml_dsa_pubkey: String,
    /// Host identity's Ed25519 signature over
    /// `daemon_delegation_transcript(http_auth_ed25519_pubkey,
    /// http_auth_ml_dsa_pubkey)`, hex.
    pub host_ed_signature: String,
    /// Host identity's ML-DSA-65 signature over the same transcript, hex.
    pub host_ml_dsa_signature: String,
}

/// The daemon's `--operators-file` enrollment record shape, shared so the
/// console (which generates one per identity) and the daemon (which parses
/// it) can never drift on field names or casing -- the exact drift that let
/// the console's high-security identity go unenrollable: the console had no
/// shared type to generate the record from, so it never emitted an
/// `ml_dsa_87_pubkey` field, and the daemon's ad hoc parser only ever
/// recognized the ML-DSA-65 key length.
///
/// `ml_dsa_pubkey` (ML-DSA-65) is required -- every operator has a standard
/// identity, since the HTTP challenge/response auth ceremony
/// (`/auth/challenge` + `/auth/verify`) always uses it regardless of which
/// suite the sealed channel later negotiates. `ml_dsa_87_pubkey` is optional:
/// only an operator who will use the high-security sealed channel needs one
/// enrolled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorEnrollmentRecord {
    /// The operator id an admin assigns when enrolling this identity.
    pub operator_id: String,
    /// Ed25519 public key, hex-encoded.
    pub ed25519_pubkey: String,
    /// ML-DSA-65 public key, hex-encoded (the standard-suite identity).
    pub ml_dsa_pubkey: String,
    /// ML-DSA-87 public key, hex-encoded (the high-security-suite identity).
    /// Present only if this operator has enrolled for the high-security
    /// sealed channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_dsa_87_pubkey: Option<String>,
    /// The role this enrollment grants.
    pub role: OperatorRole,
}

impl OperatorEnrollmentRecord {
    /// Serialize to the exact JSON object shape the daemon's
    /// `--operators-file` `operators` array element expects.
    pub fn to_json_string(&self) -> String {
        // `OperatorEnrollmentRecord` derives `Serialize` with no custom
        // field renaming, so this can't drift from the struct's own field
        // names -- unlike hand-built `serde_json::json!` call sites, which
        // is exactly how the console's `ml_dsa_87_pubkey` field went missing
        // in the first place.
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct ConsentConformanceFixture {
        schema: String,
        vectors: Vec<ConsentConformanceVector>,
    }

    #[derive(serde::Deserialize)]
    struct ConsentConformanceVector {
        name: String,
        scope: ConsentScopeV1,
        session_id_hex: String,
        session_transcript_hash_hex: String,
        issued_at: u64,
        expires_at: u64,
        action: ConsentAction,
        action_id_hex: String,
        token_nonce_hex: String,
        scope_canonical_hex: String,
        scope_digest_hex: String,
        offer_canonical_hex: String,
        offer_digest_hex: String,
        action_transcript_hex: String,
    }

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2, "unexpected hex length");
        let mut out = [0u8; N];
        for (index, byte) in out.iter_mut().enumerate() {
            let pair = &value[index * 2..index * 2 + 2];
            *byte = u8::from_str_radix(pair, 16).expect("fixture contains valid hex");
        }
        out
    }

    fn encode_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
        }
        out
    }

    #[test]
    fn consent_v3_conformance_vectors_are_stable() {
        let fixture: ConsentConformanceFixture = serde_json::from_str(include_str!(
            "../fixtures/consent-v3.json"
        ))
        .expect("consent conformance fixture parses");
        assert_eq!(fixture.schema, "xenia-consent-conformance-v3");
        assert!(!fixture.vectors.is_empty());

        for vector in fixture.vectors {
            let session_id = decode_hex::<16>(&vector.session_id_hex);
            let session_transcript_hash =
                decode_hex::<32>(&vector.session_transcript_hash_hex);
            let action_id = decode_hex::<16>(&vector.action_id_hex);
            let token_nonce = decode_hex::<16>(&vector.token_nonce_hex);
            let offer = ConsentOfferV2::new(
                session_id,
                session_transcript_hash,
                vector.scope,
                vector.issued_at,
                vector.expires_at,
            );
            let scope_digest = vector.scope.digest();
            let offer_digest = offer.digest();
            let action_transcript =
                consent_action_transcript(vector.action, &action_id, &token_nonce, &offer_digest);

            assert_eq!(
                encode_hex(&vector.scope.canonical_bytes()),
                vector.scope_canonical_hex,
                "{} scope canonical bytes drifted",
                vector.name
            );
            assert_eq!(
                encode_hex(&scope_digest),
                vector.scope_digest_hex,
                "{} scope digest drifted",
                vector.name
            );
            assert_eq!(
                encode_hex(&offer.canonical_bytes()),
                vector.offer_canonical_hex,
                "{} offer canonical bytes drifted",
                vector.name
            );
            assert_eq!(
                encode_hex(&offer_digest),
                vector.offer_digest_hex,
                "{} offer digest drifted",
                vector.name
            );
            assert_eq!(
                encode_hex(&action_transcript),
                vector.action_transcript_hex,
                "{} action transcript drifted",
                vector.name
            );
        }
    }

    #[test]
    fn role_hierarchy_is_fail_closed() {
        use OperatorAction::*;
        use OperatorRole::*;
        assert!(Viewer.permits(ViewInventory));
        assert!(Viewer.permits(ReadAudit));
        assert!(!Viewer.permits(ApproveConsent));
        assert!(Approver.permits(RevokeConsent));
        assert!(!Approver.permits(InitiateSession));
        assert!(Operator.permits(InitiateSession));
        assert!(!Operator.permits(EnrollOperator));
        for action in [
            ViewInventory,
            ReadAudit,
            ApproveConsent,
            DenyConsent,
            RevokeConsent,
            InitiateSession,
            ChangePolicy,
            EnrollOperator,
            RotateKeys,
        ] {
            assert!(Admin.permits(action), "admin denied {action:?}");
        }
        // free-fn form agrees with the method
        assert_eq!(
            role_permits(Approver, ApproveConsent),
            Approver.permits(ApproveConsent)
        );
    }

    #[test]
    fn role_serde_is_the_variant_name() {
        assert_eq!(
            serde_json::to_string(&OperatorRole::Admin).unwrap(),
            "\"Admin\""
        );
        let r: OperatorRole = serde_json::from_str("\"Approver\"").unwrap();
        assert_eq!(r, OperatorRole::Approver);
        assert_eq!(OperatorRole::Operator.as_str(), "Operator");
    }

    #[test]
    fn enrollment_record_round_trips_with_and_without_the_highsec_key() {
        let with_highsec = OperatorEnrollmentRecord {
            operator_id: "alice".to_string(),
            ed25519_pubkey: "aa".repeat(32),
            ml_dsa_pubkey: "bb".repeat(1952),
            ml_dsa_87_pubkey: Some("cc".repeat(2592)),
            role: OperatorRole::Admin,
        };
        let json = with_highsec.to_json_string();
        assert!(json.contains("ml_dsa_87_pubkey"));
        let parsed: OperatorEnrollmentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, with_highsec);

        let without_highsec = OperatorEnrollmentRecord {
            ml_dsa_87_pubkey: None,
            ..with_highsec
        };
        let json = without_highsec.to_json_string();
        // Omitted, not null -- so a daemon parser that only checks
        // `.contains_key(...)` (rather than treating an explicit null as
        // "absent") can't be tricked either way.
        assert!(!json.contains("ml_dsa_87_pubkey"));
        let parsed: OperatorEnrollmentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, without_highsec);
    }

    #[test]
    fn consent_action_tags_and_permissions_are_stable() {
        assert_eq!(ConsentAction::Approve.tag(), 1);
        assert_eq!(ConsentAction::Deny.tag(), 2);
        assert_eq!(ConsentAction::Revoke.tag(), 3);
        assert_eq!(
            ConsentAction::Revoke.required_permission(),
            OperatorAction::RevokeConsent
        );
        assert_eq!(
            ConsentAction::from_wire("Approve"),
            Some(ConsentAction::Approve)
        );
        assert_eq!(ConsentAction::from_wire("approve"), None);
        assert_eq!(ConsentAction::from_wire("nonsense"), None);
        assert_eq!(ConsentAction::Deny.as_str(), "Deny");
    }

    #[test]
    fn consent_action_serde_is_the_variant_name() {
        assert_eq!(
            serde_json::to_string(&ConsentAction::Revoke).unwrap(),
            "\"Revoke\""
        );
        let a: ConsentAction = serde_json::from_str("\"Deny\"").unwrap();
        assert_eq!(a, ConsentAction::Deny);
    }

    #[test]
    fn challenge_transcript_layout_is_exact() {
        let nonce = [0xABu8; 32];
        let ed = [0xCDu8; 32];
        let ml = vec![0xEFu8; 7];
        let t = challenge_transcript(&nonce, &ed, &ml);
        assert_eq!(&t[..CHALLENGE_DOMAIN.len()], CHALLENGE_DOMAIN);
        let mut off = CHALLENGE_DOMAIN.len();
        assert_eq!(&t[off..off + 32], &nonce);
        off += 32;
        assert_eq!(&t[off..off + 32], &ed);
        off += 32;
        assert_eq!(&t[off..], &ml[..]);
        assert_eq!(t.len(), CHALLENGE_DOMAIN.len() + 32 + 32 + 7);
    }

    #[test]
    fn consent_transcript_layout_is_exact_and_action_bound() {
        let action_id = [0x33u8; 16];
        let tn = [0x22u8; 16];
        let offer = ConsentOfferV2::new(
            [0x11u8; 16],
            [0x55u8; 32],
            ConsentScopeV1::screen_only(),
            100,
            200,
        );
        let offer_digest = offer.digest();
        let approve = consent_action_transcript(
            ConsentAction::Approve,
            &action_id,
            &tn,
            &offer_digest,
        );
        let revoke = consent_action_transcript(
            ConsentAction::Revoke,
            &action_id,
            &tn,
            &offer_digest,
        );
        // Same session/token, different action -> different bytes (can't replay).
        assert_ne!(approve, revoke);
        assert_eq!(
            &approve[..CONSENT_ACTION_DOMAIN.len()],
            CONSENT_ACTION_DOMAIN
        );
        assert_eq!(approve[CONSENT_ACTION_DOMAIN.len()], 1);
        assert_eq!(revoke[CONSENT_ACTION_DOMAIN.len()], 3);
        let action_id_start = CONSENT_ACTION_DOMAIN.len() + 1;
        assert_eq!(&approve[action_id_start..action_id_start + 16], &action_id);
        assert_eq!(
            approve.len(),
            CONSENT_ACTION_DOMAIN.len() + 1 + 16 + 16 + 32
        );
        assert_eq!(&approve[approve.len() - 32..], &offer_digest);
        assert_ne!(
            approve,
            consent_action_transcript(
                ConsentAction::Approve,
                &[0x44u8; 16],
                &tn,
                &offer_digest,
            ),
            "action id must be signature-bound"
        );
    }

    #[test]
    fn consent_scope_is_canonical_text_independent_and_field_bound() {
        let minimal = ConsentScopeV1::screen_only();
        let system = ConsentScopeV1::screen(
            ConsentTelemetryScope::SystemIdentityAndPerformance,
            ConsentAudioScope::Off,
        );
        assert_eq!(minimal.digest(), minimal.digest());
        assert_ne!(minimal.digest(), system.digest());
        assert_eq!(
            minimal.summary(),
            "display: screen stream; telemetry: off; audio: off; input: off; clipboard: off; file transfer: off"
        );
        assert_eq!(minimal.canonical_bytes().len(), CONSENT_SCOPE_DOMAIN.len() + 7);

        let complete = ConsentScopeV1::screen_with_capabilities(
            ConsentTelemetryScope::BasicHostPerformance,
            ConsentAudioScope::SyntheticTestSignal,
            ConsentInputScope::RemoteInputInjection,
            ConsentClipboardScope::Bidirectional,
            ConsentFileTransferScope::ViewerToHost,
        );
        assert_ne!(minimal.digest(), complete.digest());

        let viewer_to_host = ConsentScopeV1::screen_with_capabilities(
            ConsentTelemetryScope::Off,
            ConsentAudioScope::Off,
            ConsentInputScope::Off,
            ConsentClipboardScope::ViewerToHost,
            ConsentFileTransferScope::Off,
        );
        assert_eq!(
            viewer_to_host.canonical_bytes()[CONSENT_SCOPE_DOMAIN.len() + 5],
            3,
            "new one-way clipboard tag must not renumber published v1 tags"
        );
        assert_eq!(
            viewer_to_host.summary(),
            "display: screen stream; telemetry: off; audio: off; input: off; clipboard: viewer to host; file transfer: off"
        );
    }

    #[test]
    fn consent_offer_is_scope_session_and_time_bound() {
        let transcript_hash = [0x44u8; 32];
        let base = ConsentOfferV2::new(
            [1u8; 16],
            transcript_hash,
            ConsentScopeV1::screen_only(),
            100,
            200,
        );
        let other_session = ConsentOfferV2::new(
            [2u8; 16],
            transcript_hash,
            base.scope,
            100,
            200,
        );
        let other_transcript = ConsentOfferV2::new(
            [1u8; 16],
            [0x45u8; 32],
            base.scope,
            100,
            200,
        );
        let other_scope = ConsentOfferV2::new(
            [1u8; 16],
            transcript_hash,
            ConsentScopeV1::screen(
                ConsentTelemetryScope::SystemIdentityAndPerformance,
                ConsentAudioScope::Off,
            ),
            100,
            200,
        );
        let other_expiry = ConsentOfferV2::new(
            [1u8; 16],
            transcript_hash,
            base.scope,
            100,
            201,
        );
        assert_ne!(base.digest(), other_session.digest());
        assert_ne!(base.digest(), other_transcript.digest());
        assert_ne!(base.digest(), other_scope.digest());
        assert_ne!(base.digest(), other_expiry.digest());
        assert!(base.is_valid_at(150));
        assert!(!base.is_valid_at(99));
        assert!(!base.is_valid_at(201));
        assert!(base.can_approve_at(99, 1));
        assert!(base.can_approve_at(201, 1));
        assert!(base.is_issued_by(250, 0));
        assert!(DEFAULT_CONSENT_RISK_POLICY.requires_native_confirmation(other_scope.scope));
        assert!(!DEFAULT_CONSENT_RISK_POLICY.requires_native_confirmation(base.scope));

        let remote_control = ConsentScopeV1::screen_with_capabilities(
            ConsentTelemetryScope::Off,
            ConsentAudioScope::Off,
            ConsentInputScope::RemoteInputInjection,
            ConsentClipboardScope::Off,
            ConsentFileTransferScope::Off,
        );
        assert!(DEFAULT_CONSENT_RISK_POLICY.requires_native_confirmation(remote_control));

        let permissive = ConsentRiskPolicyV1 {
            confirm_system_identity_telemetry: false,
            confirm_host_device_audio: false,
            confirm_remote_input: false,
            confirm_clipboard: false,
            confirm_file_transfer: false,
        };
        assert!(!permissive.requires_native_confirmation(other_scope.scope));
        assert!(!permissive.requires_native_confirmation(remote_control));
    }

    #[test]
    fn daemon_delegation_transcript_layout_is_exact_and_key_bound() {
        let ed_a = [0x33u8; 32];
        let ed_b = [0x44u8; 32];
        let ml_a = vec![0x55u8; 1952];
        let ml_b = vec![0x66u8; 1952];
        let t = daemon_delegation_transcript(&ed_a, &ml_a);
        assert_eq!(
            &t[..DAEMON_DELEGATION_DOMAIN.len()],
            DAEMON_DELEGATION_DOMAIN
        );
        assert_eq!(
            &t[DAEMON_DELEGATION_DOMAIN.len()..DAEMON_DELEGATION_DOMAIN.len() + 32],
            &ed_a
        );
        assert_eq!(&t[DAEMON_DELEGATION_DOMAIN.len() + 32..], ml_a.as_slice());
        assert_eq!(t.len(), DAEMON_DELEGATION_DOMAIN.len() + 32 + 1952);
        // Either delegated key changing -> different bytes (a certificate
        // for one HTTP-auth identity can't be replayed as vouching for a
        // different Ed25519 key, a different ML-DSA key, or both).
        assert_ne!(t, daemon_delegation_transcript(&ed_b, &ml_a));
        assert_ne!(t, daemon_delegation_transcript(&ed_a, &ml_b));
    }

    #[test]
    fn challenge_host_attestation_transcript_layout_is_exact_and_nonce_bound() {
        let nonce_a = [0x55u8; 32];
        let nonce_b = [0x66u8; 32];
        let t = challenge_host_attestation_transcript(&nonce_a);
        assert_eq!(
            &t[..CHALLENGE_HOST_ATTESTATION_DOMAIN.len()],
            CHALLENGE_HOST_ATTESTATION_DOMAIN
        );
        assert_eq!(&t[CHALLENGE_HOST_ATTESTATION_DOMAIN.len()..], &nonce_a);
        assert_eq!(t.len(), CHALLENGE_HOST_ATTESTATION_DOMAIN.len() + 32);
        // An attestation over one nonce can't be replayed as attesting a
        // different one -- that's the whole point of this transcript.
        assert_ne!(t, challenge_host_attestation_transcript(&nonce_b));
    }

    #[test]
    fn operator_token_canonical_bytes_layout_is_exact_and_field_bound() {
        let base =
            operator_token_canonical_bytes("alice", OperatorRole::Admin, 1000, 2000, &[9u8; 16]);
        assert_eq!(&base[..OPERATOR_TOKEN_DOMAIN.len()], OPERATOR_TOKEN_DOMAIN);
        // Changing any one field must change the bytes -- otherwise a
        // tampered token field wouldn't actually invalidate the signature.
        assert_ne!(
            base,
            operator_token_canonical_bytes("bob", OperatorRole::Admin, 1000, 2000, &[9u8; 16])
        );
        assert_ne!(
            base,
            operator_token_canonical_bytes("alice", OperatorRole::Viewer, 1000, 2000, &[9u8; 16])
        );
        assert_ne!(
            base,
            operator_token_canonical_bytes("alice", OperatorRole::Admin, 1001, 2000, &[9u8; 16])
        );
        assert_ne!(
            base,
            operator_token_canonical_bytes("alice", OperatorRole::Admin, 1000, 2001, &[9u8; 16])
        );
        assert_ne!(
            base,
            operator_token_canonical_bytes("alice", OperatorRole::Admin, 1000, 2000, &[8u8; 16])
        );
    }

    #[test]
    fn replace_operator_key_transcript_is_domain_separated_and_field_bound() {
        let ed = [1u8; 32];
        let ml = [2u8; 4];
        let nonce = [9u8; 16];
        let base = replace_operator_key_transcript("alice", &ed, &ml, None, &nonce);
        assert_eq!(
            &base[..REPLACE_OPERATOR_KEY_DOMAIN.len()],
            REPLACE_OPERATOR_KEY_DOMAIN
        );
        // Changing any one field must change the bytes -- a captured
        // signature over one target/key/nonce combination must not verify
        // against a different one.
        assert_ne!(
            base,
            replace_operator_key_transcript("bob", &ed, &ml, None, &nonce)
        );
        assert_ne!(
            base,
            replace_operator_key_transcript("alice", &[3u8; 32], &ml, None, &nonce)
        );
        assert_ne!(
            base,
            replace_operator_key_transcript("alice", &ed, &[4u8; 4], None, &nonce)
        );
        assert_ne!(
            base,
            replace_operator_key_transcript("alice", &ed, &ml, None, &[8u8; 16])
        );
        // Presence of an ML-DSA-87 key changes the transcript even if
        // everything else matches -- an admin who only saw (and signed
        // over) a standard-suite replacement can't have that signature
        // reinterpreted as also authorizing a high-security enrollment.
        let with_87 = replace_operator_key_transcript("alice", &ed, &ml, Some(&[5u8; 4]), &nonce);
        assert_ne!(base, with_87);
        assert_ne!(
            with_87,
            replace_operator_key_transcript("alice", &ed, &ml, Some(&[6u8; 4]), &nonce)
        );
    }
}
