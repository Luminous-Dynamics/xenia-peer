//! Pure M1 session lifecycle state machine.
//!
//! This module is intentionally deterministic and transport-free.
//! It does not capture frames, inject input, open sockets, or make
//! production remote-desktop claims. It records the policy lifecycle
//! that M1 must enforce before lower-level frame/input plumbing is used.

use std::error::Error;
use std::fmt;

/// M1 local-session lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1SessionState {
    /// No M1 session has been offered yet.
    Idle,
    /// A host has offered a session and is waiting for consent.
    Offered,
    /// Consent has been granted and privileged flow is allowed.
    Active,
    /// Consent was denied before activation.
    Denied,
    /// Consent was revoked after offer or activation.
    Revoked,
    /// The session ended normally.
    Ended,
    /// The session failed before normal completion.
    Failed,
}

/// Privileged operation protected by session consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1Permission {
    /// Permission to stream a captured frame on the forward path.
    StreamFrame,
    /// Permission to inject viewer input on the reverse path.
    InjectInput,
    /// Permission to apply a viewer-originated clipboard update to the
    /// real host clipboard (reverse path, bidirectional clipboard mode).
    ClipboardSync,
    /// Permission to write a received file-transfer chunk to disk, or to
    /// read a local file's bytes for an outbound transfer.
    FileTransfer,
}

/// The set of privileged operations a granted session actually authorizes.
///
/// Consent is not a single boolean: a viewer may be allowed to see the
/// screen without also being allowed to type, read the clipboard, or pull
/// files. This set records exactly which tiers a grant unlocked so
/// `require_active` can deny an operation the operator never approved, even
/// while the session is otherwise `Active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct M1PermissionSet {
    /// Forward-path frame streaming.
    pub stream_frame: bool,
    /// Reverse-path input injection.
    pub inject_input: bool,
    /// Reverse-path clipboard apply.
    pub clipboard_sync: bool,
    /// File-transfer read/write (either direction).
    pub file_transfer: bool,
}

impl M1PermissionSet {
    /// Grant every privileged operation. Retained for the transcript-replay
    /// and test paths that reconstruct a session without a per-tier scope;
    /// live daemons should grant exactly what the operator enabled.
    pub fn all() -> Self {
        Self {
            stream_frame: true,
            inject_input: true,
            clipboard_sync: true,
            file_transfer: true,
        }
    }

    /// Whether `permission` is included in this set.
    pub fn contains(&self, permission: M1Permission) -> bool {
        match permission {
            M1Permission::StreamFrame => self.stream_frame,
            M1Permission::InjectInput => self.inject_input,
            M1Permission::ClipboardSync => self.clipboard_sync,
            M1Permission::FileTransfer => self.file_transfer,
        }
    }
}

/// Audit event emitted by the M1 lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1AuditEvent {
    /// A host offered a session.
    SessionOffered,
    /// Consent was granted.
    ConsentGranted,
    /// Consent was denied.
    ConsentDenied,
    /// A frame was allowed through the active session.
    FrameStreamed,
    /// An input event was allowed through the active session.
    InputInjected,
    /// A viewer-originated clipboard update was applied to the host clipboard.
    ClipboardSynced,
    /// A file-transfer chunk was allowed through (either direction).
    FileTransferred,
    /// Consent was revoked.
    ConsentRevoked,
    /// The session ended normally.
    SessionEnded,
    /// The session failed.
    SessionFailed,
}

/// Typed M1 state-machine failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1SessionError {
    /// The requested action is not legal from the current state.
    InvalidTransition {
        /// State from which the action was attempted.
        from: M1SessionState,
        /// Name of the attempted action.
        action: &'static str,
    },
    /// The requested privileged operation is not allowed in this state.
    PermissionDenied {
        /// State in which the permission was requested.
        state: M1SessionState,
        /// Permission that was denied.
        permission: M1Permission,
    },
}

impl fmt::Display for M1SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            M1SessionError::InvalidTransition { from, action } => {
                write!(
                    f,
                    "invalid M1 session transition from {from:?} via {action}"
                )
            }
            M1SessionError::PermissionDenied { state, permission } => {
                write!(f, "M1 permission {permission:?} denied in state {state:?}")
            }
        }
    }
}

impl Error for M1SessionError {}

/// Deterministic M1 session policy machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M1SessionMachine {
    state: M1SessionState,
    audit: Vec<M1AuditEvent>,
    granted: M1PermissionSet,
}

impl Default for M1SessionMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl M1SessionMachine {
    /// Construct a fresh idle session machine.
    pub fn new() -> Self {
        Self {
            state: M1SessionState::Idle,
            audit: Vec::new(),
            granted: M1PermissionSet::default(),
        }
    }

    /// Permissions currently granted for the active session (empty unless
    /// the session is `Active`).
    pub fn granted_permissions(&self) -> M1PermissionSet {
        self.granted
    }

    /// Current lifecycle state.
    pub fn state(&self) -> M1SessionState {
        self.state
    }

    /// Audit trail emitted by this machine.
    pub fn audit(&self) -> &[M1AuditEvent] {
        &self.audit
    }

    /// Host offers a session.
    pub fn offer(&mut self) -> Result<(), M1SessionError> {
        self.transition(
            M1SessionState::Idle,
            M1SessionState::Offered,
            "offer",
            M1AuditEvent::SessionOffered,
        )
    }

    /// Viewer grants consent for every tier; M1 becomes active.
    ///
    /// This is the broad grant used by the deterministic transcript-replay
    /// and test paths. Live daemons should prefer [`grant_consent_scoped`]
    /// so a single approval does not silently authorize input, clipboard,
    /// and file transfer alongside screen viewing.
    ///
    /// [`grant_consent_scoped`]: Self::grant_consent_scoped
    pub fn grant_consent(&mut self) -> Result<(), M1SessionError> {
        self.grant_consent_scoped(M1PermissionSet::all())
    }

    /// Viewer grants consent for exactly the tiers in `granted`; M1 becomes
    /// active. An operation whose permission is not in the set is denied by
    /// `require_active` even though the session is `Active`.
    pub fn grant_consent_scoped(&mut self, granted: M1PermissionSet) -> Result<(), M1SessionError> {
        self.transition(
            M1SessionState::Offered,
            M1SessionState::Active,
            "grant_consent",
            M1AuditEvent::ConsentGranted,
        )?;
        self.granted = granted;
        Ok(())
    }

    /// Viewer denies consent.
    pub fn deny_consent(&mut self) -> Result<(), M1SessionError> {
        self.transition(
            M1SessionState::Offered,
            M1SessionState::Denied,
            "deny_consent",
            M1AuditEvent::ConsentDenied,
        )
    }

    /// Revoke consent from an offered or active session.
    pub fn revoke(&mut self) -> Result<(), M1SessionError> {
        match self.state {
            M1SessionState::Offered | M1SessionState::Active => {
                self.state = M1SessionState::Revoked;
                self.granted = M1PermissionSet::default();
                self.audit.push(M1AuditEvent::ConsentRevoked);
                Ok(())
            }
            from => Err(M1SessionError::InvalidTransition {
                from,
                action: "revoke",
            }),
        }
    }

    /// End a non-terminal session.
    pub fn end(&mut self) -> Result<(), M1SessionError> {
        match self.state {
            M1SessionState::Idle
            | M1SessionState::Offered
            | M1SessionState::Active
            | M1SessionState::Revoked => {
                self.state = M1SessionState::Ended;
                self.granted = M1PermissionSet::default();
                self.audit.push(M1AuditEvent::SessionEnded);
                Ok(())
            }
            from => Err(M1SessionError::InvalidTransition {
                from,
                action: "end",
            }),
        }
    }

    /// Mark a non-terminal session failed.
    pub fn fail(&mut self) -> Result<(), M1SessionError> {
        match self.state {
            M1SessionState::Denied | M1SessionState::Ended | M1SessionState::Failed => {
                Err(M1SessionError::InvalidTransition {
                    from: self.state,
                    action: "fail",
                })
            }
            _ => {
                self.state = M1SessionState::Failed;
                self.granted = M1PermissionSet::default();
                self.audit.push(M1AuditEvent::SessionFailed);
                Ok(())
            }
        }
    }

    /// Record that one frame was allowed through the forward path.
    pub fn stream_frame(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::StreamFrame)?;
        self.audit.push(M1AuditEvent::FrameStreamed);
        Ok(())
    }

    /// Record that one input event was allowed through the reverse path.
    pub fn inject_input(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::InjectInput)?;
        self.audit.push(M1AuditEvent::InputInjected);
        Ok(())
    }

    /// Record that one viewer-originated clipboard update was applied to
    /// the host clipboard on the reverse path.
    pub fn sync_clipboard(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::ClipboardSync)?;
        self.audit.push(M1AuditEvent::ClipboardSynced);
        Ok(())
    }

    /// Record that one file-transfer chunk was allowed through (either
    /// direction: writing a received chunk to disk, or reading a local
    /// chunk to send).
    pub fn transfer_file(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::FileTransfer)?;
        self.audit.push(M1AuditEvent::FileTransferred);
        Ok(())
    }

    fn transition(
        &mut self,
        from: M1SessionState,
        to: M1SessionState,
        action: &'static str,
        event: M1AuditEvent,
    ) -> Result<(), M1SessionError> {
        if self.state != from {
            return Err(M1SessionError::InvalidTransition {
                from: self.state,
                action,
            });
        }

        self.state = to;
        self.audit.push(event);
        Ok(())
    }

    fn require_active(&self, permission: M1Permission) -> Result<(), M1SessionError> {
        if self.state == M1SessionState::Active && self.granted.contains(permission) {
            Ok(())
        } else {
            Err(M1SessionError::PermissionDenied {
                state: self.state,
                permission,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_grant_authorizes_only_the_requested_tiers() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session
            .grant_consent_scoped(M1PermissionSet {
                stream_frame: true,
                ..M1PermissionSet::default()
            })
            .unwrap();

        // The granted tier is allowed...
        session.stream_frame().unwrap();

        // ...but the ungranted tiers are denied even though Active.
        let denied = |permission| M1SessionError::PermissionDenied {
            state: M1SessionState::Active,
            permission,
        };
        assert_eq!(
            session.inject_input().unwrap_err(),
            denied(M1Permission::InjectInput)
        );
        assert_eq!(
            session.sync_clipboard().unwrap_err(),
            denied(M1Permission::ClipboardSync)
        );
        assert_eq!(
            session.transfer_file().unwrap_err(),
            denied(M1Permission::FileTransfer)
        );
    }

    #[test]
    fn broad_grant_still_authorizes_every_tier() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        session.stream_frame().unwrap();
        session.inject_input().unwrap();
        session.sync_clipboard().unwrap();
        session.transfer_file().unwrap();
        assert_eq!(session.granted_permissions(), M1PermissionSet::all());
    }

    #[test]
    fn revocation_clears_granted_permissions() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();
        session.revoke().unwrap();

        assert_eq!(session.granted_permissions(), M1PermissionSet::default());
        assert_eq!(
            session.stream_frame().unwrap_err(),
            M1SessionError::PermissionDenied {
                state: M1SessionState::Revoked,
                permission: M1Permission::StreamFrame,
            }
        );
    }

    #[test]
    fn host_offer_creates_pending_session() {
        let mut session = M1SessionMachine::new();

        session.offer().unwrap();

        assert_eq!(session.state(), M1SessionState::Offered);
        assert_eq!(session.audit(), &[M1AuditEvent::SessionOffered]);
    }

    #[test]
    fn cannot_stream_frames_before_consent() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();

        let err = session.stream_frame().unwrap_err();

        assert_eq!(
            err,
            M1SessionError::PermissionDenied {
                state: M1SessionState::Offered,
                permission: M1Permission::StreamFrame
            }
        );
    }

    #[test]
    fn cannot_inject_input_before_consent() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();

        let err = session.inject_input().unwrap_err();

        assert_eq!(
            err,
            M1SessionError::PermissionDenied {
                state: M1SessionState::Offered,
                permission: M1Permission::InjectInput
            }
        );
    }

    #[test]
    fn viewer_approval_activates_session() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();

        session.grant_consent().unwrap();

        assert_eq!(session.state(), M1SessionState::Active);
        assert_eq!(
            session.audit(),
            &[M1AuditEvent::SessionOffered, M1AuditEvent::ConsentGranted]
        );
    }

    #[test]
    fn active_session_allows_frames_and_input() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        session.stream_frame().unwrap();
        session.inject_input().unwrap();

        assert_eq!(
            session.audit(),
            &[
                M1AuditEvent::SessionOffered,
                M1AuditEvent::ConsentGranted,
                M1AuditEvent::FrameStreamed,
                M1AuditEvent::InputInjected
            ]
        );
    }

    #[test]
    fn cannot_sync_clipboard_before_consent() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();

        let err = session.sync_clipboard().unwrap_err();

        assert_eq!(
            err,
            M1SessionError::PermissionDenied {
                state: M1SessionState::Offered,
                permission: M1Permission::ClipboardSync
            }
        );
    }

    #[test]
    fn active_session_allows_clipboard_sync() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        session.sync_clipboard().unwrap();

        assert_eq!(
            session.audit(),
            &[
                M1AuditEvent::SessionOffered,
                M1AuditEvent::ConsentGranted,
                M1AuditEvent::ClipboardSynced
            ]
        );
    }

    #[test]
    fn cannot_transfer_file_before_consent() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();

        let err = session.transfer_file().unwrap_err();

        assert_eq!(
            err,
            M1SessionError::PermissionDenied {
                state: M1SessionState::Offered,
                permission: M1Permission::FileTransfer
            }
        );
    }

    #[test]
    fn active_session_allows_file_transfer() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        session.transfer_file().unwrap();

        assert_eq!(
            session.audit(),
            &[
                M1AuditEvent::SessionOffered,
                M1AuditEvent::ConsentGranted,
                M1AuditEvent::FileTransferred
            ]
        );
    }

    #[test]
    fn revocation_disables_frames_and_input() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        session.revoke().unwrap();

        assert_eq!(session.state(), M1SessionState::Revoked);
        assert!(matches!(
            session.stream_frame(),
            Err(M1SessionError::PermissionDenied {
                state: M1SessionState::Revoked,
                permission: M1Permission::StreamFrame
            })
        ));
        assert!(matches!(
            session.inject_input(),
            Err(M1SessionError::PermissionDenied {
                state: M1SessionState::Revoked,
                permission: M1Permission::InjectInput
            })
        ));
    }

    #[test]
    fn ended_session_rejects_further_actions() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();
        session.end().unwrap();

        assert_eq!(session.state(), M1SessionState::Ended);
        assert!(matches!(
            session.stream_frame(),
            Err(M1SessionError::PermissionDenied {
                state: M1SessionState::Ended,
                permission: M1Permission::StreamFrame
            })
        ));
        assert!(matches!(
            session.grant_consent(),
            Err(M1SessionError::InvalidTransition {
                from: M1SessionState::Ended,
                action: "grant_consent"
            })
        ));
    }

    #[test]
    fn denied_session_is_terminal_for_privileged_flow() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.deny_consent().unwrap();

        assert_eq!(session.state(), M1SessionState::Denied);
        assert!(matches!(
            session.stream_frame(),
            Err(M1SessionError::PermissionDenied {
                state: M1SessionState::Denied,
                permission: M1Permission::StreamFrame
            })
        ));
        assert!(matches!(
            session.revoke(),
            Err(M1SessionError::InvalidTransition {
                from: M1SessionState::Denied,
                action: "revoke"
            })
        ));
    }

    #[test]
    fn invalid_transitions_return_typed_errors() {
        let mut session = M1SessionMachine::new();

        let err = session.grant_consent().unwrap_err();

        assert_eq!(
            err,
            M1SessionError::InvalidTransition {
                from: M1SessionState::Idle,
                action: "grant_consent"
            }
        );
    }

    #[test]
    fn every_state_transition_produces_an_audit_event() {
        let mut session = M1SessionMachine::new();

        session.offer().unwrap();
        session.grant_consent().unwrap();
        session.revoke().unwrap();
        session.end().unwrap();

        assert_eq!(
            session.audit(),
            &[
                M1AuditEvent::SessionOffered,
                M1AuditEvent::ConsentGranted,
                M1AuditEvent::ConsentRevoked,
                M1AuditEvent::SessionEnded
            ]
        );
    }
}
