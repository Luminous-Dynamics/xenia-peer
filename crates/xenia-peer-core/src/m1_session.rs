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
        }
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

    /// Viewer grants consent; M1 becomes active.
    pub fn grant_consent(&mut self) -> Result<(), M1SessionError> {
        self.transition(
            M1SessionState::Offered,
            M1SessionState::Active,
            "grant_consent",
            M1AuditEvent::ConsentGranted,
        )
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
        if self.state == M1SessionState::Active {
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
