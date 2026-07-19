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
    /// Permission to read host clipboard contents for delivery to the viewer.
    ReadHostClipboard,
    /// Permission to apply viewer clipboard contents to the host clipboard.
    WriteHostClipboard,
    /// Permission to read a host file and send it to the viewer.
    SendFileToViewer,
    /// Permission to receive viewer file bytes and write them on the host.
    ReceiveFileFromViewer,
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
    /// Host clipboard disclosure to the viewer.
    pub read_host_clipboard: bool,
    /// Viewer clipboard application to the host.
    pub write_host_clipboard: bool,
    /// Host file disclosure to the viewer.
    pub send_file_to_viewer: bool,
    /// Viewer file receipt and host write.
    pub receive_file_from_viewer: bool,
}

impl M1PermissionSet {
    /// Stable prefix for the machine-readable grant persisted in consent ledgers.
    pub const SCOPE_DESCRIPTOR_PREFIX: &'static str = "xenia-m1-permissions-v1:";

    /// Encode this grant as a stable, human-inspectable six-bit descriptor.
    /// Field order is part of the persistence contract and must not be changed:
    /// frame, input, host-clipboard-read, host-clipboard-write,
    /// host-to-viewer-file, viewer-to-host-file.
    pub fn scope_descriptor(self) -> String {
        format!(
            "{}{}{}{}{}{}{}",
            Self::SCOPE_DESCRIPTOR_PREFIX,
            u8::from(self.stream_frame),
            u8::from(self.inject_input),
            u8::from(self.read_host_clipboard),
            u8::from(self.write_host_clipboard),
            u8::from(self.send_file_to_viewer),
            u8::from(self.receive_file_from_viewer),
        )
    }

    /// Decode a grant persisted by [`Self::scope_descriptor`]. Unknown versions,
    /// malformed lengths, and non-binary fields fail closed.
    pub fn from_scope_descriptor(scope: &str) -> Option<Self> {
        let bits = scope.strip_prefix(Self::SCOPE_DESCRIPTOR_PREFIX)?.as_bytes();
        if bits.len() != 6 || bits.iter().any(|bit| !matches!(bit, b'0' | b'1')) {
            return None;
        }
        let enabled = |index: usize| bits[index] == b'1';
        Some(Self {
            stream_frame: enabled(0),
            inject_input: enabled(1),
            read_host_clipboard: enabled(2),
            write_host_clipboard: enabled(3),
            send_file_to_viewer: enabled(4),
            receive_file_from_viewer: enabled(5),
        })
    }

    /// Grant every privileged operation. Retained for the transcript-replay
    /// and test paths that reconstruct a session without a per-tier scope;
    /// live daemons should grant exactly what the operator enabled.
    pub fn all() -> Self {
        Self {
            stream_frame: true,
            inject_input: true,
            read_host_clipboard: true,
            write_host_clipboard: true,
            send_file_to_viewer: true,
            receive_file_from_viewer: true,
        }
    }

    /// Whether `permission` is included in this set.
    pub fn contains(&self, permission: M1Permission) -> bool {
        match permission {
            M1Permission::StreamFrame => self.stream_frame,
            M1Permission::InjectInput => self.inject_input,
            M1Permission::ReadHostClipboard => self.read_host_clipboard,
            M1Permission::WriteHostClipboard => self.write_host_clipboard,
            M1Permission::SendFileToViewer => self.send_file_to_viewer,
            M1Permission::ReceiveFileFromViewer => self.receive_file_from_viewer,
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
    /// Host clipboard contents were disclosed to the viewer.
    HostClipboardRead,
    /// Viewer clipboard contents were applied to the host.
    HostClipboardWritten,
    /// Host file bytes were sent to the viewer.
    FileSentToViewer,
    /// Viewer file bytes were accepted for host storage.
    FileReceivedFromViewer,
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

    /// Record that host clipboard contents were read for delivery to the viewer.
    pub fn read_host_clipboard(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::ReadHostClipboard)?;
        self.audit.push(M1AuditEvent::HostClipboardRead);
        Ok(())
    }

    /// Record that viewer clipboard contents were applied to the host.
    pub fn write_host_clipboard(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::WriteHostClipboard)?;
        self.audit.push(M1AuditEvent::HostClipboardWritten);
        Ok(())
    }

    /// Record that host file bytes were sent to the viewer.
    pub fn send_file_to_viewer(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::SendFileToViewer)?;
        self.audit.push(M1AuditEvent::FileSentToViewer);
        Ok(())
    }

    /// Record that viewer file bytes were accepted for host storage.
    pub fn receive_file_from_viewer(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::ReceiveFileFromViewer)?;
        self.audit.push(M1AuditEvent::FileReceivedFromViewer);
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
    fn permission_scope_descriptor_round_trips_and_rejects_unknown_shapes() {
        let grant = M1PermissionSet {
            stream_frame: true,
            inject_input: false,
            read_host_clipboard: true,
            write_host_clipboard: false,
            send_file_to_viewer: true,
            receive_file_from_viewer: false,
        };
        let descriptor = grant.scope_descriptor();
        assert_eq!(descriptor, "xenia-m1-permissions-v1:101010");
        assert_eq!(M1PermissionSet::from_scope_descriptor(&descriptor), Some(grant));
        assert_eq!(M1PermissionSet::from_scope_descriptor("view screen"), None);
        assert_eq!(
            M1PermissionSet::from_scope_descriptor("xenia-m1-permissions-v2:101010"),
            None
        );
        assert_eq!(
            M1PermissionSet::from_scope_descriptor("xenia-m1-permissions-v1:10101x"),
            None
        );
    }

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
            session.write_host_clipboard().unwrap_err(),
            denied(M1Permission::WriteHostClipboard)
        );
        assert_eq!(
            session.receive_file_from_viewer().unwrap_err(),
            denied(M1Permission::ReceiveFileFromViewer)
        );
    }

    #[test]
    fn broad_grant_still_authorizes_every_tier() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        session.stream_frame().unwrap();
        session.inject_input().unwrap();
        session.read_host_clipboard().unwrap();
        session.write_host_clipboard().unwrap();
        session.send_file_to_viewer().unwrap();
        session.receive_file_from_viewer().unwrap();
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
    fn cannot_write_host_clipboard_before_consent() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();

        let err = session.write_host_clipboard().unwrap_err();

        assert_eq!(
            err,
            M1SessionError::PermissionDenied {
                state: M1SessionState::Offered,
                permission: M1Permission::WriteHostClipboard
            }
        );
    }

    #[test]
    fn active_session_allows_host_clipboard_write() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        session.write_host_clipboard().unwrap();

        assert_eq!(
            session.audit(),
            &[
                M1AuditEvent::SessionOffered,
                M1AuditEvent::ConsentGranted,
                M1AuditEvent::HostClipboardWritten
            ]
        );
    }

    #[test]
    fn cannot_receive_file_before_consent() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();

        let err = session.receive_file_from_viewer().unwrap_err();

        assert_eq!(
            err,
            M1SessionError::PermissionDenied {
                state: M1SessionState::Offered,
                permission: M1Permission::ReceiveFileFromViewer
            }
        );
    }

    #[test]
    fn active_session_allows_file_receive() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        session.receive_file_from_viewer().unwrap();

        assert_eq!(
            session.audit(),
            &[
                M1AuditEvent::SessionOffered,
                M1AuditEvent::ConsentGranted,
                M1AuditEvent::FileReceivedFromViewer
            ]
        );
    }

    #[test]
    fn one_way_grants_do_not_authorize_the_opposite_direction() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session
            .grant_consent_scoped(M1PermissionSet {
                stream_frame: true,
                read_host_clipboard: true,
                send_file_to_viewer: true,
                ..M1PermissionSet::default()
            })
            .unwrap();

        session.read_host_clipboard().unwrap();
        session.send_file_to_viewer().unwrap();
        assert!(matches!(
            session.write_host_clipboard(),
            Err(M1SessionError::PermissionDenied {
                permission: M1Permission::WriteHostClipboard,
                ..
            })
        ));
        assert!(matches!(
            session.receive_file_from_viewer(),
            Err(M1SessionError::PermissionDenied {
                permission: M1Permission::ReceiveFileFromViewer,
                ..
            })
        ));
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
