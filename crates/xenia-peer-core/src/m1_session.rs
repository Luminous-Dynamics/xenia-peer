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
    /// Permission to stream host telemetry (performance metrics, and at
    /// `TelemetryLevel::System`, hostname/OS identity) to the viewer.
    /// Independent of [`StreamFrame`] -- a grant that only permits
    /// viewing the screen must not also silently disclose host identity
    /// or performance data. See `docs/roadmap/
    /// XENIA_EXPANSION_PLAN_REVIEW_2026-07-29.md`'s "one real gap found"
    /// note: this tier didn't exist before, so every telemetry frame
    /// rode on `StreamFrame` alone.
    ///
    /// [`StreamFrame`]: Self::StreamFrame
    StreamTelemetry,
    /// Permission to stream host audio (synthetic test signal or real
    /// device capture, per `AudioMode`) to the viewer. Independent of
    /// [`StreamFrame`] for the same reason as [`StreamTelemetry`] -- at
    /// `AudioMode::Capture` this is a live microphone, a materially
    /// different privacy commitment than "can see the screen."
    ///
    /// [`StreamFrame`]: Self::StreamFrame
    /// [`StreamTelemetry`]: Self::StreamTelemetry
    StreamAudio,
    /// Permission to inject viewer input on the reverse path.
    InjectInput,
    /// Permission to disclose host clipboard contents to the viewer
    /// (forward path). Independent of [`WriteHostClipboard`] -- a grant
    /// that only permits viewing the screen must not also silently leak
    /// clipboard contents.
    ///
    /// [`WriteHostClipboard`]: Self::WriteHostClipboard
    ReadHostClipboard,
    /// Permission to apply a viewer-originated clipboard update to the
    /// real host clipboard (reverse path, bidirectional clipboard mode).
    WriteHostClipboard,
    /// Permission to read a local file's bytes and send it to the viewer
    /// (forward path, e.g. `--send-file`).
    SendFileToViewer,
    /// Permission to accept a viewer-offered file and write it to disk
    /// (reverse path, e.g. `--recv-file-dir`).
    ReceiveFileFromViewer,
}

/// The set of privileged operations a granted session actually authorizes.
///
/// Consent is not a single boolean: a viewer may be allowed to see the
/// screen without also being allowed to type, read the clipboard, or pull
/// files. This set records exactly which tiers a grant unlocked so
/// `require_active` can deny an operation the operator never approved, even
/// while the session is otherwise `Active`. Clipboard and file-transfer are
/// each split by direction rather than a single combined flag: a grant
/// scoped to "receive files" must not silently also permit sending host
/// files, and "view the screen" must not silently also permit disclosing
/// the host clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct M1PermissionSet {
    /// Forward-path frame streaming.
    pub stream_frame: bool,
    /// Forward-path telemetry streaming.
    pub stream_telemetry: bool,
    /// Forward-path audio streaming.
    pub stream_audio: bool,
    /// Reverse-path input injection.
    pub inject_input: bool,
    /// Forward-path host-clipboard disclosure to the viewer.
    pub read_host_clipboard: bool,
    /// Reverse-path viewer-clipboard apply to the host.
    pub write_host_clipboard: bool,
    /// Forward-path file send (host -> viewer).
    pub send_file_to_viewer: bool,
    /// Reverse-path file receive (viewer -> host).
    pub receive_file_from_viewer: bool,
}

impl M1PermissionSet {
    /// Grant every privileged operation. Retained for the transcript-replay
    /// and test paths that reconstruct a session without a per-tier scope;
    /// live daemons should grant exactly what the operator enabled.
    pub fn all() -> Self {
        Self {
            stream_frame: true,
            stream_telemetry: true,
            stream_audio: true,
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
            M1Permission::StreamTelemetry => self.stream_telemetry,
            M1Permission::StreamAudio => self.stream_audio,
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
    /// A telemetry batch was allowed through the active session.
    TelemetryStreamed,
    /// An audio frame was allowed through the active session.
    AudioStreamed,
    /// An input event was allowed through the active session.
    InputInjected,
    /// Host clipboard contents were disclosed to the viewer.
    HostClipboardRead,
    /// A viewer-originated clipboard update was applied to the host clipboard.
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

    /// Record that one telemetry batch was allowed through the forward
    /// path. Gated separately from [`stream_frame`] -- see
    /// [`M1Permission::StreamTelemetry`]'s doc comment.
    ///
    /// [`stream_frame`]: Self::stream_frame
    pub fn stream_telemetry(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::StreamTelemetry)?;
        self.audit.push(M1AuditEvent::TelemetryStreamed);
        Ok(())
    }

    /// Record that one audio frame was allowed through the forward path.
    /// Gated separately from [`stream_frame`] -- see
    /// [`M1Permission::StreamAudio`]'s doc comment.
    ///
    /// [`stream_frame`]: Self::stream_frame
    pub fn stream_audio(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::StreamAudio)?;
        self.audit.push(M1AuditEvent::AudioStreamed);
        Ok(())
    }

    /// Record that one input event was allowed through the reverse path.
    pub fn inject_input(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::InjectInput)?;
        self.audit.push(M1AuditEvent::InputInjected);
        Ok(())
    }

    /// Record that host clipboard contents were disclosed to the viewer on
    /// the forward path.
    pub fn read_host_clipboard(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::ReadHostClipboard)?;
        self.audit.push(M1AuditEvent::HostClipboardRead);
        Ok(())
    }

    /// Record that one viewer-originated clipboard update was applied to
    /// the host clipboard on the reverse path.
    pub fn write_host_clipboard(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::WriteHostClipboard)?;
        self.audit.push(M1AuditEvent::HostClipboardWritten);
        Ok(())
    }

    /// Record that one chunk of a host-initiated (forward-path) file
    /// transfer was allowed through.
    pub fn send_file_to_viewer(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::SendFileToViewer)?;
        self.audit.push(M1AuditEvent::FileSentToViewer);
        Ok(())
    }

    /// Record that one chunk of a viewer-initiated (reverse-path) file
    /// transfer was allowed through.
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
            session.read_host_clipboard().unwrap_err(),
            denied(M1Permission::ReadHostClipboard)
        );
        assert_eq!(
            session.write_host_clipboard().unwrap_err(),
            denied(M1Permission::WriteHostClipboard)
        );
        assert_eq!(
            session.send_file_to_viewer().unwrap_err(),
            denied(M1Permission::SendFileToViewer)
        );
        assert_eq!(
            session.receive_file_from_viewer().unwrap_err(),
            denied(M1Permission::ReceiveFileFromViewer)
        );
        assert_eq!(
            session.stream_telemetry().unwrap_err(),
            denied(M1Permission::StreamTelemetry)
        );
        assert_eq!(
            session.stream_audio().unwrap_err(),
            denied(M1Permission::StreamAudio)
        );
    }

    /// A screen-view-only grant must not silently also authorize
    /// telemetry or audio streaming -- the real gap this pair of tiers
    /// closes (see `M1Permission::StreamTelemetry`'s doc comment). Before
    /// this fix, every telemetry/audio frame rode on
    /// `M1Permission::StreamFrame` alone, so this exact scenario would
    /// have wrongly authorized both.
    #[test]
    fn stream_frame_grant_does_not_authorize_telemetry_or_audio() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session
            .grant_consent_scoped(M1PermissionSet {
                stream_frame: true,
                ..M1PermissionSet::default()
            })
            .unwrap();

        session.stream_frame().unwrap();
        assert_eq!(
            session.stream_telemetry().unwrap_err(),
            M1SessionError::PermissionDenied {
                state: M1SessionState::Active,
                permission: M1Permission::StreamTelemetry,
            }
        );
        assert_eq!(
            session.stream_audio().unwrap_err(),
            M1SessionError::PermissionDenied {
                state: M1SessionState::Active,
                permission: M1Permission::StreamAudio,
            }
        );
    }

    /// The converse: granting only telemetry/audio must not authorize
    /// viewing the screen either -- these three forward-path tiers are
    /// fully independent, not a hierarchy.
    #[test]
    fn telemetry_and_audio_grant_does_not_authorize_stream_frame() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session
            .grant_consent_scoped(M1PermissionSet {
                stream_telemetry: true,
                stream_audio: true,
                ..M1PermissionSet::default()
            })
            .unwrap();

        session.stream_telemetry().unwrap();
        session.stream_audio().unwrap();
        assert_eq!(
            session.stream_frame().unwrap_err(),
            M1SessionError::PermissionDenied {
                state: M1SessionState::Active,
                permission: M1Permission::StreamFrame,
            }
        );
    }

    /// The core property this directional split exists for: a grant scoped
    /// to only one direction of clipboard or file-transfer access must not
    /// silently also authorize the opposite direction.
    #[test]
    fn directional_grants_do_not_authorize_the_opposite_direction() {
        let denied = |permission| M1SessionError::PermissionDenied {
            state: M1SessionState::Active,
            permission,
        };

        let mut read_only = M1SessionMachine::new();
        read_only.offer().unwrap();
        read_only
            .grant_consent_scoped(M1PermissionSet {
                stream_frame: true,
                read_host_clipboard: true,
                ..M1PermissionSet::default()
            })
            .unwrap();
        read_only.read_host_clipboard().unwrap();
        assert_eq!(
            read_only.write_host_clipboard().unwrap_err(),
            denied(M1Permission::WriteHostClipboard)
        );

        let write_only = &mut M1SessionMachine::new();
        write_only.offer().unwrap();
        write_only
            .grant_consent_scoped(M1PermissionSet {
                stream_frame: true,
                write_host_clipboard: true,
                ..M1PermissionSet::default()
            })
            .unwrap();
        write_only.write_host_clipboard().unwrap();
        assert_eq!(
            write_only.read_host_clipboard().unwrap_err(),
            denied(M1Permission::ReadHostClipboard)
        );

        let send_only = &mut M1SessionMachine::new();
        send_only.offer().unwrap();
        send_only
            .grant_consent_scoped(M1PermissionSet {
                stream_frame: true,
                send_file_to_viewer: true,
                ..M1PermissionSet::default()
            })
            .unwrap();
        send_only.send_file_to_viewer().unwrap();
        assert_eq!(
            send_only.receive_file_from_viewer().unwrap_err(),
            denied(M1Permission::ReceiveFileFromViewer)
        );

        let receive_only = &mut M1SessionMachine::new();
        receive_only.offer().unwrap();
        receive_only
            .grant_consent_scoped(M1PermissionSet {
                stream_frame: true,
                receive_file_from_viewer: true,
                ..M1PermissionSet::default()
            })
            .unwrap();
        receive_only.receive_file_from_viewer().unwrap();
        assert_eq!(
            receive_only.send_file_to_viewer().unwrap_err(),
            denied(M1Permission::SendFileToViewer)
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
    fn cannot_read_host_clipboard_before_consent() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();

        let err = session.read_host_clipboard().unwrap_err();

        assert_eq!(
            err,
            M1SessionError::PermissionDenied {
                state: M1SessionState::Offered,
                permission: M1Permission::ReadHostClipboard
            }
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
    fn active_session_allows_clipboard_read_and_write() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        session.read_host_clipboard().unwrap();
        session.write_host_clipboard().unwrap();

        assert_eq!(
            session.audit(),
            &[
                M1AuditEvent::SessionOffered,
                M1AuditEvent::ConsentGranted,
                M1AuditEvent::HostClipboardRead,
                M1AuditEvent::HostClipboardWritten
            ]
        );
    }

    #[test]
    fn cannot_send_file_to_viewer_before_consent() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();

        let err = session.send_file_to_viewer().unwrap_err();

        assert_eq!(
            err,
            M1SessionError::PermissionDenied {
                state: M1SessionState::Offered,
                permission: M1Permission::SendFileToViewer
            }
        );
    }

    #[test]
    fn cannot_receive_file_from_viewer_before_consent() {
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
    fn active_session_allows_file_send_and_receive() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        session.send_file_to_viewer().unwrap();
        session.receive_file_from_viewer().unwrap();

        assert_eq!(
            session.audit(),
            &[
                M1AuditEvent::SessionOffered,
                M1AuditEvent::ConsentGranted,
                M1AuditEvent::FileSentToViewer,
                M1AuditEvent::FileReceivedFromViewer
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
