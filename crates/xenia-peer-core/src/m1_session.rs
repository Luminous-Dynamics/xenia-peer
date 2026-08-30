//! Pure M1 session lifecycle state machine.
//!
//! This module is intentionally deterministic and transport-free.
//! It does not capture frames, inject input, open sockets, spawn processes,
//! or make production remote-desktop claims. It records the policy lifecycle
//! that M1 must enforce before lower-level privileged plumbing is used.

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

/// Existing remote-session privileged operation protected by session consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1Permission {
    /// Permission to stream a captured frame on the forward path.
    StreamFrame,
    /// Permission to stream host telemetry (performance metrics, and at
    /// `TelemetryLevel::System`, hostname/OS identity) to the viewer.
    StreamTelemetry,
    /// Permission to stream host audio to the viewer.
    StreamAudio,
    /// Permission to inject viewer input on the reverse path.
    InjectInput,
    /// Permission to disclose host clipboard contents to the viewer.
    ReadHostClipboard,
    /// Permission to apply a viewer-originated clipboard update to the host.
    WriteHostClipboard,
    /// Permission to read a local file's bytes and send it to the viewer.
    SendFileToViewer,
    /// Permission to accept a viewer-offered file and write it to disk.
    ReceiveFileFromViewer,
}

/// The existing set of remote-session privileged operations a grant authorizes.
///
/// Execution authority intentionally does **not** get appended to this legacy
/// broad set. It lives in [`M1ExecutionPermissionSet`] so historical calls to
/// [`M1PermissionSet::all`] cannot silently acquire process-execution power when
/// this crate is upgraded. Live execution must opt into the new sidecar grant.
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
    /// Grant every pre-execution privileged operation.
    ///
    /// This deliberately does not grant native execution or interactive
    /// terminal authority. See [`M1ExecutionPermissionSet`].
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

/// Process/terminal authority introduced after the original M1 permission set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1ExecutionPermission {
    /// Authorize one exact structured one-shot invocation under the session's
    /// authenticated execution policy. This is not interactive PTY authority.
    ExecuteCommand,
    /// Authorize creation of an interactive PTY/terminal session.
    /// Reserved for a later runtime tranche; independent of [`ExecuteCommand`].
    OpenInteractiveTerminal,
}

/// Explicit default-off process/terminal authority for one active M1 session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct M1ExecutionPermissionSet {
    /// Structured one-shot execution authority.
    pub execute_command: bool,
    /// Interactive PTY/terminal authority.
    pub open_interactive_terminal: bool,
}

impl M1ExecutionPermissionSet {
    /// A set that grants only structured one-shot execution.
    pub const fn command_only() -> Self {
        Self {
            execute_command: true,
            open_interactive_terminal: false,
        }
    }

    /// Whether `permission` is included in this execution grant.
    pub const fn contains(&self, permission: M1ExecutionPermission) -> bool {
        match permission {
            M1ExecutionPermission::ExecuteCommand => self.execute_command,
            M1ExecutionPermission::OpenInteractiveTerminal => self.open_interactive_terminal,
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
    /// M1 authorized a structured one-shot command request.
    CommandExecutionAuthorized,
    /// M1 authorized opening an interactive terminal.
    InteractiveTerminalAuthorized,
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
    /// The requested existing remote-session operation is not allowed.
    PermissionDenied {
        /// State in which the permission was requested.
        state: M1SessionState,
        /// Permission that was denied.
        permission: M1Permission,
    },
    /// The requested execution/terminal operation is not allowed.
    ExecutionPermissionDenied {
        /// State in which the permission was requested.
        state: M1SessionState,
        /// Execution permission that was denied.
        permission: M1ExecutionPermission,
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
            M1SessionError::ExecutionPermissionDenied { state, permission } => write!(
                f,
                "M1 execution permission {permission:?} denied in state {state:?}"
            ),
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
    execution_granted: M1ExecutionPermissionSet,
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
            execution_granted: M1ExecutionPermissionSet::default(),
        }
    }

    /// Existing permissions currently granted for the active session.
    pub fn granted_permissions(&self) -> M1PermissionSet {
        self.granted
    }

    /// Execution/terminal permissions currently granted for the active session.
    pub fn granted_execution_permissions(&self) -> M1ExecutionPermissionSet {
        self.execution_granted
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

    /// Grant every historical pre-execution tier; execution remains off.
    ///
    /// This backwards-compatible broad grant intentionally cannot acquire
    /// process-execution power merely because the library added a new feature.
    pub fn grant_consent(&mut self) -> Result<(), M1SessionError> {
        self.grant_consent_scoped(M1PermissionSet::all())
    }

    /// Grant exactly the historical tiers in `granted`; execution remains off.
    pub fn grant_consent_scoped(&mut self, granted: M1PermissionSet) -> Result<(), M1SessionError> {
        self.grant_consent_scoped_with_execution(granted, M1ExecutionPermissionSet::default())
    }

    /// Grant historical remote-session tiers plus an explicit execution sidecar.
    ///
    /// This is the only M1 activation path that can grant process/terminal
    /// authority. The future daemon capability/consent tranche must call this
    /// only after the exact execution policy has been authenticated and shown
    /// in the consent scope.
    pub fn grant_consent_scoped_with_execution(
        &mut self,
        granted: M1PermissionSet,
        execution_granted: M1ExecutionPermissionSet,
    ) -> Result<(), M1SessionError> {
        self.transition(
            M1SessionState::Offered,
            M1SessionState::Active,
            "grant_consent",
            M1AuditEvent::ConsentGranted,
        )?;
        self.granted = granted;
        self.execution_granted = execution_granted;
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
                self.clear_permissions();
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
                self.clear_permissions();
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
                self.clear_permissions();
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

    /// Record that one telemetry batch was allowed through the forward path.
    pub fn stream_telemetry(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::StreamTelemetry)?;
        self.audit.push(M1AuditEvent::TelemetryStreamed);
        Ok(())
    }

    /// Record that one audio frame was allowed through the forward path.
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

    /// Record that host clipboard contents were disclosed to the viewer.
    pub fn read_host_clipboard(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::ReadHostClipboard)?;
        self.audit.push(M1AuditEvent::HostClipboardRead);
        Ok(())
    }

    /// Record that a viewer-originated clipboard update was applied.
    pub fn write_host_clipboard(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::WriteHostClipboard)?;
        self.audit.push(M1AuditEvent::HostClipboardWritten);
        Ok(())
    }

    /// Record that host file bytes were allowed to flow to the viewer.
    pub fn send_file_to_viewer(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::SendFileToViewer)?;
        self.audit.push(M1AuditEvent::FileSentToViewer);
        Ok(())
    }

    /// Record that viewer file bytes were allowed into host storage.
    pub fn receive_file_from_viewer(&mut self) -> Result<(), M1SessionError> {
        self.require_active(M1Permission::ReceiveFileFromViewer)?;
        self.audit.push(M1AuditEvent::FileReceivedFromViewer);
        Ok(())
    }

    /// Record that M1 authorized a structured one-shot command request.
    ///
    /// This is an authorization event only; it does not claim a process was
    /// spawned or completed. The runtime must still validate the authenticated
    /// execution policy and persist required evidence before spawning.
    pub fn authorize_command_execution(&mut self) -> Result<(), M1SessionError> {
        self.require_execution_active(M1ExecutionPermission::ExecuteCommand)?;
        self.audit.push(M1AuditEvent::CommandExecutionAuthorized);
        Ok(())
    }

    /// Record that M1 authorized opening an interactive terminal.
    ///
    /// No terminal runtime is implemented by this state machine.
    pub fn authorize_interactive_terminal(&mut self) -> Result<(), M1SessionError> {
        self.require_execution_active(M1ExecutionPermission::OpenInteractiveTerminal)?;
        self.audit.push(M1AuditEvent::InteractiveTerminalAuthorized);
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

    fn require_execution_active(
        &self,
        permission: M1ExecutionPermission,
    ) -> Result<(), M1SessionError> {
        if self.state == M1SessionState::Active && self.execution_granted.contains(permission) {
            Ok(())
        } else {
            Err(M1SessionError::ExecutionPermissionDenied {
                state: self.state,
                permission,
            })
        }
    }

    fn clear_permissions(&mut self) {
        self.granted = M1PermissionSet::default();
        self.execution_granted = M1ExecutionPermissionSet::default();
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

        session.stream_frame().unwrap();

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

    #[test]
    fn legacy_broad_grant_does_not_silently_acquire_execution() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session.grant_consent().unwrap();

        assert_eq!(
            session.granted_execution_permissions(),
            M1ExecutionPermissionSet::default()
        );
        assert_eq!(
            session.authorize_command_execution().unwrap_err(),
            M1SessionError::ExecutionPermissionDenied {
                state: M1SessionState::Active,
                permission: M1ExecutionPermission::ExecuteCommand,
            }
        );
        assert_eq!(
            session.authorize_interactive_terminal().unwrap_err(),
            M1SessionError::ExecutionPermissionDenied {
                state: M1SessionState::Active,
                permission: M1ExecutionPermission::OpenInteractiveTerminal,
            }
        );
    }

    #[test]
    fn command_and_interactive_terminal_are_independent_grants() {
        let mut command = M1SessionMachine::new();
        command.offer().unwrap();
        command
            .grant_consent_scoped_with_execution(
                M1PermissionSet::default(),
                M1ExecutionPermissionSet::command_only(),
            )
            .unwrap();
        command.authorize_command_execution().unwrap();
        assert_eq!(
            command.authorize_interactive_terminal().unwrap_err(),
            M1SessionError::ExecutionPermissionDenied {
                state: M1SessionState::Active,
                permission: M1ExecutionPermission::OpenInteractiveTerminal,
            }
        );

        let mut terminal = M1SessionMachine::new();
        terminal.offer().unwrap();
        terminal
            .grant_consent_scoped_with_execution(
                M1PermissionSet::default(),
                M1ExecutionPermissionSet {
                    execute_command: false,
                    open_interactive_terminal: true,
                },
            )
            .unwrap();
        terminal.authorize_interactive_terminal().unwrap();
        assert_eq!(
            terminal.authorize_command_execution().unwrap_err(),
            M1SessionError::ExecutionPermissionDenied {
                state: M1SessionState::Active,
                permission: M1ExecutionPermission::ExecuteCommand,
            }
        );
    }

    #[test]
    fn revocation_clears_execution_permissions() {
        let mut session = M1SessionMachine::new();
        session.offer().unwrap();
        session
            .grant_consent_scoped_with_execution(
                M1PermissionSet::default(),
                M1ExecutionPermissionSet::command_only(),
            )
            .unwrap();
        session.revoke().unwrap();

        assert_eq!(
            session.granted_execution_permissions(),
            M1ExecutionPermissionSet::default()
        );
        assert_eq!(
            session.authorize_command_execution().unwrap_err(),
            M1SessionError::ExecutionPermissionDenied {
                state: M1SessionState::Revoked,
                permission: M1ExecutionPermission::ExecuteCommand,
            }
        );
    }

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
    fn broad_grant_still_authorizes_every_historical_tier() {
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
        assert_eq!(
            session.granted_execution_permissions(),
            M1ExecutionPermissionSet::default()
        );
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
        assert_eq!(
            session.stream_frame().unwrap_err(),
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
        assert_eq!(
            session.inject_input().unwrap_err(),
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
        assert_eq!(
            session.read_host_clipboard().unwrap_err(),
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
        assert_eq!(
            session.write_host_clipboard().unwrap_err(),
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
        assert_eq!(
            session.send_file_to_viewer().unwrap_err(),
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
        assert_eq!(
            session.receive_file_from_viewer().unwrap_err(),
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
        assert_eq!(
            session.grant_consent().unwrap_err(),
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
