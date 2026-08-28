// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Runtime-free contracts for Xenia native execution.
//!
//! This crate deliberately contains no process spawning, PTY, filesystem,
//! networking, cryptography, or shell integration. It defines the exact typed
//! execution request/response surface and the deterministic policy commitment
//! that later runtime code must authorize before creating a process.
//!
//! V1 is intentionally one-shot and non-interactive. An executable and argv are
//! represented separately; there is no shell-command-string field.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current native execution protocol version.
pub const EXEC_PROTOCOL_VERSION: u16 = 1;
/// Stable schema label for [`ExecPolicyV1`].
pub const EXEC_POLICY_SCHEMA_V1: &str = "xenia-exec-policy-v1";
/// Domain separator for policy commitments.
pub const EXEC_POLICY_DIGEST_DOMAIN_V1: &[u8] = b"xenia-exec-policy-digest-v1";
/// Domain separator for request commitments/evidence.
pub const EXEC_REQUEST_DIGEST_DOMAIN_V1: &[u8] = b"xenia-exec-request-digest-v1";

/// Maximum encoded path-like text accepted by the protocol contract.
pub const MAX_PATH_BYTES_V1: usize = 4 * 1024;
/// Maximum executable entries in one policy.
pub const MAX_ALLOWED_EXECUTABLES_V1: usize = 256;
/// Maximum working-directory roots in one policy.
pub const MAX_WORKING_ROOTS_V1: usize = 64;
/// Maximum environment keys in one policy or request.
pub const MAX_ENVIRONMENT_KEYS_V1: usize = 128;
/// Maximum bytes in an environment key.
pub const MAX_ENVIRONMENT_KEY_BYTES_V1: usize = 256;
/// Maximum bytes in an environment value.
pub const MAX_ENVIRONMENT_VALUE_BYTES_V1: usize = 4 * 1024;
/// Maximum argv entries in one execution request.
pub const MAX_ARGUMENTS_V1: usize = 256;
/// Maximum bytes in one argv entry.
pub const MAX_ARGUMENT_BYTES_V1: usize = 4 * 1024;
/// Maximum aggregate argv bytes in one request.
pub const MAX_ARGUMENT_VECTOR_BYTES_V1: usize = 64 * 1024;
/// Maximum stdout/stderr bytes carried by one protocol message.
pub const MAX_OUTPUT_CHUNK_BYTES_V1: usize = 64 * 1024;
/// Absolute protocol ceiling for one requested runtime (24 hours).
pub const MAX_REQUEST_RUNTIME_MS_V1: u64 = 24 * 60 * 60 * 1000;
/// Absolute protocol ceiling for one stream's retained output.
pub const MAX_STREAM_OUTPUT_BYTES_V1: u64 = 64 * 1024 * 1024;
/// Absolute protocol ceiling for concurrent one-shot processes.
pub const MAX_CONCURRENT_PROCESSES_V1: u16 = 64;

/// Runtime identity under which a native execution request may run.
///
/// V1 intentionally exposes only the daemon's current user. Fixed accounts,
/// privilege transitions, `sudo`, service identities, and container/user
/// namespaces require a future protocol revision/policy extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecIdentityPolicyV1 {
    /// Execute as the same OS identity as the Xenia host process.
    CurrentUser,
}

/// Deterministic authorization policy committed into the session consent scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecPolicyV1 {
    /// Stable schema label. Must equal [`EXEC_POLICY_SCHEMA_V1`].
    pub schema: String,
    /// Protocol revision this policy authorizes.
    pub protocol_version: u16,
    /// Exact executable identities/paths permitted by the policy.
    ///
    /// Entries must be sorted and unique. Host runtime code is responsible for
    /// platform-specific canonicalization and safe path resolution before
    /// matching an execution request to this list.
    pub allowed_executables: Vec<String>,
    /// Exact allowed working-directory roots, sorted and unique.
    pub allowed_working_directory_roots: Vec<String>,
    /// Environment variable keys that a viewer may explicitly supply, sorted
    /// and unique. The runtime must not implicitly inherit arbitrary daemon
    /// environment state merely because a key is absent here.
    pub allowed_environment_keys: Vec<String>,
    /// Maximum requested runtime for one process.
    pub max_runtime_ms: u64,
    /// Maximum stdout bytes retained/transmitted for one process.
    pub max_stdout_bytes: u64,
    /// Maximum stderr bytes retained/transmitted for one process.
    pub max_stderr_bytes: u64,
    /// Maximum simultaneous processes admitted by this policy.
    pub max_concurrent_processes: u16,
    /// Execution identity policy.
    pub execution_identity: ExecIdentityPolicyV1,
    /// Whether viewer-provided interactive stdin is permitted.
    /// Must be `false` for protocol V1.
    pub allow_stdin: bool,
    /// Whether PTY allocation is permitted. Must be `false` for protocol V1.
    pub allow_pty: bool,
    /// Whether privilege elevation is permitted. Must be `false` for protocol V1.
    pub allow_elevation: bool,
    /// Whether network/port forwarding is permitted. Must be `false` for V1.
    pub allow_port_forwarding: bool,
}

impl ExecPolicyV1 {
    /// Construct a V1 policy for structured one-shot execution.
    pub fn one_shot(
        allowed_executables: Vec<String>,
        allowed_working_directory_roots: Vec<String>,
        allowed_environment_keys: Vec<String>,
        max_runtime_ms: u64,
        max_stdout_bytes: u64,
        max_stderr_bytes: u64,
        max_concurrent_processes: u16,
    ) -> Self {
        Self {
            schema: EXEC_POLICY_SCHEMA_V1.to_string(),
            protocol_version: EXEC_PROTOCOL_VERSION,
            allowed_executables,
            allowed_working_directory_roots,
            allowed_environment_keys,
            max_runtime_ms,
            max_stdout_bytes,
            max_stderr_bytes,
            max_concurrent_processes,
            execution_identity: ExecIdentityPolicyV1::CurrentUser,
            allow_stdin: false,
            allow_pty: false,
            allow_elevation: false,
            allow_port_forwarding: false,
        }
    }

    /// Construct an explicit deny-all V1 policy.
    pub fn deny_all() -> Self {
        Self::one_shot(Vec::new(), Vec::new(), Vec::new(), 0, 0, 0, 0)
    }

    /// Validate the policy's bounded, canonical V1 representation.
    pub fn validate(&self) -> Result<(), ExecProtocolError> {
        if self.schema != EXEC_POLICY_SCHEMA_V1 {
            return Err(ExecProtocolError::UnsupportedPolicySchema);
        }
        if self.protocol_version != EXEC_PROTOCOL_VERSION {
            return Err(ExecProtocolError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        if self.allowed_executables.len() > MAX_ALLOWED_EXECUTABLES_V1 {
            return Err(ExecProtocolError::TooManyAllowedExecutables);
        }
        if self.allowed_working_directory_roots.len() > MAX_WORKING_ROOTS_V1 {
            return Err(ExecProtocolError::TooManyWorkingRoots);
        }
        if self.allowed_environment_keys.len() > MAX_ENVIRONMENT_KEYS_V1 {
            return Err(ExecProtocolError::TooManyEnvironmentKeys);
        }

        validate_sorted_unique_paths("allowed_executables", &self.allowed_executables)?;
        validate_sorted_unique_paths(
            "allowed_working_directory_roots",
            &self.allowed_working_directory_roots,
        )?;
        validate_sorted_unique_environment_keys(&self.allowed_environment_keys)?;

        if self.max_runtime_ms > MAX_REQUEST_RUNTIME_MS_V1 {
            return Err(ExecProtocolError::RuntimeLimitTooLarge);
        }
        if self.max_stdout_bytes > MAX_STREAM_OUTPUT_BYTES_V1
            || self.max_stderr_bytes > MAX_STREAM_OUTPUT_BYTES_V1
        {
            return Err(ExecProtocolError::OutputLimitTooLarge);
        }
        if self.max_concurrent_processes > MAX_CONCURRENT_PROCESSES_V1 {
            return Err(ExecProtocolError::ConcurrencyLimitTooLarge);
        }

        if self.allow_stdin
            || self.allow_pty
            || self.allow_elevation
            || self.allow_port_forwarding
        {
            return Err(ExecProtocolError::UnsupportedV1Privilege);
        }

        // A policy is either a fully explicit deny-all policy or it must have
        // finite non-zero ceilings for the work it can authorize.
        if self.allowed_executables.is_empty() {
            if self.max_runtime_ms != 0
                || self.max_stdout_bytes != 0
                || self.max_stderr_bytes != 0
                || self.max_concurrent_processes != 0
            {
                return Err(ExecProtocolError::NonCanonicalDenyAllPolicy);
            }
        } else if self.max_runtime_ms == 0 || self.max_concurrent_processes == 0 {
            return Err(ExecProtocolError::InvalidEnabledPolicyLimits);
        }

        Ok(())
    }

    /// Whether this policy can authorize one-shot execution at all.
    pub fn one_shot_enabled(&self) -> bool {
        !self.allowed_executables.is_empty()
            && self.max_runtime_ms != 0
            && self.max_concurrent_processes != 0
    }

    /// Return deterministic canonical policy bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecProtocolError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Return the domain-separated BLAKE3-256 policy commitment.
    pub fn policy_digest(&self) -> Result<[u8; 32], ExecProtocolError> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(EXEC_POLICY_DIGEST_DOMAIN_V1);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Authenticated-session advertisement for the native execution surface.
///
/// This type is defined in the contract tranche but is not wired into
/// `RawCapabilities` until the companion authority/compatibility tranche.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecAdvertisementV1 {
    /// Protocol version offered by the host.
    pub protocol_version: u16,
    /// Digest of the exact execution policy the host will enforce.
    pub policy_digest: [u8; 32],
    /// Structured one-shot execution is available.
    pub one_shot_enabled: bool,
    /// Interactive PTY is available. Always false for V1.
    pub interactive_pty_enabled: bool,
    /// Maximum simultaneous one-shot processes permitted by the policy.
    pub max_concurrent_processes: u16,
}

impl ExecAdvertisementV1 {
    /// Build an advertisement from a validated V1 policy.
    pub fn from_policy(policy: &ExecPolicyV1) -> Result<Self, ExecProtocolError> {
        policy.validate()?;
        Ok(Self {
            protocol_version: EXEC_PROTOCOL_VERSION,
            policy_digest: policy.policy_digest()?,
            one_shot_enabled: policy.one_shot_enabled(),
            interactive_pty_enabled: false,
            max_concurrent_processes: policy.max_concurrent_processes,
        })
    }

    /// Validate the advertised V1 feature boundary.
    pub fn validate(&self) -> Result<(), ExecProtocolError> {
        if self.protocol_version != EXEC_PROTOCOL_VERSION {
            return Err(ExecProtocolError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        if self.interactive_pty_enabled {
            return Err(ExecProtocolError::UnsupportedV1Privilege);
        }
        if self.max_concurrent_processes > MAX_CONCURRENT_PROCESSES_V1 {
            return Err(ExecProtocolError::ConcurrencyLimitTooLarge);
        }
        if !self.one_shot_enabled && self.max_concurrent_processes != 0 {
            return Err(ExecProtocolError::InvalidAdvertisement);
        }
        Ok(())
    }
}

/// One explicitly supplied environment variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecEnvironmentEntryV1 {
    /// Environment key.
    pub key: String,
    /// Environment value.
    pub value: String,
}

/// Structured one-shot execution request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequestV1 {
    /// Protocol version used to encode the request.
    pub protocol_version: u16,
    /// Viewer-chosen request identifier, unique for the live session.
    pub request_id: u64,
    /// Executable identity/path. This is never a shell command string.
    pub executable: String,
    /// Exact argv entries passed to the executable, not shell-tokenized text.
    pub argv: Vec<String>,
    /// Optional requested working directory.
    pub cwd: Option<String>,
    /// Explicit environment additions, sorted and unique by key.
    pub environment: Vec<ExecEnvironmentEntryV1>,
    /// Requested process runtime ceiling.
    pub timeout_ms: u64,
}

impl ExecRequestV1 {
    /// Validate finite V1 request syntax independent of a host policy.
    pub fn validate(&self) -> Result<(), ExecProtocolError> {
        if self.protocol_version != EXEC_PROTOCOL_VERSION {
            return Err(ExecProtocolError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        validate_path_text("executable", &self.executable)?;
        if self.argv.len() > MAX_ARGUMENTS_V1 {
            return Err(ExecProtocolError::TooManyArguments);
        }
        let mut total_argv_bytes = 0usize;
        for arg in &self.argv {
            validate_text("argv", arg, MAX_ARGUMENT_BYTES_V1, true)?;
            total_argv_bytes = total_argv_bytes.saturating_add(arg.len());
        }
        if total_argv_bytes > MAX_ARGUMENT_VECTOR_BYTES_V1 {
            return Err(ExecProtocolError::ArgumentVectorTooLarge);
        }
        if let Some(cwd) = &self.cwd {
            validate_path_text("cwd", cwd)?;
        }
        if self.environment.len() > MAX_ENVIRONMENT_KEYS_V1 {
            return Err(ExecProtocolError::TooManyEnvironmentKeys);
        }
        let mut previous_key: Option<&str> = None;
        for entry in &self.environment {
            validate_environment_key(&entry.key)?;
            validate_text(
                "environment value",
                &entry.value,
                MAX_ENVIRONMENT_VALUE_BYTES_V1,
                true,
            )?;
            if previous_key.is_some_and(|previous| previous >= entry.key.as_str()) {
                return Err(ExecProtocolError::NonCanonicalEnvironment);
            }
            previous_key = Some(&entry.key);
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_REQUEST_RUNTIME_MS_V1 {
            return Err(ExecProtocolError::InvalidRequestedRuntime);
        }
        Ok(())
    }

    /// Return deterministic canonical request bytes for evidence/audit binding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecProtocolError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Return a domain-separated BLAKE3-256 request commitment.
    pub fn request_digest(&self) -> Result<[u8; 32], ExecProtocolError> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(EXEC_REQUEST_DIGEST_DOMAIN_V1);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Stable reason a host refused an execution request before process creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecRejectReasonV1 {
    /// Execution was not advertised for this authenticated session surface.
    FeatureDisabled,
    /// M1/local consent did not grant execution.
    PermissionDenied,
    /// Request referenced a policy commitment other than the authenticated one.
    PolicyMismatch,
    /// Request was well-formed but denied by the active execution policy.
    PolicyDenied,
    /// Request exceeded a finite concurrency/resource admission limit.
    CapacityExceeded,
    /// Request failed bounded protocol validation.
    InvalidRequest,
    /// Required durable authorization evidence could not be committed.
    AuditUnavailable,
    /// Host encountered a non-policy internal failure before spawn.
    InternalFailure,
}

/// Stable reason a previously accepted process stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecTerminationReasonV1 {
    /// Process exited normally or returned a non-zero exit code itself.
    Exited,
    /// Viewer explicitly cancelled the request.
    Cancelled,
    /// Local consent was revoked while the process was alive.
    ConsentRevoked,
    /// Xenia session ended or failed.
    SessionEnded,
    /// Runtime ceiling elapsed.
    TimedOut,
    /// Output ceiling forced termination according to runtime policy.
    OutputLimit,
    /// Runtime had to terminate the process for an internal fail-closed reason.
    InternalFailure,
}

/// Final status for an accepted execution request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecExitStatusV1 {
    /// Conventional process exit code when available.
    pub code: Option<i32>,
    /// Platform signal number when available.
    pub signal: Option<i32>,
    /// Why Xenia considers the execution finished.
    pub reason: ExecTerminationReasonV1,
}

/// Native execution protocol message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecMessageV1 {
    /// Viewer asks the host to authorize and start a structured process.
    Start {
        /// Digest of the policy committed into the authenticated session.
        policy_digest: [u8; 32],
        /// Structured execution request.
        request: ExecRequestV1,
    },
    /// Viewer cancels an accepted or pending request.
    Cancel {
        /// Request to cancel.
        request_id: u64,
    },
    /// Host durably authorized and admitted the request.
    Accepted {
        /// Accepted request.
        request_id: u64,
    },
    /// Host refused a request before process creation.
    Rejected {
        /// Refused request.
        request_id: u64,
        /// Stable refusal class.
        reason: ExecRejectReasonV1,
    },
    /// Bounded stdout bytes from an accepted request.
    Stdout {
        /// Request producing the bytes.
        request_id: u64,
        /// Output sequence number within this stream.
        sequence: u64,
        /// Bounded output bytes.
        data: Vec<u8>,
    },
    /// Bounded stderr bytes from an accepted request.
    Stderr {
        /// Request producing the bytes.
        request_id: u64,
        /// Output sequence number within this stream.
        sequence: u64,
        /// Bounded output bytes.
        data: Vec<u8>,
    },
    /// Final process status.
    Exit {
        /// Finished request.
        request_id: u64,
        /// Final status.
        status: ExecExitStatusV1,
        /// Total stdout bytes observed by the host before any truncation.
        stdout_bytes: u64,
        /// Total stderr bytes observed by the host before any truncation.
        stderr_bytes: u64,
        /// Whether any stdout/stderr content was omitted due to a finite limit.
        output_truncated: bool,
    },
}

impl ExecMessageV1 {
    /// Validate protocol-local finite bounds.
    pub fn validate(&self) -> Result<(), ExecProtocolError> {
        match self {
            Self::Start { request, .. } => request.validate(),
            Self::Stdout { data, .. } | Self::Stderr { data, .. } => {
                if data.len() > MAX_OUTPUT_CHUNK_BYTES_V1 {
                    Err(ExecProtocolError::OutputChunkTooLarge)
                } else {
                    Ok(())
                }
            }
            Self::Cancel { .. }
            | Self::Accepted { .. }
            | Self::Rejected { .. }
            | Self::Exit { .. } => Ok(()),
        }
    }
}

/// Contract-validation failure.
#[derive(Debug, Error)]
pub enum ExecProtocolError {
    /// Policy schema is not the exact V1 schema.
    #[error("unsupported execution policy schema")]
    UnsupportedPolicySchema,
    /// Protocol revision is not supported.
    #[error("unsupported execution protocol version {0}")]
    UnsupportedProtocolVersion(u16),
    /// Too many executables were listed.
    #[error("too many allowed executables")]
    TooManyAllowedExecutables,
    /// Too many working roots were listed.
    #[error("too many allowed working-directory roots")]
    TooManyWorkingRoots,
    /// Too many environment keys were listed.
    #[error("too many environment keys")]
    TooManyEnvironmentKeys,
    /// Too many argv entries were supplied.
    #[error("too many argv entries")]
    TooManyArguments,
    /// Aggregate argv bytes exceeded the V1 ceiling.
    #[error("argv vector exceeds the V1 byte ceiling")]
    ArgumentVectorTooLarge,
    /// Output chunk exceeded the V1 ceiling.
    #[error("output chunk exceeds the V1 byte ceiling")]
    OutputChunkTooLarge,
    /// Policy runtime ceiling exceeds the absolute protocol bound.
    #[error("execution runtime limit exceeds the V1 protocol ceiling")]
    RuntimeLimitTooLarge,
    /// Policy output ceiling exceeds the absolute protocol bound.
    #[error("execution output limit exceeds the V1 protocol ceiling")]
    OutputLimitTooLarge,
    /// Policy concurrency exceeds the absolute protocol bound.
    #[error("execution concurrency limit exceeds the V1 protocol ceiling")]
    ConcurrencyLimitTooLarge,
    /// V1 policy attempted to enable a future privilege.
    #[error("execution policy enables a privilege unsupported by V1")]
    UnsupportedV1Privilege,
    /// Deny-all policy carried non-zero work limits.
    #[error("deny-all execution policy is not canonical")]
    NonCanonicalDenyAllPolicy,
    /// Enabled execution policy has zero required work limits.
    #[error("enabled execution policy has invalid zero limits")]
    InvalidEnabledPolicyLimits,
    /// Advertisement contains a contradictory feature/limit combination.
    #[error("invalid execution advertisement")]
    InvalidAdvertisement,
    /// Request runtime is zero or exceeds the absolute protocol bound.
    #[error("invalid requested runtime")]
    InvalidRequestedRuntime,
    /// Policy collection is not sorted and unique.
    #[error("non-canonical sorted/unique policy field {0}")]
    NonCanonicalPolicyField(&'static str),
    /// Environment request entries are not strictly sorted/unique by key.
    #[error("environment entries must be strictly sorted and unique by key")]
    NonCanonicalEnvironment,
    /// Text field is empty when V1 requires a value.
    #[error("execution field {0} must not be empty")]
    EmptyField(&'static str),
    /// Text field exceeds a finite bound.
    #[error("execution field {0} exceeds its V1 byte ceiling")]
    FieldTooLarge(&'static str),
    /// Text field contains NUL and cannot be passed safely to OS process APIs.
    #[error("execution field {0} contains NUL")]
    NulInField(&'static str),
    /// Environment key contains a forbidden `=` separator or unsupported byte.
    #[error("invalid environment key")]
    InvalidEnvironmentKey,
    /// Deterministic encoding failed.
    #[error("failed to encode execution contract: {0}")]
    Encoding(#[from] bincode::Error),
}

fn validate_sorted_unique_paths(
    field: &'static str,
    values: &[String],
) -> Result<(), ExecProtocolError> {
    for value in values {
        validate_path_text(field, value)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ExecProtocolError::NonCanonicalPolicyField(field));
    }
    Ok(())
}

fn validate_sorted_unique_environment_keys(values: &[String]) -> Result<(), ExecProtocolError> {
    for value in values {
        validate_environment_key(value)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ExecProtocolError::NonCanonicalPolicyField(
            "allowed_environment_keys",
        ));
    }
    Ok(())
}

fn validate_path_text(field: &'static str, value: &str) -> Result<(), ExecProtocolError> {
    validate_text(field, value, MAX_PATH_BYTES_V1, false)
}

fn validate_environment_key(value: &str) -> Result<(), ExecProtocolError> {
    validate_text(
        "environment key",
        value,
        MAX_ENVIRONMENT_KEY_BYTES_V1,
        false,
    )?;
    if value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Err(ExecProtocolError::InvalidEnvironmentKey);
    }
    Ok(())
}

fn validate_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), ExecProtocolError> {
    if !allow_empty && value.is_empty() {
        return Err(ExecProtocolError::EmptyField(field));
    }
    if value.len() > max_bytes {
        return Err(ExecProtocolError::FieldTooLarge(field));
    }
    if value.as_bytes().contains(&0) {
        return Err(ExecProtocolError::NulInField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ExecPolicyV1 {
        ExecPolicyV1::one_shot(
            vec!["/usr/bin/id".into(), "/usr/bin/uname".into()],
            vec!["/tmp".into()],
            vec!["LANG".into(), "TERM".into()],
            60_000,
            1_048_576,
            1_048_576,
            1,
        )
    }

    fn request(argv: Vec<&str>) -> ExecRequestV1 {
        ExecRequestV1 {
            protocol_version: EXEC_PROTOCOL_VERSION,
            request_id: 7,
            executable: "/usr/bin/uname".into(),
            argv: argv.into_iter().map(str::to_string).collect(),
            cwd: Some("/tmp".into()),
            environment: vec![ExecEnvironmentEntryV1 {
                key: "LANG".into(),
                value: "C.UTF-8".into(),
            }],
            timeout_ms: 5_000,
        }
    }

    #[test]
    fn deny_all_is_explicit_and_valid() {
        let policy = ExecPolicyV1::deny_all();
        policy.validate().unwrap();
        assert!(!policy.one_shot_enabled());
        let advertisement = ExecAdvertisementV1::from_policy(&policy).unwrap();
        assert!(!advertisement.one_shot_enabled);
        assert!(!advertisement.interactive_pty_enabled);
    }

    #[test]
    fn policy_digest_commits_to_privilege_relevant_limits() {
        let first = policy();
        let mut second = first.clone();
        second.max_runtime_ms += 1;
        assert_ne!(
            first.policy_digest().unwrap(),
            second.policy_digest().unwrap()
        );
    }

    #[test]
    fn policy_rejects_future_privileges_in_v1() {
        let mut candidate = policy();
        candidate.allow_pty = true;
        assert!(matches!(
            candidate.validate(),
            Err(ExecProtocolError::UnsupportedV1Privilege)
        ));
    }

    #[test]
    fn policy_collections_are_canonical_sorted_unique() {
        let mut candidate = policy();
        candidate.allowed_executables.reverse();
        assert!(matches!(
            candidate.validate(),
            Err(ExecProtocolError::NonCanonicalPolicyField(
                "allowed_executables"
            ))
        ));
    }

    #[test]
    fn argv_boundaries_are_part_of_the_request_commitment() {
        let one_argument = request(vec!["a b"]);
        let two_arguments = request(vec!["a", "b"]);
        assert_ne!(
            one_argument.request_digest().unwrap(),
            two_arguments.request_digest().unwrap()
        );
    }

    #[test]
    fn shell_metacharacters_are_data_not_a_command_language() {
        let candidate = request(vec!["$(touch /tmp/never-shell-expand)", ";", "&&"]);
        candidate.validate().unwrap();
        // The protocol has only executable + argv fields. Runtime code must pass
        // these entries directly to a process API rather than through a shell.
        assert_eq!(candidate.executable, "/usr/bin/uname");
        assert_eq!(candidate.argv.len(), 3);
    }

    #[test]
    fn environment_must_be_sorted_unique() {
        let mut candidate = request(vec!["-a"]);
        candidate.environment = vec![
            ExecEnvironmentEntryV1 {
                key: "TERM".into(),
                value: "xterm".into(),
            },
            ExecEnvironmentEntryV1 {
                key: "LANG".into(),
                value: "C".into(),
            },
        ];
        assert!(matches!(
            candidate.validate(),
            Err(ExecProtocolError::NonCanonicalEnvironment)
        ));
    }

    #[test]
    fn output_chunks_are_bounded() {
        let message = ExecMessageV1::Stdout {
            request_id: 1,
            sequence: 0,
            data: vec![0u8; MAX_OUTPUT_CHUNK_BYTES_V1 + 1],
        };
        assert!(matches!(
            message.validate(),
            Err(ExecProtocolError::OutputChunkTooLarge)
        ));
    }

    #[test]
    fn advertisement_commits_to_exact_policy() {
        let policy = policy();
        let advertisement = ExecAdvertisementV1::from_policy(&policy).unwrap();
        assert_eq!(advertisement.policy_digest, policy.policy_digest().unwrap());
        assert!(advertisement.one_shot_enabled);
        assert!(!advertisement.interactive_pty_enabled);
        advertisement.validate().unwrap();
    }
}
