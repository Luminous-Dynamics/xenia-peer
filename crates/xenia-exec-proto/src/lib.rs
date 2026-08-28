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
//! represented separately; there is no shell-command-string field. V1 policies
//! authorize exact invocation tuples so allowing one executable does not silently
//! allow every argument that executable happens to accept.

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
/// Domain separator for invocation commitments/evidence.
pub const EXEC_INVOCATION_DIGEST_DOMAIN_V1: &[u8] = b"xenia-exec-invocation-digest-v1";
/// Domain separator for request commitments/evidence.
pub const EXEC_REQUEST_DIGEST_DOMAIN_V1: &[u8] = b"xenia-exec-request-digest-v1";

/// Maximum encoded path-like text accepted by the protocol contract.
pub const MAX_PATH_BYTES_V1: usize = 4 * 1024;
/// Maximum exact invocation rules in one policy.
pub const MAX_ALLOWED_INVOCATIONS_V1: usize = 256;
/// Maximum argv entries in one invocation.
pub const MAX_ARGUMENTS_V1: usize = 256;
/// Maximum bytes in one argv entry.
pub const MAX_ARGUMENT_BYTES_V1: usize = 4 * 1024;
/// Maximum aggregate argv bytes in one invocation.
pub const MAX_ARGUMENT_VECTOR_BYTES_V1: usize = 64 * 1024;
/// Maximum explicit environment entries in one invocation.
pub const MAX_ENVIRONMENT_ENTRIES_V1: usize = 128;
/// Maximum bytes in an environment key.
pub const MAX_ENVIRONMENT_KEY_BYTES_V1: usize = 256;
/// Maximum bytes in an environment value.
pub const MAX_ENVIRONMENT_VALUE_BYTES_V1: usize = 4 * 1024;
/// Maximum aggregate key/value bytes in one invocation's environment.
pub const MAX_ENVIRONMENT_VECTOR_BYTES_V1: usize = 64 * 1024;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExecIdentityPolicyV1 {
    /// Execute as the same OS identity as the Xenia host process.
    CurrentUser,
}

/// One exact environment entry committed into an invocation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExecEnvironmentEntryV1 {
    /// Environment key.
    pub key: String,
    /// Environment value.
    pub value: String,
}

/// Exact process invocation authorized by a V1 policy.
///
/// `working_directory` and `environment` are explicit so the eventual runtime
/// does not inherit the daemon's ambient current directory or arbitrary daemon
/// environment. The runtime must start from an empty environment and apply the
/// committed entries exactly, subject to platform implementation constraints.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExecInvocationV1 {
    /// Executable identity/path. This is never a shell command string.
    pub executable: String,
    /// Exact argv entries passed directly to the executable.
    pub argv: Vec<String>,
    /// Exact committed working directory for the process.
    pub working_directory: String,
    /// Exact committed environment, sorted and unique by key.
    pub environment: Vec<ExecEnvironmentEntryV1>,
}

impl ExecInvocationV1 {
    /// Validate finite, canonical V1 invocation syntax.
    pub fn validate(&self) -> Result<(), ExecProtocolError> {
        validate_path_text("executable", &self.executable)?;
        validate_path_text("working_directory", &self.working_directory)?;

        if self.argv.len() > MAX_ARGUMENTS_V1 {
            return Err(ExecProtocolError::TooManyArguments);
        }
        let mut argv_bytes = 0usize;
        for arg in &self.argv {
            validate_text("argv", arg, MAX_ARGUMENT_BYTES_V1, true)?;
            argv_bytes = argv_bytes.saturating_add(arg.len());
        }
        if argv_bytes > MAX_ARGUMENT_VECTOR_BYTES_V1 {
            return Err(ExecProtocolError::ArgumentVectorTooLarge);
        }

        if self.environment.len() > MAX_ENVIRONMENT_ENTRIES_V1 {
            return Err(ExecProtocolError::TooManyEnvironmentEntries);
        }
        let mut environment_bytes = 0usize;
        let mut previous_key: Option<&str> = None;
        for entry in &self.environment {
            validate_environment_key(&entry.key)?;
            validate_text(
                "environment value",
                &entry.value,
                MAX_ENVIRONMENT_VALUE_BYTES_V1,
                true,
            )?;
            environment_bytes = environment_bytes
                .saturating_add(entry.key.len())
                .saturating_add(entry.value.len());
            if previous_key.is_some_and(|previous| previous >= entry.key.as_str()) {
                return Err(ExecProtocolError::NonCanonicalEnvironment);
            }
            previous_key = Some(&entry.key);
        }
        if environment_bytes > MAX_ENVIRONMENT_VECTOR_BYTES_V1 {
            return Err(ExecProtocolError::EnvironmentVectorTooLarge);
        }
        Ok(())
    }

    /// Return deterministic canonical invocation bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecProtocolError> {
        self.validate()?;
        Ok(bincode::serialize(self)?)
    }

    /// Return a domain-separated BLAKE3-256 invocation commitment.
    pub fn invocation_digest(&self) -> Result<[u8; 32], ExecProtocolError> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(EXEC_INVOCATION_DIGEST_DOMAIN_V1);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Deterministic authorization policy committed into the session consent scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecPolicyV1 {
    /// Stable schema label. Must equal [`EXEC_POLICY_SCHEMA_V1`].
    pub schema: String,
    /// Protocol revision this policy authorizes.
    pub protocol_version: u16,
    /// Exact invocation tuples authorized by the policy, sorted and unique.
    ///
    /// V1 deliberately has no "any argv" rule. Parameterized/typed argument
    /// policies require an explicit future protocol revision.
    pub allowed_invocations: Vec<ExecInvocationV1>,
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
    /// Construct a V1 policy for exact structured one-shot invocations.
    pub fn one_shot(
        allowed_invocations: Vec<ExecInvocationV1>,
        max_runtime_ms: u64,
        max_stdout_bytes: u64,
        max_stderr_bytes: u64,
        max_concurrent_processes: u16,
    ) -> Self {
        Self {
            schema: EXEC_POLICY_SCHEMA_V1.to_string(),
            protocol_version: EXEC_PROTOCOL_VERSION,
            allowed_invocations,
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

    /// Construct the one canonical deny-all V1 policy.
    pub fn deny_all() -> Self {
        Self::one_shot(Vec::new(), 0, 0, 0, 0)
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
        if self.allowed_invocations.len() > MAX_ALLOWED_INVOCATIONS_V1 {
            return Err(ExecProtocolError::TooManyAllowedInvocations);
        }
        for invocation in &self.allowed_invocations {
            invocation.validate()?;
        }
        if self
            .allowed_invocations
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(ExecProtocolError::NonCanonicalInvocationAllowlist);
        }

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

        if self.allowed_invocations.is_empty() {
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
        !self.allowed_invocations.is_empty()
            && self.max_runtime_ms != 0
            && self.max_concurrent_processes != 0
    }

    /// Whether the exact request is admitted by this policy before runtime-only
    /// filesystem/process checks. This does not replace M1 consent.
    pub fn permits_request(&self, request: &ExecRequestV1) -> Result<bool, ExecProtocolError> {
        self.validate()?;
        request.validate()?;
        if !self.one_shot_enabled() || request.timeout_ms > self.max_runtime_ms {
            return Ok(false);
        }
        Ok(self
            .allowed_invocations
            .binary_search(&request.invocation)
            .is_ok())
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
        if self.one_shot_enabled != (self.max_concurrent_processes != 0) {
            return Err(ExecProtocolError::InvalidAdvertisement);
        }
        Ok(())
    }
}

/// Structured one-shot execution request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequestV1 {
    /// Protocol version used to encode the request.
    pub protocol_version: u16,
    /// Viewer-chosen request identifier, unique for the live session.
    pub request_id: u64,
    /// Exact invocation requested from the authenticated policy allowlist.
    pub invocation: ExecInvocationV1,
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
        self.invocation.validate()?;
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
    /// Too many invocation rules were listed.
    #[error("too many allowed execution invocations")]
    TooManyAllowedInvocations,
    /// Policy invocation list is not strictly sorted and unique.
    #[error("execution invocation allowlist must be strictly sorted and unique")]
    NonCanonicalInvocationAllowlist,
    /// Too many argv entries were supplied.
    #[error("too many argv entries")]
    TooManyArguments,
    /// Aggregate argv bytes exceeded the V1 ceiling.
    #[error("argv vector exceeds the V1 byte ceiling")]
    ArgumentVectorTooLarge,
    /// Too many explicit environment entries were supplied.
    #[error("too many environment entries")]
    TooManyEnvironmentEntries,
    /// Aggregate environment bytes exceeded the V1 ceiling.
    #[error("environment vector exceeds the V1 byte ceiling")]
    EnvironmentVectorTooLarge,
    /// Environment entries are not strictly sorted/unique by key.
    #[error("environment entries must be strictly sorted and unique by key")]
    NonCanonicalEnvironment,
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
    /// Text field is empty when V1 requires a value.
    #[error("execution field {0} must not be empty")]
    EmptyField(&'static str),
    /// Text field exceeds a finite bound.
    #[error("execution field {0} exceeds its V1 byte ceiling")]
    FieldTooLarge(&'static str),
    /// Text field contains NUL and cannot be passed safely to OS process APIs.
    #[error("execution field {0} contains NUL")]
    NulInField(&'static str),
    /// Environment key contains a forbidden separator or unsupported byte.
    #[error("invalid environment key")]
    InvalidEnvironmentKey,
    /// Deterministic encoding failed.
    #[error("failed to encode execution contract: {0}")]
    Encoding(#[from] bincode::Error),
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

    fn invocation(executable: &str, argv: Vec<&str>) -> ExecInvocationV1 {
        ExecInvocationV1 {
            executable: executable.into(),
            argv: argv.into_iter().map(str::to_string).collect(),
            working_directory: "/tmp".into(),
            environment: vec![ExecEnvironmentEntryV1 {
                key: "LANG".into(),
                value: "C.UTF-8".into(),
            }],
        }
    }

    fn policy() -> ExecPolicyV1 {
        ExecPolicyV1::one_shot(
            vec![
                invocation("/usr/bin/id", vec![]),
                invocation("/usr/bin/uname", vec!["-a"]),
            ],
            60_000,
            1_048_576,
            1_048_576,
            1,
        )
    }

    fn request(invocation: ExecInvocationV1) -> ExecRequestV1 {
        ExecRequestV1 {
            protocol_version: EXEC_PROTOCOL_VERSION,
            request_id: 7,
            invocation,
            timeout_ms: 5_000,
        }
    }

    #[test]
    fn deny_all_is_single_canonical_shape() {
        let policy = ExecPolicyV1::deny_all();
        policy.validate().unwrap();
        assert!(!policy.one_shot_enabled());
        let advertisement = ExecAdvertisementV1::from_policy(&policy).unwrap();
        assert!(!advertisement.one_shot_enabled);
        assert_eq!(advertisement.max_concurrent_processes, 0);
        advertisement.validate().unwrap();
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
    fn invocation_allowlist_is_canonical_sorted_unique() {
        let mut candidate = policy();
        candidate.allowed_invocations.reverse();
        assert!(matches!(
            candidate.validate(),
            Err(ExecProtocolError::NonCanonicalInvocationAllowlist)
        ));
    }

    #[test]
    fn policy_allows_exact_invocation_not_arbitrary_argv() {
        let policy = policy();
        let allowed = request(invocation("/usr/bin/uname", vec!["-a"]));
        let denied = request(invocation("/usr/bin/uname", vec!["--help"]));
        assert!(policy.permits_request(&allowed).unwrap());
        assert!(!policy.permits_request(&denied).unwrap());
    }

    #[test]
    fn argv_boundaries_are_part_of_the_invocation_commitment() {
        let one_argument = invocation("/usr/bin/tool", vec!["a b"]);
        let two_arguments = invocation("/usr/bin/tool", vec!["a", "b"]);
        assert_ne!(
            one_argument.invocation_digest().unwrap(),
            two_arguments.invocation_digest().unwrap()
        );
    }

    #[test]
    fn shell_metacharacters_are_only_argv_data() {
        let candidate = invocation(
            "/usr/bin/tool",
            vec!["$(touch /tmp/never-shell-expand)", ";", "&&"],
        );
        candidate.validate().unwrap();
        assert_eq!(candidate.executable, "/usr/bin/tool");
        assert_eq!(candidate.argv.len(), 3);
    }

    #[test]
    fn invocation_requires_explicit_working_directory() {
        let mut candidate = invocation("/usr/bin/id", vec![]);
        candidate.working_directory.clear();
        assert!(matches!(
            candidate.validate(),
            Err(ExecProtocolError::EmptyField("working_directory"))
        ));
    }

    #[test]
    fn environment_must_be_sorted_unique() {
        let mut candidate = invocation("/usr/bin/id", vec![]);
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
    fn advertisement_rejects_enabled_with_zero_concurrency() {
        let policy = policy();
        let mut advertisement = ExecAdvertisementV1::from_policy(&policy).unwrap();
        advertisement.max_concurrent_processes = 0;
        assert!(matches!(
            advertisement.validate(),
            Err(ExecProtocolError::InvalidAdvertisement)
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
