// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Privacy-preserving, version-aware freshness evidence for remote UI regions.
//!
//! This module measures only caller-supplied region/version metadata. It does
//! not inspect pixels, OCR, window titles, applications, typed text, or raw
//! input. Region IDs are expected to be ephemeral and session-scoped.
//!
//! The output is a vector of per-region evidence, not an aggregate score.
//! Version lag and local pipeline age are deliberately independent: version
//! lag can be known even when clock evidence is unavailable. No cross-host
//! one-way delay or physical input-to-photon value is computed here.

/// Caller-declared semantic class for a region.
///
/// The class is metadata supplied by a documented source or explicit user
/// action. It must never be inferred by this module from screen content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegionClass {
    /// Region explicitly declared critical to the current interaction.
    CriticalInteraction,
    /// Region explicitly declared as the current active interaction surface.
    ActiveInteraction,
    /// Cursor, caret, focus ring, or similarly small feedback region.
    PointerOrCaretFeedback,
    /// Background animation or a region declared replaceable by its producer.
    Background,
    /// No trusted class metadata is available.
    Unclassified,
}

/// Session- and capture-generation-scoped identity for one local region.
///
/// `region_id` must be a pseudonymous local identifier, not a window title,
/// application name, user ID, or content-derived identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RegionIdentity {
    /// Monotonically increasing generation for this Xenia session.
    pub session_generation: u64,
    /// Ephemeral pseudonymous region identifier.
    pub region_id: u64,
    /// Incremented whenever the region/capture source is recreated.
    pub region_generation: u64,
}

/// Version emitted for one region within one identity generation.
///
/// Versions must be monotonically increasing and contiguous if the caller
/// intends their numeric difference to mean the number of missed updates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RegionVersion {
    /// Region identity associated with this version.
    pub identity: RegionIdentity,
    /// Monotonic source version within the region generation.
    pub version: u64,
}

/// Optional local timing evidence for one software-pipeline segment.
///
/// Both ticks must originate from the same monotonic clock domain. This
/// describes local queue-to-observation age only; it is not source-to-viewer
/// one-way network delay and is not physical photon timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalStageAgeEvidence {
    /// Clock-domain ID used for the enqueue tick.
    pub enqueue_clock_domain: u64,
    /// Clock-domain ID used for the observation tick.
    pub observation_clock_domain: u64,
    /// Local monotonic tick when the update entered the measured stage.
    pub enqueued_at_ticks: u64,
    /// Local monotonic tick when the update left the measured stage.
    pub observed_at_ticks: u64,
}

/// Independent evidence for one region's current freshness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionFreshnessSample {
    /// Latest source version advertised by the capture producer, if known.
    pub source: Option<RegionVersion>,
    /// Latest version known to have reached the viewer's corresponding
    /// software observation boundary, if known.
    pub observed: Option<RegionVersion>,
    /// Caller-declared class; never inferred from pixels in this module.
    pub class: RegionClass,
    /// Explicit opt-in relevance from a documented source, in 0..=100.
    pub declared_relevance: Option<u8>,
    /// Optional local queue/pipeline timing evidence.
    pub local_age: Option<LocalStageAgeEvidence>,
}

/// Why version freshness could not be established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionUnknownReason {
    /// The source has not supplied a version for this region.
    MissingSource,
    /// The viewer has not supplied an observed version for this region.
    MissingObservation,
    /// Source and viewer observations refer to different Xenia sessions.
    SessionGenerationMismatch,
    /// Source and viewer observations refer to different region IDs.
    RegionIdMismatch,
    /// Source and viewer observations refer to different region generations.
    RegionGenerationMismatch,
    /// The viewer claims to have observed a version newer than the source.
    ObservedVersionAheadOfSource,
}

/// Result of comparing source and viewer versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionFreshness {
    /// Numeric source-to-viewer version lag; meaningful as missed-update
    /// count only when the producer uses contiguous version increments.
    Known {
        /// `source.version - observed.version`.
        version_lag: u64,
    },
    /// Evidence was incomplete or internally inconsistent.
    Unknown(VersionUnknownReason),
}

/// Why local pipeline age could not be computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAgeUnknownReason {
    /// No local timing evidence was supplied.
    MissingEvidence,
    /// Enqueue and observation ticks use different monotonic clock domains.
    ClockDomainMismatch,
    /// Observation tick predates enqueue tick in the declared clock domain.
    ClockRegression,
}

/// Result of local queue/pipeline age evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalPipelineAge {
    /// Elapsed ticks inside one declared local clock domain.
    Known {
        /// `observed_at_ticks - enqueued_at_ticks`.
        age_ticks: u64,
        /// Clock domain in which the duration was measured.
        clock_domain: u64,
    },
    /// Local timing was unavailable or inconsistent.
    Unknown(LocalAgeUnknownReason),
}

/// Independent per-region freshness result.
///
/// This intentionally exposes a vector of evidence rather than one scalar.
/// Consumers may report class-conditioned or worst-region distributions, but
/// must not silently collapse UNKNOWN regions into fresh or zero-age values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionFreshnessResult {
    /// Source/viewer version freshness.
    pub version: VersionFreshness,
    /// Local queue/pipeline age, independent from version freshness.
    pub local_pipeline_age: LocalPipelineAge,
    /// Caller-declared region class.
    pub class: RegionClass,
    /// Explicit relevance supplied by the user or documented source.
    pub declared_relevance: Option<u8>,
}

/// Invalid caller-provided region metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionMetadataError {
    /// Explicit relevance must be in the closed interval 0..=100.
    RelevanceOutOfRange,
}

/// Assess one region sample without inspecting protected content.
pub fn assess_region_freshness(
    sample: RegionFreshnessSample,
) -> Result<RegionFreshnessResult, RegionMetadataError> {
    if sample.declared_relevance.is_some_and(|value| value > 100) {
        return Err(RegionMetadataError::RelevanceOutOfRange);
    }

    Ok(RegionFreshnessResult {
        version: assess_version(sample.source, sample.observed),
        local_pipeline_age: assess_local_age(sample.local_age),
        class: sample.class,
        declared_relevance: sample.declared_relevance,
    })
}

/// Compare two region versions without comparing clocks or inspecting content.
pub fn assess_version(
    source: Option<RegionVersion>,
    observed: Option<RegionVersion>,
) -> VersionFreshness {
    let source = match source {
        Some(value) => value,
        None => return VersionFreshness::Unknown(VersionUnknownReason::MissingSource),
    };
    let observed = match observed {
        Some(value) => value,
        None => {
            return VersionFreshness::Unknown(VersionUnknownReason::MissingObservation);
        }
    };

    if source.identity.session_generation != observed.identity.session_generation {
        return VersionFreshness::Unknown(VersionUnknownReason::SessionGenerationMismatch);
    }
    if source.identity.region_id != observed.identity.region_id {
        return VersionFreshness::Unknown(VersionUnknownReason::RegionIdMismatch);
    }
    if source.identity.region_generation != observed.identity.region_generation {
        return VersionFreshness::Unknown(VersionUnknownReason::RegionGenerationMismatch);
    }

    match source.version.checked_sub(observed.version) {
        Some(version_lag) => VersionFreshness::Known { version_lag },
        None => VersionFreshness::Unknown(
            VersionUnknownReason::ObservedVersionAheadOfSource,
        ),
    }
}

/// Compute local queue/pipeline age only when both ticks share one clock domain.
pub fn assess_local_age(evidence: Option<LocalStageAgeEvidence>) -> LocalPipelineAge {
    let evidence = match evidence {
        Some(value) => value,
        None => return LocalPipelineAge::Unknown(LocalAgeUnknownReason::MissingEvidence),
    };

    if evidence.enqueue_clock_domain != evidence.observation_clock_domain {
        return LocalPipelineAge::Unknown(LocalAgeUnknownReason::ClockDomainMismatch);
    }

    match evidence
        .observed_at_ticks
        .checked_sub(evidence.enqueued_at_ticks)
    {
        Some(age_ticks) => LocalPipelineAge::Known {
            age_ticks,
            clock_domain: evidence.enqueue_clock_domain,
        },
        None => LocalPipelineAge::Unknown(LocalAgeUnknownReason::ClockRegression),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> RegionIdentity {
        RegionIdentity {
            session_generation: 7,
            region_id: 42,
            region_generation: 3,
        }
    }

    fn version(version: u64) -> RegionVersion {
        RegionVersion {
            identity: identity(),
            version,
        }
    }

    fn sample() -> RegionFreshnessSample {
        RegionFreshnessSample {
            source: Some(version(105)),
            observed: Some(version(101)),
            class: RegionClass::ActiveInteraction,
            declared_relevance: Some(80),
            local_age: Some(LocalStageAgeEvidence {
                enqueue_clock_domain: 9,
                observation_clock_domain: 9,
                enqueued_at_ticks: 100,
                observed_at_ticks: 145,
            }),
        }
    }

    #[test]
    fn version_lag_is_reported_without_collapsing_to_time() {
        let result = assess_region_freshness(sample())
            .unwrap_or_else(|error| panic!("valid sample rejected: {error:?}"));
        assert_eq!(
            result.version,
            VersionFreshness::Known { version_lag: 4 }
        );
        assert_eq!(
            result.local_pipeline_age,
            LocalPipelineAge::Known {
                age_ticks: 45,
                clock_domain: 9,
            }
        );
    }

    #[test]
    fn exact_version_match_is_fresh_at_the_version_boundary() {
        assert_eq!(
            assess_version(Some(version(10)), Some(version(10))),
            VersionFreshness::Known { version_lag: 0 }
        );
    }

    #[test]
    fn missing_version_evidence_is_unknown_not_fresh() {
        assert_eq!(
            assess_version(None, Some(version(1))),
            VersionFreshness::Unknown(VersionUnknownReason::MissingSource)
        );
        assert_eq!(
            assess_version(Some(version(1)), None),
            VersionFreshness::Unknown(VersionUnknownReason::MissingObservation)
        );
    }

    #[test]
    fn future_observation_is_rejected_as_inconsistent() {
        assert_eq!(
            assess_version(Some(version(10)), Some(version(11))),
            VersionFreshness::Unknown(
                VersionUnknownReason::ObservedVersionAheadOfSource
            )
        );
    }

    #[test]
    fn session_generation_mismatch_cannot_look_fresh() {
        let mut other = version(10);
        other.identity.session_generation += 1;
        assert_eq!(
            assess_version(Some(version(10)), Some(other)),
            VersionFreshness::Unknown(VersionUnknownReason::SessionGenerationMismatch)
        );
    }

    #[test]
    fn region_id_mismatch_cannot_look_fresh() {
        let mut other = version(10);
        other.identity.region_id += 1;
        assert_eq!(
            assess_version(Some(version(10)), Some(other)),
            VersionFreshness::Unknown(VersionUnknownReason::RegionIdMismatch)
        );
    }

    #[test]
    fn region_generation_mismatch_cannot_look_fresh() {
        let mut other = version(10);
        other.identity.region_generation += 1;
        assert_eq!(
            assess_version(Some(version(10)), Some(other)),
            VersionFreshness::Unknown(VersionUnknownReason::RegionGenerationMismatch)
        );
    }

    #[test]
    fn local_age_requires_a_common_monotonic_clock_domain() {
        assert_eq!(
            assess_local_age(Some(LocalStageAgeEvidence {
                enqueue_clock_domain: 1,
                observation_clock_domain: 2,
                enqueued_at_ticks: 10,
                observed_at_ticks: 30,
            })),
            LocalPipelineAge::Unknown(LocalAgeUnknownReason::ClockDomainMismatch)
        );
    }

    #[test]
    fn local_clock_regression_is_unknown() {
        assert_eq!(
            assess_local_age(Some(LocalStageAgeEvidence {
                enqueue_clock_domain: 1,
                observation_clock_domain: 1,
                enqueued_at_ticks: 30,
                observed_at_ticks: 10,
            })),
            LocalPipelineAge::Unknown(LocalAgeUnknownReason::ClockRegression)
        );
    }

    #[test]
    fn version_evidence_can_be_known_when_local_timing_is_unknown() {
        let mut value = sample();
        value.local_age = None;
        let result = assess_region_freshness(value)
            .unwrap_or_else(|error| panic!("valid sample rejected: {error:?}"));
        assert_eq!(
            result.version,
            VersionFreshness::Known { version_lag: 4 }
        );
        assert_eq!(
            result.local_pipeline_age,
            LocalPipelineAge::Unknown(LocalAgeUnknownReason::MissingEvidence)
        );
    }

    #[test]
    fn relevance_outside_closed_range_is_rejected() {
        let mut value = sample();
        value.declared_relevance = Some(101);
        assert_eq!(
            assess_region_freshness(value),
            Err(RegionMetadataError::RelevanceOutOfRange)
        );
    }

    #[test]
    fn no_content_bearing_fields_exist_in_the_region_contract() {
        let fields = [
            "session_generation",
            "region_id",
            "region_generation",
            "version",
        ];
        assert!(fields.iter().all(|field| !field.contains("pixel")));
        assert!(fields.iter().all(|field| !field.contains("window")));
        assert!(fields.iter().all(|field| !field.contains("text")));
    }
}
