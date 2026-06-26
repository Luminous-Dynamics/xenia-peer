# RC1 Candidate Review Evidence

Status: generated for explicit RC1 candidate review.

This evidence confirms that Xenia has exited blocker burn-down while still
recording the current release-train status. Before promotion this is `pre-rc`; after the explicit promotion PR this is `rc`.

## Release train

- Current milestone: `normalization-v0.2`
- Next candidate: `rc1`
- Release status: `rc`
- Hard blockers: `0`
- Soft blockers: `0`

## Validation checks

| Check | Status | Exit code |
| --- | --- | ---: |
| `xenia-validate` | `pass` | `0` |
| `release-readiness` | `pass` | `0` |
| `release-readiness-rc1` | `pass` | `0` |

## Required evidence set

| Evidence | Present | Path |
| --- | --- | --- |
| normalization review | `yes` | `docs/release/evidence/NORMALIZATION_V0_2_EVIDENCE_REVIEW.md` |
| release dashboard | `yes` | `docs/release/evidence/RC1_RELEASE_DASHBOARD.md` |
| source archive checksums | `yes` | `docs/release/evidence/RC1_SOURCE_ARCHIVE_CHECKSUMS.md` |
| normalization dry-run | `yes` | `docs/release/evidence/NORMALIZATION_V0_2_DRY_RUN_EVIDENCE.md` |
| transport fault injection | `yes` | `docs/release/evidence/RC1_TRANSPORT_FAULT_INJECTION.md` |
| admin audit event names | `yes` | `docs/release/evidence/RC1_ADMIN_AUDIT_EVENT_NAMES.md` |

## Decision

- RC1 candidate review ready: `True`
- Promotion performed: `True`
- Promotion policy: Promotion must be a separate explicit PR after candidate review passes; status rc records that promotion has occurred.

## Next step

If this review PR passes CI and is merged, open a separate promotion PR.
That promotion PR should be intentionally small and should change only the
release-train status/evidence needed to mark RC1.
