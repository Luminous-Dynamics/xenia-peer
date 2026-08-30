# ADR-014: Governed operation-store recovery

Status: draft

## Context

The privileged-operation store intentionally enters a fail-stop `RecoveryRequired` state after an unclean writer lifecycle or other durability uncertainty. A generic `clear_recovery(bool)` or automatic marker cleanup would collapse several materially different cases into one unsafe operation and could resurrect stale privileged authority.

ADR-013 introduced operation-authority epochs so a store generation rollover, store replacement, or global revocation invalidates all grants from prior epochs. This ADR defines the recovery ceremony that may preserve or advance that authority state.

## Decision

Recovery is a two-phase, evidence-bound protocol:

1. produce an immutable, read-only `OperationStoreRecoveryAssessmentV1`;
2. produce a short-lived, explicitly approved `OperationStoreRecoveryPlanV1` bound to that exact assessment and current authority epoch;
3. validate the live plan and, when applicable, an exact successor authority epoch before any recovery mutation is committed.

Serialized assessment and plan objects are evidence/decision commitments, not bearer credentials.

## Recovery checks

V1 models these canonical evidence categories:

- store structural integrity;
- filesystem authority-root integrity;
- admission/use-slot integrity;
- receipt-chain integrity;
- frontier/anchor continuity;
- armed-operation reconciliation.

A plan carries a sorted unique set of checks that policy requires. `ResumeSameEpoch`, generation rollover, and replacement require all named checks to be present and `Passed`. A `Failed`, `NotApplicable`, or missing required check rejects the plan.

`NotApplicable` is allowed only to describe a feature that is genuinely outside the deployment's implemented claim. It never satisfies a required check.

## Recovery dispositions

### `Quarantine`

Keep the store fail-stopped. No mutation authority is restored and no next authority epoch is created.

### `ResumeSameEpoch`

Permit recovery only when evidence proves continuity of the exact existing store identity, generation, authority epoch, admission/use-slot history, and every other policy-required security invariant.

This does **not** preserve live privileged sessions. Entering `RecoveryRequired` terminates or drains privileged runtime authority. After a successful same-epoch recovery, new privileged operations still require a fresh authenticated session, fresh consent/approval, and a fresh grant bound to the current epoch.

### `AdvanceStoreGenerationAndEpoch`

Use the same store identity, advance to exactly the next store generation, and create exactly the next authority epoch under `AuthorityEpochReasonV1::RecoveryGenerationRollover`. The successor epoch must commit the exact recovery-plan digest.

Old grants remain stale; they cannot be transformed into the new epoch.

### `ReplaceStoreAndAdvanceEpoch`

Create a new store identity at generation zero and exactly the next authority epoch under `AuthorityEpochReasonV1::StoreReplacement`. The successor epoch must commit the exact recovery-plan digest.

This path must not import historical grants or reconstruct spent-use budgets as fresh authority.

## Plan lifetime and stale-plan defense

A V1 recovery plan has a maximum lifetime of 15 minutes.

The transition API must not expose a low-level helper that validates only the proposed successor. `OperationStoreRecoveryPlanV1::validate_next_epoch(...)` deliberately accepts the assessment, current epoch, next epoch, and current time and revalidates the entire chain in one call:

- plan schema/window;
- exact assessment commitment;
- assessment/current epoch agreement;
- authority-domain agreement;
- store id/generation agreement;
- required evidence checks;
- exact successor transition;
- exact recovery-plan digest in the successor reason.

This prevents an implementation from accidentally applying a plan after a concurrent epoch advance or after the plan expires.

## Recovery runtime rules

Entering `RecoveryRequired` MUST:

1. fail-stop new privileged admissions;
2. forbid new effect arming;
3. terminate or drain privileged adapters according to their fail-safe policy;
4. preserve uncertainty for any operation whose effect outcome cannot be proved;
5. expose only inspection/assessment interfaces needed for recovery.

Recovery MUST NOT silently turn an armed uncertain operation into a retryable operation.

## Persistence transaction boundary

A concrete store recovery implementation must commit a recovery disposition atomically with all authority-bearing metadata it changes. In particular, generation/epoch rollover must not expose a state where the store generation is new but the authority epoch is old, or vice versa.

A future persistent recovery record should commit at least:

- assessment digest;
- plan digest;
- old authority epoch digest;
- resulting authority epoch digest when changed;
- old/new store id and generation as applicable;
- recovery policy and approval digests;
- completion time and implementation profile.

## Rollback safety

`ResumeSameEpoch` is only valid when applicable external anti-rollback evidence proves continuity. If the deployment cannot prove that an older store snapshot has not replaced newer consumed authority, the safe choices are quarantine or a governed generation/store replacement with an authority-epoch advance.

## Relationship to filesystem trust

ADR-011 and ADR-012 define path and Linux authority-root trust. A successful SQLite `integrity_check` does not substitute for filesystem authority-root evidence, and filesystem trust does not substitute for anti-rollback or receipt/admission semantic integrity.

## Non-goals

V1 does not implement:

- automatic repair of corrupted SQLite pages;
- reconstruction of unknown external effects;
- rollback of target-side actions;
- generic exactly-once execution;
- import of old grants into a new authority epoch;
- automatic clearing of `RecoveryRequired`;
- native exec, PTY, forwarding, or credential use.

## Integration gates

Before a concrete recovery mutation API is enabled:

1. authority-epoch binding must be present end-to-end in grant, admission, store metadata, and effect-arm schemas;
2. the SQLite backend must implement the qualified filesystem authority-root profile;
3. receipt persistence/frontier state used by recovery must be durable and validated;
4. C0-C10 crash/fault tests must cover the recovery transaction itself;
5. stale-plan, concurrent-epoch, failed-check, and armed-uncertainty negative tests must pass.
