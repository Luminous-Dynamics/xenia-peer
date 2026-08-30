# Xenia operation-store recovery contract

This standalone contract defines evidence-bound recovery assessment and planning for fail-stopped privileged-operation stores.

It intentionally provides no persistence, database repair, adapter execution, or `clear_recovery` shortcut.

The core sequence is:

```text
RecoveryRequired
  -> immutable assessment
  -> short-lived approved plan
  -> validate current epoch + required evidence + plan lifetime
  -> Quarantine | ResumeSameEpoch | governed epoch/store transition
```

`ResumeSameEpoch` preserves durable authority-history continuity only; it does not preserve privileged runtime sessions or old grants.

See `docs/ADR-014-governed-operation-store-recovery.md` for the normative architecture boundary.
