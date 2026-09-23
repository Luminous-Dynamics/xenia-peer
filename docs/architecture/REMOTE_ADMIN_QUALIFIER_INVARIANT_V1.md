# Remote Admin Qualifier Invariant v1

Qualification jobs for historical/open privileged-operation subjects are read-only with respect to the exact subject under test.

```text
qualification failure
!= permission to patch the evidence subject
```

A failed exact subject produces evidence of failure and a fresh repair/requalification subject. The qualifier may upload logs/receipts but may not push format, lockfile, source or workflow repairs into the target branch.
