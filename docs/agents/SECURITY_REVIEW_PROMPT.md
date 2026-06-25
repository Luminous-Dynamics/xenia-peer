# Security Review Prompt for Future Agents

Before modifying Xenia, answer these questions in the handoff or PR summary:

1. Does this change alter capture, injection, transport, authentication, consent,
   revocation, ledger, or admin behavior?
2. Does it introduce or modify a network bind address?
3. Does it make a privileged path easier to start silently?
4. Does revocation still fail closed?
5. Are ledger/audit events preserved for privileged session lifecycle changes?
6. Did `scripts/check-secure-defaults.py .` pass?
7. Did the release dashboard get regenerated for release-significant changes?

If the answer to questions 1, 2, or 3 is yes, the change requires a security note.
Do not bury the note in terminal logs.
