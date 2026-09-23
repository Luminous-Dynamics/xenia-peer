# SSH ConnectService Implementation Scope v1

The first runtime adapter should be intentionally minimal:

- one exact TCP service target;
- one exact SSH host-key policy;
- one bounded lifetime;
- no generic forwarding;
- no agent forwarding;
- no credential disclosure;
- no embedded shell policy;
- no persistence after revoke/expiry;
- metadata-only receipts by default.

The adapter consumes the current qualified Xenia authority stack selected by #216; it does not add a new grant/token/session-intent format.
