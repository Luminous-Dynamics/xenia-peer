# Remote Admin Adapter Sequence v1

Status: sequencing note; no runtime authority

Remote administration should now be treated as adapter work over existing Xenia authority, not another generic security subsystem.

## Dependencies

Cross-cutting authority ordering belongs to #216.

Adapter implementation starts only when the exact parent authority/durability surface it needs is current-base, reviewed, and qualified. A historical PASS on a parent does not qualify a restacked adapter.

## Sequence

1. **SSH ConnectService** — prove exact-target bounded service access, host-key evidence, revoke/expiry teardown, and no privilege widening.
2. **RDP ConnectService** — reuse service-access authority; add Windows-specific redirection and credential-security profiles.
3. **Redfish/OOB Observe + Recover** — prove resource/action mapping and destructive-operation receipts.
4. **Nixward request bridge** — authorize delivery/use of one exact request while preserving independent Nixward authorization.
5. **Unattended issuance policy** — fresh short-lived grants from explicit enrollment, never permanent sessions.
6. **Break-glass issuance/recovery policy** — stronger approval, short TTL, explicit assurance downgrade/requalification semantics.

## Anti-duplication gate

An adapter PR is rejected if it introduces a second implementation of any of:

- generic Xenia capability/grant semantics;
- remote screen/input/clipboard/file authority;
- durable operation admission/receipt store;
- authority epochs/recovery;
- general Nixward mutation authority;
- protocol-independent credential vault semantics.

Adapters translate qualified authority into one exact protocol operation and return bounded evidence. They do not define another policy plane.
