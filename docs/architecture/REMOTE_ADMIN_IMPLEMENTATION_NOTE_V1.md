# Remote Admin Implementation Note v1

The first new runtime work must be an adapter, not an authority primitive.

Preferred first proof: SSH service access under one exact `ConnectService` grant, with independent SSH host authentication, bounded lifetime, revoke/expiry teardown, no generic forwarding, no credential disclosure, and receipts containing metadata/evidence commitments rather than session plaintext.

Implementation remains blocked until the exact parent authority lineage selected by #216 is current-base and qualified enough to permit external effects.
