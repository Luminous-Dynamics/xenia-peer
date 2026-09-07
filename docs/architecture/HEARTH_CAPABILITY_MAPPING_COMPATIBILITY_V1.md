# Hearth Capability Mapping Compatibility — V1

Status: non-authoritative cross-repository compatibility contract

## Purpose

Mirror Mycelix Hearth HXB-2's canonical capability-mapping commitment inside
Xenia without importing Hearth/Holochain runtime state or minting remote
authority.

The compatibility layer deliberately reuses Xenia's own
`DeviceCapabilityV1` enum. This means any change to Xenia's V1 capability codes
changes the compatibility subject instead of being hidden by a duplicated
foreign enum.

## Bound schemas

V1 requires:

```text
Hearth capability mapping schema = 1
Xenia DeviceCapabilityAdvertisementV1 schema = 1
Xenia DeviceCapabilityRequestV1 schema = 1
```

A schema mismatch fails validation before digest calculation.

## Canonical commitment

The encoding exactly mirrors Hearth HXB-2:

```text
domain = "hearth-xenia-capability-mapping-v1\0"
u16be mapping schema
u16be Xenia advertisement schema
u16be Xenia request schema
u64be target policy generation
u16be entry count
entries sorted by Xenia numeric capability code:
  u16be Xenia capability code
  u16be Hearth requirement count
  canonical Hearth requirements
  u8 additional-policy-present
  optional 32-byte additional-policy commitment
```

Canonical Hearth requirement tags are:

```text
1      Observe
2      ActuateLow
3      ActuateHigh
65535 Custom + u16be UTF-8 length + exact UTF-8 bytes
```

The hash is SHA-256.

## Frozen cross-repository vector

The shared example-only policy uses generation `42`:

```text
PresentNotification (2)
  -> ActuateLow

CaptureCamera (10)
  -> Custom("camera.observe.v1")
  -> additional policy commitment = 0x11 repeated 32 bytes

BiometricApproval (30)
  -> Custom("biometric.approve.v1")
```

Expected digest:

```text
64cc86021c01bc0cdaf22992da45cf95e91e1d5a9af750d4cea67b6813a09251
```

This digest must match the independent native Hearth verifier before HXB-2
cross-repository compatibility is claimed.

The example mappings are not universal policy semantics.

## Authority boundary

`HearthCapabilityMappingPolicyV1` is serializable policy/compatibility data.
Validation, digest calculation, and subset resolution do **not** prove:

- that Hearth policy is current;
- that the target requires Hearth policy;
- that a grant exists or is live;
- that presence/usage/time constraints are satisfied;
- that the Xenia peer/session is authenticated;
- that the user consented;
- that execution is authorized.

A later execution grant must bind the exact mapping digest only after target-owned
routing, current Hearth verification when required, and Xenia's authenticated
session/consent/deadline boundaries have independently succeeded.
