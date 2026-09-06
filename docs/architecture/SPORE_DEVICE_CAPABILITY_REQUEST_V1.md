# Spore Device Capability Request Intent — V1

Status: proposed

## Purpose

Define the exact non-authoritative request that sits between:

```text
Holon capability advertisement
        ↓
Spore intent
        ↓
future authenticated Xenia authority
```

This profile deliberately does not mint remote authority.

## Contract

`DeviceCapabilityRequestV1` binds:

- request schema;
- non-zero 128-bit request id;
- exact `DeviceCapabilityAdvertisementV1` digest;
- exact requesting application/workload commitment;
- exact canonical purpose/presentation commitment;
- requested lifetime;
- exact canonical subset of requested device functions.

The complete request has a hand-written domain-separated BLAKE3 commitment.

## Point-of-use validation

`validate_against(advertisement)` requires:

1. both request and advertisement are structurally valid;
2. the supplied advertisement digest is exactly the digest named by the request;
3. every requested capability exists in the advertised set.

Success is only a subject-consistency result. It is not a capability token.

A later authority integration MUST repeat this check at the authenticated
point of use. A serialized/deserialized request cannot authorize device I/O.

## Requested lifetime

V1 accepts a requested lifetime of:

```text
1 ms .. 24 hours
```

This value expresses requester intent only.

It is not:

- trusted wall clock;
- an expiry timestamp;
- a lease;
- consent;
- authority.

The future Xenia authority boundary may shorten or reject it.

## Purpose and workload commitments

The request carries commitments rather than free-form purpose/application
strings.

`requester_workload_commitment` should identify the exact requesting workload,
package, application, or policy-relevant execution subject.

`purpose_commitment` should commit to the exact canonical semantic purpose /
user-facing presentation that is later shown or approved.

Xenia V1 does not define those external canonical encodings. Their owners must
define them before a consent-bound grant can claim semantic equivalence.

## Hearth boundary

Mycelix Hearth relationship/autonomy state is not serialized into this request.

A future policy adapter may evaluate Hearth and produce narrow evidence such as:

```text
policy subject commitment
+ policy generation
+ permitted capability subset
+ applicable constraints
```

That policy evidence must be independently authenticated/verified. A caller
cannot turn `same_hearth=true`, a role label, or a local cached Hearth object
into Xenia authority.

## Future authority composition

Only after the current Xenia authenticated-generation, transport-profile, and
consent/durability lineages are qualified should a later type consume this
request:

```text
DeviceCapabilityRequestV1
+ exact advertisement
+ authenticated session generation
+ authenticated carrier profile
+ consent / revocation evidence
+ optional verified Hearth-derived policy evidence
+ authoritative deadline
        ↓
AuthenticatedDeviceCapabilityGrant
```

The resulting grant should be opaque/non-deserializable and usable only with
the exact authenticated generation that created it.

## Non-claims

This profile does not:

- prove who owns a Holon;
- authenticate an advertisement;
- pair devices;
- prove current Hearth membership;
- show that a human saw the committed purpose;
- establish trusted time;
- grant camera, microphone, location, clipboard, file, signing, biometric, or
  presentation authority;
- define a wire payload or production transport lane.
