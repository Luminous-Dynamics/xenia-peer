# Authenticated Session Surface

V11 separates two facts that must not be conflated:

1. the cryptographic handshake produced session keys; and
2. the one sealed capability contract was authenticated against the handshake-bound session context.

`PendingSessionSurface` represents state (1). It is consumed by `authenticate_capabilities`, which returns `AuthenticatedSessionSurface` only after the exact transport profile, lane-envelope contract, and expected context hash agree.

Application payload processing should require an `AuthenticatedSessionSurface`. The former boolean-style `SessionCapabilityGuard` API is removed in V11 so new code cannot opt back into the weaker state representation. The desktop and mobile viewers also park user-driven outbound input and clipboard tasks until that transition succeeds. A duplicate capabilities frame is not a renegotiation mechanism; changing capabilities requires a fresh handshake/consent flow.

The host sends its sealed capabilities frame before splitting the transport into media/input tasks. V11 keeps that send-before-payload ordering as part of the source-level session contract, while receivers still fail closed if a future refactor violates it.

This typestate does not replace M1 consent/authorization. It establishes the immutable cryptographic/session semantics on which those higher-layer authorization decisions rely. In particular, an authenticated session surface means “the transport and capability contract is cryptographically fixed,” not “every advertised capability has been granted by local consent.”
