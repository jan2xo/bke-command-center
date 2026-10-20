# GeckoView private host seam — Issue #60 (source only)

This module composes the existing pinned-attestor verifier and private admission gateway. It is deliberately **not** an OS peer attestor, Android implementation, public ingress, or enrollment endpoint.

## Boundary

- `src/admin-geckoview-private-host.js` is default-off behind `BKE_GECKOVIEW_PRIVATE_HOST_ENABLED`; that flag is not added to Wrangler and the module is not imported by `src/index.js` or `src/cloudflare-worker-entry.js`.
- The adapter checks all gateway feature flags and platform-verified human Admin identity before resolving or inspecting any private/native peer; the existing gateway independently repeats its checks. A GeckoView-specific verifier accepts only `GECKOVIEW_EXTENSION_NATIVE` signed bindings, including on repeated binding checks. A server-only `trustedHost` must resolve an exclusive private GeckoView/native link and obtain signed bindings from a real OS/browser peer attestor. Those dependencies are not implemented by this source slice; arbitrary callbacks and tests do not establish trust.
- `createPinnedDevicePeerAuthorizer` verifies a fresh nonce-bound P-256 attestation against a server-pinned public key. The signed binding is limited to 30 seconds and binds worker, device key, exclusive session, profile, bridge, ChatGPT target and source.
- The existing `stageDeviceFromPrivateTransport` still checks same-link binding around candidate and challenge exchange, normalizes the device P-256 proposal, and returns only `PREPARED_FOR_HUMAN_REVIEW` with `pairing_authority=NONE` and `dispatch_authority=NONE`.
- No caller/request fields are accepted as worker, installation, profile, target, identity or trust claims. No public route, relay bearer, credentials, lease, enrollment, dispatch, or production behavior is added.

## Failure and retry rules

Missing configuration, malformed links, host resolution failures and ambiguous gateway outcomes fail closed with bounded codes. The attestor uses a fresh challenge nonce and does not retry uncertain delivery. The gateway's existing single-use proof and binding checks remain authoritative. A source-only test cannot certify actual OS channel identity or device lifecycle.

## Unresolved owner dependency

A real GeckoView/Android-side attestor must verify OS-level peer identity, extension/native-port origin, exclusive session/profile/bridge/target binding, and protect the private signing key. Pin provisioning, rotation and revocation require separate human-controlled approval. Until then the adapter remains disconnected/default-off and live device acceptance is NOT RUN.
