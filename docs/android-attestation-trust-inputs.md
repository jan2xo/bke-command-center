# Android attestation trust inputs — private source contract

Status: source-only, default-off, non-routed, non-authoritative. Parent: [Command Center #30](https://github.com/jan2xo/bke-command-center/issues/30), blocker [#66](https://github.com/jan2xo/bke-command-center/issues/66), implementing intent [#69](https://github.com/jan2xo/bke-command-center/issues/69). This module is not imported by the HTTP/Worker entrypoint.

## Policy contract

The module validates a server-owned versioned object with schema `bke.android-key-attestation-policy.v1`. It requires explicit approved/unapproved/revoked state, a bounded policy version and approval reference/time, one to eight unique lowercase 64-character SHA-256 root fingerprints, one exact Android package name, and one to eight unique lowercase 64-character signing certificate SHA-256 digests. Unknown fields, versions, malformed/duplicate pins, absent policy, unapproved policy and revoked policy fail closed.

**No real root fingerprint, package name or signer digest is provisioned by this change.** Test pins are synthetic fixtures only. Shape validation cannot prove where an object came from: future runtime callers must source the policy from an independently approved server-only configuration/store, never request/device/page fields. Identity membership is not X.509 validation. The APIs always return `authority: NONE`.

## Google revocation loader

The only source is `https://android.googleapis.com/attestation/status`. The loader does not accept a URL, redirects are errors, requests are timeout bounded, content length and streamed bytes are capped at 1 MiB, JSON and Google entry schema are strict, and unsupported status/reason/serial/date forms fail closed. It parses the source's `Cache-Control: max-age` and `Age`, requires a plausible upstream `Date`, applies a six-hour maximum freshness and one-minute minimum compatible snapshot lifetime, and detects per-loader local wall-clock rollback. A stale cache is never returned as success; a failed refresh after expiry returns typed `BLOCKED`.

The in-memory single-flight cache is isolate-local and ephemeral. No Durable Object, extra task database, deployed config or secret is introduced. A refresh result returns the #62 documented four-field snapshot shape only:
`{ source, fetchedAtMs, cacheMaxAgeMs, entries }`.
The returned `authority: NONE` is an explicit guardrail, not a trust grant. Serial status evaluation returns `NOT_LISTED` only for a fresh, correctly shaped snapshot; `REVOKED`, `SUSPENDED`, missing, stale or malformed evidence does not succeed.

## Tests and limits

The accompanying tests call the real policy parser, status parser, cache/clock logic and certificate-serial evaluator. They cover policy denials, root/package/signer mismatch, malformed/duplicate pins, strict Google schema, serial canonicalization, status outcomes, redirect/source mismatch, HTTP/network/timeout failures, oversized bodies, cache headers, freshness and clock rollback, refresh concurrency, and ignored call-time URL/pin injection. Fetch is injectable strictly for local unit tests; the production default is the platform HTTPS fetch implementation, and the endpoint cannot be changed through loader arguments.

The tests do not establish live Google availability, trust-anchor authenticity, APK signer approval, real Android hardware identity, or trusted GeckoView session authority. Test code uses generated/synthetic policy fixtures and mocked HTTP only.

## Not implemented here

- No verifier implementation (reuse the separately reviewed #62 contract; do not copy its unmerged source).
- No initial enrollment or recurring proof challenge ledger.
- No resolver/current-session reader, owner approval workflow, or actual trust policy provisioning.
- No public HTTP/WebSocket endpoint, runtime wiring, enrollment/pairing, credentials, labels, wake, deployment, PREPRODUCTION activation or production behavior.
- No actual invocation inside deployed Worker/DO runtime: **NOT RUN**.
