# Private P-256 attestor verification — SOURCE ONLY

Parent: jan2xo/bke-command-center issue #30. This is one necessary, independent server-side prerequisite after Command Center PR #56 and Worker PRs #105–#107.

The existing admission gateway in src/admin-private-device-admission.js accepts a trusted server-host authorizePeer callback. This PR adds a narrow cryptographic verifier for *one independently attesting private host's signed evidence*. It is not the attestor itself, not OS evidence, and not an enrollment or dispatch grant.

## Contract

- Trusted server code supplies an owner-pinned P-256 public JWK and a private requestSignedBinding(link, {version:1,request_nonce}) function. Neither may come from HTTP body, page, extension content script, or device JSON.
- The verifier generates an independent unpredictable 256-bit challenge on every invocation, including repeat checks during a pairing attempt.
- A trusted host must independently examine an actual native OS/browser session and sign the exact canonical v1 array: audience, version, request nonce, binding audience, source, worker, identity-key fingerprint, native-session fingerprint, three resource fingerprints, expiry. The resulting signature is P-256/SHA-256 IEEE-P1363.
- The verifier refuses bad/missing pins, unsigned or malformed evidence, wrong host key, replayed nonces, unexpected fields, altered worker/profile/resource/session identities, expired or overlong bindings, or private host failures.
- Its return value is ONLY the previously defined immutable binding shape expected by the Command Center gateway. No bearer token, human consent, pairing decision, worker assignment, nativeMessaging permission, or dispatch authority is created.

## Crucial trust boundary

A pinned verifier authenticates which *attestor key* signed an observation. It does NOT prove the attestor is a legitimate Chrome/GeckoView OS host merely because it signed one. The future genuine attestor MUST be separately implemented/certified for platform provenance, private key isolation, installation, browser peer authentication, profile isolation and server-side trusted registration. A local PR #106 P-256 receipt or a Chrome argv origin is insufficient.

## Locks and certification

- Entirely source-only; no deployed src/index.js or src/cloudflare-worker-entry.js imports this verifier, no Wrangler flag, route, service or secret changes.
- No real Chrome installer, browser nativeMessaging permission, Cloudflare activation, live Admin Access interaction, Android PR #90 wake, active worker lease or production.
- Certify with exact-head npm ci, node tests (positive P-256 and adversarial negative cases), npm run check, Wrangler PREPRODUCTION dry-run, real local SQLite Durable Object smoke, changed-file security audit, and SHA-locked merge only if all required gates pass.
- Future independent host-attestor/OS provenance PR required before live admission claims.
