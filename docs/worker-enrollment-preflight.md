# BKE Command Center — worker enrollment preflight (first security wave)

**Status: SOURCE-ONLY, INERT.** Parent: [Issue #30](https://github.com/jan2xo/bke-command-center/issues/30). This is NOT device enrollment, a credential broker, a pairing ceremony, a lease, or a new endpoint. Human authenticated PREPRODUCTION Admin discovery reported 76 installation-approved GitHub repositories on 2026-10-19; catalog discovery is not worker liveness or pairing.

## Authority and scope

GitHub PR labels of the form `bke-worker:<worker_id>` are durable engineering ownership. One worker may actively own one PR; one active PR may have one worker. Command Center is a bounded observer/control surface, **not another task database**. Android GeckoView/WebExtension and desktop WebExtension are the operator-selected entry/runtime targets. Linux/Playwright is preserved legacy evidence, not a gate for this wave.

Each independent worker requires a dedicated identity, human-authenticated ChatGPT target, writable browser/GeckoView profile, extension/native bridge, and bounded broker-controlled lease. No shared writable target/profile or global Admin key; GitHub App PEM and provider tokens never enter worker, browser, GitHub comments, logs or client responses.

## Implemented in this PR

`src/worker-enrollment-policy.js` provides a **pure, internal preflight**. The caller supplies complete, **trusted server-retrieved** paired-worker and cross-repository open-PR inventories. Boolean `inventoryVerified`/`prSnapshotVerified` are internal prerequisites, **not remotely submitted security attestations**. A future API must fetch and validate inventories itself; do not accept client-provided lists or verification booleans.

Reject unverified/incomplete inventories, malformed/duplicated registry identities, reused public-key/target/profile/bridge/nonce fingerprints, invalid worker IDs, expired or unbounded challenge times, non-IDLE dispatch, current PR ownership, malformed/duplicate PR snapshots or multiple `bke-worker:` labels. Return fixed redacted errors only.

`READY_FOR_HUMAN_REVIEW` is **NOT AUTHORIZED, PAIRED or ACTIVE**. SHA-256 fingerprints are comparison hints, **not proof of possession, random nonce generation, replay resistance, target isolation, or cryptographic identity**. The library does not make outbound calls, mint credentials, dispatch wakes, persist identities, expose an HTTP route or authorize any action.

## Next independent security-critical implementation

A fresh PR must implement the actual pairing ceremony: platform-verified allowlisted human Admin plus per-action authorization; bound worker-specific audience and device-key possession proof; server-generated single-use nonce with atomic replay/idempotency tracking and short expiry; concurrency-safe current GitHub assignment and paired-identity reads; narrowly scoped encrypted broker-controlled per-device identity/lease storage (not PR task authority); bounded renewal/revocation and explicit recovery for uncertain dispatch, device loss and conflicting leases; negative security/SSRF/race tests; exact-head CI and independent human PREPRODUCTION acceptance.

No provider installation/permissions change, no Cloudflare secret writes, no Android wake, no public pairing endpoint, no production action, and no human authentication automation are authorized by this PR. **Operator action for this source-only preflight: none.**
