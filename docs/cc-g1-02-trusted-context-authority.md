# CC-G1-02 — Trusted-context authority map

**Status: BLOCKED at the authoritative-record boundary.** This document records evidence from current-main source for the authorized CC-G1-02 discovery phase. It does not implement a resolver, configure a trust provider, or assert live identity.

Audit date: 2026-10-22 (Asia/Manila)

## Canonical state

- Command Center current `main` at discovery: `e1bb68d5f91a40ea6e0e34063db160bc3f155760`.
- Canonical engineering instructions: [`bke.md`](../bke.md), which requires current-main context recovery, one fresh PR per intent, exact-head proof, and fail-closed behavior for ambiguous authority.
- Parent scope: [Command Center Issue #30](https://github.com/jan2xo/bke-command-center/issues/30) and [BKE Worker Issue #121](https://github.com/jan2xo/bke-worker/issues/121).
- The prerequisite read-only Admin discovery [PR #29](https://github.com/jan2xo/bke-command-center/pull/29) is merged at `c042b6fc46a026f9750f318d51a38879dead613d`.
- At recovery time, Command Center PRs #64 (CC-G1-01 challenge lifecycle), #62 (Android attestation verifier), and #61 (native-host admission seam) were OPEN/DRAFT/UNMERGED. Treat their code as non-authoritative for current main; **this intent imports none of it**.
- BKE Worker PRs #145 and #90 remain separate OPEN/DRAFT/UNMERGED lanes. #90's queued-delivery uncertainty is a read-only reconciliation dependency; this intent must not wake, arm, relabel, reassign, or modify it.

## Required identity tuple

The intended resolver must bind a single record to all of:

1. Server-verified GitHub App installation ID and actual installation-named Command Center Durable Object.
2. One unique worker ID, the exact enrolled public-key fingerprint, enrollment freshness, and non-revoked state.
3. A server-authenticated *current* transport/browser session with generation and freshness/replay fences.
4. Current browser-profile, bridge, and ChatGPT-target fingerprints independently verified at the trusted boundary.
5. Purpose and audience scoped to one downstream operation.

No one existing current-main record contains this tuple.

## Evidence inventory

### Installation identity — partly available

- Worker `cloudflare-relay/src/admin-assignment-inventory.js` resolves the GitHub App installation from the provider and mints a bounded installation token for read-only repository/PR inventory.
- Command Center `src/admin-worker-assignments.js` validates and retains `trusted_installation_id` only in its internal projection; browser-safe diagnostics drop it.
- Command Center `src/admin-installation-vault-attestation.js` maps `installation:<id>` using the Durable Object namespace and checks that the received request is for the actual named object.

**What this proves:** installation-scoped routing when the existing trusted server path invokes it. It does not associate a live device/session with that installation.

### Worker ownership — observed, not a lease

- The installed-GitHub-App inventory lists approved repositories and open PR labels of the form `bke-worker:<worker-id>`.
- The Command Center contract explicitly classifies this as `NON_ATOMIC_ENUMERATION`; it is an ownership observation, not a proof of worker liveness, current browser session, or dispatch lease.
- Duplicate/ambiguous PR-to-worker mapping must block, not be resolved by choosing a label heuristically.

### Enrollment / revocation — available only as inactive vault evidence

Current-main `src/worker-pairing-durable-store.js` stores bounded arrays in the installation-scoped SQLite Durable Object using keys:

- `bke:pairing:v1:paired`
- `bke:pairing:v1:pending`
- `bke:pairing:v1:admin_actions`
- `bke:pairing:v1:consents`
- `bke:pairing:v1:prepared`

The paired-row schema contains `worker_id`, `identity_public_key_sha256`, `browser_profile_sha256`, `bridge_identity_sha256`, `chatgpt_target_sha256`, `nonce_sha256`, `status`, `registered_at_ms`, and `enrollment_expires_at_ms`. The accepted statuses are `PAIRED_INACTIVE` and `REVOKED`; protected pairing writes `PAIRED_INACTIVE`, with a bounded one-hour enrollment TTL. This is not an active-device status or a session ledger, and current-main runtime wiring does not establish an active live enrollment authority.

Critically, `src/admin-inactive-registration-audit.js` explicitly emits `session_binding_authority: "NONE"` and states that a nonce, pairing key, or browser profile claim must not be used to synthesize a session binding.

### Native peer/session binding — schema and injected seams, not a configured authority

- `src/admin-pinned-device-attestor.js` can verify a signature over a short-lived binding that includes `session_binding_sha256`, worker ID, enrolled-key fingerprint, source, profile hash, bridge hash, and ChatGPT-target hash.
- Its factory requires a server-owned pinned public key and `requestSignedBinding` transport. The comments require that transport and pin to come from a verified server configuration/private service and that a real host independently verify the OS/browser peer.
- `src/admin-private-device-admission.js` additionally requires `authorizePeer`, a private in-process `link`, and resource readers; there is no public ingress. The current-main source does not configure an actual authoritative attestor key, authenticated transport, or current-session data reader.

These are dependency seams, not proof that current-session authentication is available. A test callback, caller-supplied object, page message, or arbitrary “trusted” callback cannot fill the dependency.

### Relay current connection — server-observed socket, but not bound to enrolled device/session facts

Worker current-main `cloudflare-relay/src/index.js` uses a per-worker `WorkerSession` Durable Object and maintains `active_connection_id` plus a socket attachment containing `workerId`, server-generated `connectionId`, `registered`, and `sessionId`. The server-generated connection ID is useful transport state.

However:

- The relay first checks a bearer derived from `BKE_WORKER_RELAY_TOKEN_KEY` and the worker ID. This is a worker-scoped shared-secret derivation, not proof of possession of the enrolled device private key for this session.
- `cloudflare-relay/src/protocol.js:366-375` validates `session_id` from the client only as a string of 1–128 characters and checks the claimed worker ID; it does not cryptographically bind the session to enrollment or the three current resource fingerprints.
- The relay's WorkerSession state is not tied to the Command Center paired-vault row's public-key hash or resource hashes.
- Command Center's existing `BKE_GITHUB_READ_BROKER` service binding exposes GitHub-read/inventory capabilities only. It is not a trusted reader for WorkerSession socket state; no session-context RPC/audience contract is present in current main.
- The WorkerSession inspection method in current main is separately described as a private candidate behind an unprovisioned/unaudited lock. It must not be repurposed as a trusted session API without a separately designed and authorized contract.

Thus the relay has a server-observed live socket record, but **not** a complete authenticated current-session binding usable by the resolver.

### Local device identity — not a server authority

Worker `browser-extension/src/device-identity.ts` stores the P-256 private CryptoKey in browser-profile IndexedDB with `extractable: false`. That local key is useful for client proof-of-possession but does not, by itself, prove to Command Center which installation, current relay session, browser profile, native bridge, or ChatGPT target is active now. Local records can be stale, copied by unsafe recovery, revoked server-side, or inconsistent with the server's enrollment register; the server must verify evidence rather than trust local claims.

## Blocking gap

**No current-main source-authoritative record and authenticated read path atomically binds installation + enrollment + device key + current live session + currently attested profile/bridge/ChatGPT target.**

The current sources give separate partial facts: installation namespace; GitHub assignment observation; inactive/revoked enrollment row with old resource hashes; client-local key; and relay socket/session metadata. They do not form a single validated tuple, nor is there a configured, scoped cross-system reader to join them.

### Minimum missing dependency

Before implementing successful resolution, specify and independently validate:

1. A server-private authenticated session-binding issuer/record source. It must observe a current trusted native/browser peer, establish possession of the enrolled key, derive the live session generation/expiry server-side, and attest the exact current resource hashes. It must not accept fields copied from caller/device JSON as identity.
2. A scoped server-to-server Command Center read contract to obtain that evidence, with caller principal, audience, installation, worker, request nonce/expiry, and failure semantics bound and validated. The existing GitHub read broker must not be assumed to provide this authority.
3. A freshness/revocation policy joining that session evidence with the actual installation-scoped paired-vault enrollment and worker/key fingerprint; all updates or reads that affect the decision must be fail-closed under uncertainty.
4. A defined owner-controlled enrollment/revocation path and authoritative sources for changed profile, bridge, and ChatGPT targets. Old paired-row hashes cannot prove they still match the current session.

## Required fail-closed behavior

The eventual resolver must return a typed BLOCKED result, never success, for:

- unknown or revoked worker, expired/stale enrollment, or wrong actual installation/DO ID;
- missing, revoked, unprovisioned, or mismatched device public key;
- zero or multiple enrollment/ownership/session matches;
- missing session reader, expired session, replaced connection generation, replay, uncertain delivery, or provider/storage error;
- changed browser-profile, bridge, or ChatGPT-target hash;
- missing/invalid native-peer attestation, missing server-side pin, unavailable trusted context, or any attempt to substitute local/test/caller-provided data;
- any inconsistent GitHub assignment observation that makes worker ownership ambiguous.

## Checkpoint disposition

- **Authority recovery + source map:** DONE by this documentation change.
- **Resolver implementation:** BLOCKED pending the missing authoritative current-session binding source and authenticated scoped read contract.
- **Resolver tests / exact-head certification / security acceptance:** NOT RUN / NOT CLAIMED; no resolver is implemented here.
- **Dormant verifier, enrollment, runtime route, and relay session path remain unwired/unchanged.** No feature flag, deployment, credential write, live device pairing, GitHub label mutation, wake, dispatch, or merge occurred.
- This does not establish real Android enrollment or distinct-GitHub-identity review approval.
