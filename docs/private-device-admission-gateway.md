# Private device transport-bound admission gateway — SOURCE ONLY

Program dependency [issue #30](https://github.com/jan2xo/bke-command-center/issues/30), following Command Center source [PR #55](https://github.com/jan2xo/bke-command-center/pull/55) at main `28a06408e319c86b0b6d0e95bac8caefa819faef` and Worker desktop signer [PR #105](https://github.com/jan2xo/bke-worker/pull/105) at main `aaca56e4b7d8f449b96245d099109ac9c66db78b`.

## Trust and execution boundary

The new `stageDeviceFromPrivateTransport` function is a strictly **server-only in-process gateway** for a future separately certified native messaging / GeckoView extension transport adapter. The deployable `src/index.js` and `src/cloudflare-worker-entry.js` do **not** call it. No HTTP/WebSocket enrollment route is created, and the new `BKE_NATIVE_DEVICE_ADMISSION_ENABLED` feature flag is **absent from Wrangler**. Production and PREPRODUCTION activation remain locked.

The gateway requires:

1. Real Cloudflare platform Access identity and human Admin authorization **before** inspecting any device or private peer.
2. A strictly private `authorizePeer(link,executionCtx,env)` callback supplied by a **trusted server host**, using native/extension OS-channel evidence, not device self-asserted authorization. It must attest one verified source (`DESKTOP_EXTENSION_NATIVE` or `GECKOVIEW_EXTENSION_NATIVE`), one identity P-256 key SHA-256, one worker ID, each of the three resource fingerprints, an exclusive session-binding SHA-256 and a fresh expiry no more than 30 seconds away. The callback is NOT implemented in this PR; a future certified host must provide it. **A forged callback from client input is NOT authentication.**
3. Only a private duplex `link` with `readCandidate()` and `exchangeProof(challenge)`. The candidate has exactly worker ID, public P-256 key and resource fingerprint fields. No `approved`, `trusted`, installation number, Admin subject, private key or human labels are accepted from the device.
4. The server recomputes the canonical P-256 key fingerprint using the existing Command Center #55 canonicalizer, comparing it and all resource fingerprints with the independently attested host binding. It rechecks the **same** private link binding before and after each proof exchange. A disappearing/switched/rebound native peer fails closed.
5. Only a **server-issued** PR #55 domain-separated challenge can be presented through the one-use in-process signer capability. It is tied to the fresh GitHub App installation, the verified human's keyed subject, worker, device public key, resource digests, random 256-bit nonce and 30-second expiry. The original #55 stage flow verifies the P-256 signature independently and rechecks Access/GitHub scope before the correct installation Durable Object atomically persists one 90-second `prepared` proposal.
6. Human-readable labels come from a separate trusted `describeResources` server callback, never the unpaired device. The result is **PREPARED_FOR_HUMAN_REVIEW**, expressly `pairing_authority=NONE` and `dispatch_authority=NONE`. No Admin consent is created or finalized by the gateway; Admin review, protected inactive pairing and worker/GitHub leases remain separate later stages.

The server capability is used once per candidate and once per signing exchange; uncertain exchange or storage results must not automatically retry. Connection-level replay, process crash recovery and credible native peer attestation must be certified by the later **real transport host**. P-256 signature alone proves only key possession. The old BKE Worker relay bearer is NOT reused for device admission.

## Certification, gaps and locks

Full exact-head Command Center CI must pass npm ci, Node adversarial tests, npm run check, Wrangler PREPRODUCTION dry-run, and the real local Workerd/SQLite smoke. Tests cover Access denial before link activity, per-session canonical P-256, attestation mismatch/expiry, native channel binding switch, proof failure, duplicate concurrent proposals, GitHub broker failure, storage rollback, malformed device frames and deployed route OFF.

**Still missing:** actual browser extension ↔ native host / GeckoView authenticated channel and platform-specific peer-attestation implementation; live human-authenticated PREPRODUCTION device ceremony, challenge delivery, client/browser lifecycle acceptance, exclusive worker lease and GitHub PR atomic assignment. No secrets or production/Cloudflare deployment, no OAuth/MFA/CAPTCHA automation, no new GitHub App permissions, no Worker PR #90 wake. The next independent PR must implement and certify the native transport attestor or equivalent authenticated service principal without treating client claims as trusted.
