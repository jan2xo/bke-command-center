# Worker device-key pairing ceremony — source-only security wave

**Status:** implemented as internal source and tests only. No HTTP route, no Durable Object binding/migration, no provider authentication change, no live pairing, no worker wake, no production or PREPRODUCTION deployment. Parent: [Command Center #30](https://github.com/jan2xo/bke-command-center/issues/30). Prerequisite preflight: PR #39 (merged main `67070847bb758e4c4129f2b2fecfb4c67925259b`).

## Scope

`src/worker-pairing-ceremony.js` is a dependency-injected, side-effect-isolated **cryptographic ceremony**. It can issue a bounded random challenge to a candidate P-256 public key, verify a P-256 ECDSA/SHA-256 device signature over an exact audience/installation/worker/resource/nonce/expiry payload, and atomically replace the consumed nonce with an **inactive** registry record. It supports human-admin-authorized revocation with a permanent tombstone; no silent re-enrollment or key reuse.

`PAIRED_INACTIVE` explicitly does **not** grant access to GitHub, ChatGPT, Cloudflare, a Worker relay, a task, or a renewable execution lease. This PR does not introduce a token, bearer, API key, browser bridge, or automatic wake. Registration expires for further trust consideration after one hour; expiry is **not** a live credential lifecycle. An actual device-usable lease, key rotation/renewal and authenticated runtime transport require a separate intent.

## Trust boundary / caller obligations

`createWorkerPairingCeremony` is **NOT a public API endpoint**. The future caller must supply:

1. `authorizeAdmin(action, workerId, context)` implemented entirely server-side with Cloudflare's **platform-verified** `ctx.access`, configured application AUD, explicitly allowlisted human identity, action/worker-specific approval and appropriate CSRF safeguards for mutations. NEVER implement it as `return clientBody.authorized`. Only `true` authorizes `pair` or `revoke`; all failures block.
2. `readLiveAssignments()` that enumerates a **complete, current**, trusted GitHub PR inventory across all worker-owned repositories (not a client-submitted or partially paginated list), validates each head/label state and fails closed on rate limits, pagination gaps, ambiguous scope or unavailable evidence. `verified` is a *trusted return contract*, not evidence if browser-controlled.
3. `store.atomic(callback)`, an **atomic, serializable transaction namespace for the installation**, covering `paired` AND `pending` together for ALL worker IDs. A single installation-scoped SQLite-backed Cloudflare Durable Object is suitable; Cloudflare KV, process memory, multiple isolated DO instances and naive read/put are not. Preserve atomic rollback and commit, storage encryption at rest as applicable, least-privileged internal access and bounded retention. The source deliberately does not create or bind this namespace.
4. Trusted installation identity injected from existing GitHub App broker-controlled configuration, never from a device-supplied installation ID. All device resources are SHA-256 fingerprint hints; operators must independently validate actual isolated ChatGPT browser profile, bridge identity, and target. Fingerprints do **not** prove runtime isolation.
5. `cryptoImpl` is Cloudflare Web Crypto; `clock` is a monotonic-enough trusted server timestamp in milliseconds. No device/browser time is accepted.

**The storage inventory of enrolled worker identity is not a task/PR database.** GitHub remains the sole durable engineering/PR assignment authority. No registered device is authorized to dispatch an active PR until it has independently certified, fresh GitHub ownership and safe runtime delivery proof.

## Protocol implemented

1. Only after trusted human admin authorizes `pair`, validate canonical worker ID, exact P-256 JWK coordinates (no private key), and bounded SHA-256 fingerprints for ChatGPT target, browser profile and bridge.
2. Read complete trusted GitHub assignments. Inside a single installation-wide atomic transaction, validate paired registry and pending challenges; run the PR #39 preflight; refuse reused identity/target/profile/bridge, ambiguous/active PR labels, busy identity or conflicting active challenge.
3. Issue 24 bytes of random challenge ID and 32 bytes of nonce (Web Crypto CSPRNG), expiring in **120 seconds**. Challenge message is an exact JSON array of v1 audience, trusted installation ID, worker ID, challenge ID, nonce, public-key thumbprint, all three resource fingerprints and expiry. Client may see challenge and message, but no private key or installation bearer.
4. The device signs the unchanged UTF-8 challenge message with its P-256 private key using WebCrypto ECDSA SHA-256 (64-byte IEEE-P1363 signature, base64url encoding).
5. The server accepts only the matching worker/challenge; checks trusted fresh PR inventory, exact challenge expiry, signature, registry conflicts and scope again. It atomically consumes pending challenge and records **PAIRED_INACTIVE** with key and resource hashes and a one-hour validity bound. Replay and racing duplicate completions fail closed.
6. A separately human-authorized `revoke` transaction marks the identity `REVOKED`, expires it immediately and clears pending challenges. Tombstones block silent re-use; operator recovery must be a separate explicit action.

**No real WebExtension/GeckoView device has been paired or live-certified.** Unit tests use generated disposable P-256 keypairs and an in-memory serial transaction simulator, proving protocol logic only. The simulator is NOT a deployment storage adapter.

## Required next independent intent before activation

Integrate an installation-scoped SQLite-backed Cloudflare Durable Object **with a verified atomic transaction adapter**, private RPC caller identity, authenticated Admin action routes, CSRF and anti-replay controls, current complete GitHub inventory retrieval, and explicit operator consent. Prove real Worker-to-browser key possession, device-specific audience, paired identity renewal/rotation, revocation enforcement on every sensitive call, crash-ambiguous dispatch and preproduction live negative tests. Must not share global Admin credentials, App PEM, GitHub PAT, OAuth state or browser profiles. Source-only merge is not authorization for deployment, pairing, worker wake, new Cloudflare bindings, secret changes or production cutover.

## Certification

Existing Command Center full exact-head `ci` (npm ci/test/check/Cloudflare dry-run), focused key/replay/race/negative auth tests, and review of trust boundaries. No Android APK, Linux/CDP or worker-wake certification because no runtime is touched. Never claim an inactive pairing as worker liveness.
