# Private Admin-to-Durable-Object invitation RPC — source only

Parent: Command Center Issue #30. Prerequisites: merged #47 scoped routing, #48 authenticated protected finalizer, #49 local SQLite proof, #51 one-use human consent, #52 atomic consent + invitation.

## Scope

This change adds one private named Durable Object RPC, issueAtomicPairingInvitation, through src/admin-invitation-rpc.js and BkeWorkerPairingVault. No public HTTP enrollment route, human-facing presentation, consent endpoint activation, authenticated device transport, active worker lease or GitHub PR claim is added.

The new independent PREPRODUCTION latch BKE_ADMIN_INVITATION_RPC_ENABLED remains absent from wrangler.toml (OFF). No Cloudflare deployment, secret provisioning, permission expansion or production work is authorized.

## Trust path

1. Trusted server sender uses inspectAdminRuntimeAccess and the actual Cloudflare platform-provided executionCtx.access identity, audience and allowlist. Browser flags/headers and caller-provided installation IDs are never authority.
2. Sender asks the existing private GitHub App broker for strictly parsed worker assignment inventory, derives the installation ID and recomputes the exact canonical PR #52 P-256 JWK/resource proposal hash.
3. It derives the SAME keyed subject as the existing PR #48 protected finalizer, using its HMAC human-subject domain, and HMAC-signs a distinct private 30-second command binding purpose, installation, worker, public device key, resources, proposal hash, confirmed consent challenge and server subject.
4. Only the installation-scoped DO is eligible. Receiver validates exact shape, expiry, HMAC, actual ctx.id and canonical proposal before processing. It independently re-fetches the original strict GitHub App inventory, verifies installation tenancy and delegates to existing atomic invitation source.
5. The same installation-wide SQLite transaction validates current GitHub claims, paired/pending/ticket uniqueness and the exact CONFIRMED human proposal/subject, then CONSUMES the approval and writes BOTH pending challenge and Admin ticket. Errors roll back the full transaction. Successful replay cannot consume confirmation again.

GitHub NON_ATOMIC_ENUMERATION remains observational; neither DO nor this command grants exclusive GitHub PR ownership.

## Sensitive response

The DO named RPC returns the full invitation only across the private server boundary. The server sender *requires* a local trusted onPrivateIssued callback, then returns only a reduced non-secret receipt with challenge identifiers and NONE authority markers. The one-use Admin nonce and full challenge message never appear in the ordinary return, browser, device, GitHub or logs. A callback failure after commit is OUTCOME_UNCERTAIN and MUST NOT trigger automatic issuance retries. Future work must design durable server-only nonce handoff before any live activation.

## Certification

Require full exact-head Command Center CI: npm ci, Node tests, npm run check, Wrangler PREPRODUCTION dry-run and real local Workerd/SQLite four-key smoke. Adversarial tests cover tenant mismatch, broker outage, wrong human, changed worker/key/resource proposal, tampering, expiry, replay, concurrency, partial storage rollback, duplicate GitHub assignments, private callback failure and absence of public HTTP endpoint.

No live Cloudflare Access, remote deployed Durable Object, provider installation permission, authenticated human confirmation UI, real device key proof, active lease or dispatch behavior is certified. Production, sensitive activation and unconsented enrollment are locked.
