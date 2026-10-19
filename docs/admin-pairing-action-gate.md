# Secure Admin pairing-action admission gate — source-only

**Status:** independent source/test gate only, **OFF**, unimported by any HTTP route and not deployed. Parent: [Command Center Issue #30](https://github.com/jan2xo/bke-command-center/issues/30). Depends on preflight PR #39, cryptographic inactive pairing ceremony #40, dormant Cloudflare pairing-vault source #41.

## Purpose

The operator must explicitly approve **each worker action**, never merely log in once and give workers a shared Admin token. The source module `inspectPairingAdminAction(request, env, executionCtx)` validates:

- Exact runtime latches: PREPRODUCTION, verified Access edge, existing Admin allowlist configuration, and **separate** `BKE_ADMIN_PAIRING_ACTIONS_ENABLED=true` (absent in Wrangler).
- Cloudflare **platform-verified** `executionCtx.access`, exact application AUD and allowlisted email, via the existing `inspectAdminRuntimeAccess`; NEVER `cf-access-jwt-assertion`, `cf-access-authenticated-user-email` or any caller-supplied JSON boolean as substitute.
- Same-origin browser-only human POST, exact `Origin: https://cc.jl-bke.com`, `Sec-Fetch-Site: same-origin`, supported Fetch Mode, HTTPS approved hostname, JSON without content encoding or transfer of a giant payload; body limited to 1024 bytes even when `Content-Length` is absent.
- Strict exact JSON keys `action`, `worker_id`, `confirm_worker_id` with canonical worker ID, `pair|revoke` action, matching confirmation and `x-bke-admin-action` header. Any installation ID, GitHub bearer, identity escalation field or unrecognized action is rejected.
- Only returns redacted `BLOCKED` codes or `AUTHORIZED_FOR_PREFLIGHT` with action+worker identifier. It NEVER returns verified Admin identity/email, bearer, active lease or cryptographic proof.

**`AUTHORIZED_FOR_PREFLIGHT` IS NOT PAIRING, REVOCATION, ENROLLMENT, A TRUSTED DO RPC, OR A ONE-TIME AUTHORIZATION.** This result is only usable as a local admission result within a yet-to-be-certified trusted server path. Anyone able to call the JS function with fake `executionCtx` or injected `env` in a unit test can simulate a pass; those mocks are not real Cloudflare Access evidence. Browser origin and Fetch Metadata mitigate CSRF but are not secret or proof of user presence.

## Remaining integration and gates

A separate PR must introduce a fully trusted server integration with route/feature locks, CSRF **plus** a server-minted single-use per-action challenge atomically consumed for pair/revoke (prevent replay/double-click); fresh approved installation identity from the broker and a **complete** authorized cross-repository GitHub open-PR snapshot; and a deterministic one-installation Durable Object RPC routing layer. Never authorize PR actions from catalog metadata: currently reported 76 repositories says nothing about actual `pull_requests:read` installation-granted scope. Do not pass unsigned `authorized: true` or `verified: true` flags across untrusted boundaries as security attestations.

`createWorkerPairingCeremony` must run inside the one installation-scoped storage instance; callback functions cannot be serialized over Cloudflare RPC. Human Access authentication and admin consent remain human-only. Actual live pairing, credential/lease renewal/revocation, profile isolation and two-worker execution require further separately certified integration and human PREPRODUCTION acceptance. Android parked PR #90, Cloudflare secrets, runtime deployments, OAuth/MFA/CAPTCHA and production remain untouched.

Minimum source certification: existing exact-head Command Center `ci` with full Node tests, `npm run check` and Wrangler dry-run, plus bounded negative-auth and changed-file audit. No operator action for this inert wave.
