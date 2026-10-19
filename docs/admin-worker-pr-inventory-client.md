# Admin worker PR ownership inventory — trusted Command Center consumer

**Status: SOURCE-ONLY, DEFAULT OFF.** Next authorized security dependency of [Command Center Issue #30](https://github.com/jan2xo/bke-command-center/issues/30) and [BKE Worker #104](https://github.com/jan2xo/bke-worker/pull/104). Worker #104 source main was certified and SHA-locked merged at `566ca613b1353aabcc0bc0096001a430cb36c697`. This is NOT evidence that the new private RPC/permission scope was activated in Cloudflare or exercised live.

## Scope of this independent intent

`src/admin-worker-assignments.js` adds `readAdminWorkerAssignments(env, executionCtx)`: an **on-demand, read-only, server-side** consumer of the existing PREPRODUCTION service binding `BKE_GITHUB_READ_BROKER.listVerifiedWorkerAssignments`. The only request passed is `{purpose:"admin_worker_assignment_inventory"}` — no browser- or device-chosen repository, installation ID, worker, URL or token. Before ANY RPC, it requires all of:

- Existing PREPRODUCTION and human-verification latches `BKE_PREPRODUCTION=true` and `BKE_ACCESS_POLICY_VERIFIED=true`;
- A separate `BKE_ADMIN_PR_INVENTORY_ENABLED=true` latch, **not present in Wrangler source or current deployed configuration**;
- Exact Cloudflare platform `executionCtx.access` audience and allowlisted verified human identity through the already-certified `inspectAdminRuntimeAccess`; no fallbacks to browser-supplied JWTs, emails or booleans.

`GET /api/admin/worker-assignments` is a read-only route, **OFF by default**, with no parameters or POST/action path. Method violation is 405, query is 400, disabled is 404, unverified Admin is 403, unknown/upstream broker errors are fixed-code 503, and successful replies carry `Cache-Control: no-store`. No route change affects the existing `/admin` GitHub source catalog. Authentication is done *before* any broker operation.

The private broker's response must exactly match its declared authority, installation identity, approved scope and non-atomic consistency contract. Command Center independently rejects unexpected or additional fields, invalid grants expressed as data, malformed labels/head SHA, duplicate PRs/workers across repositories, repository-ID drift, conflicting IDs/names, impossible counts and oversized inventories. It constructs new reduced objects; never passes broker payloads directly to the client. The trusted internal model retains a validated installation ID for a **future** single-installation DO-routing design, but the browser API deliberately omits that identifier. No GitHub bearer, PEM, repository contents, PR body or personal browser profiles may cross either response boundary.

## The anti-claim invariant

**`OBSERVED_ONLY` + `NON_ATOMIC_ENUMERATION` + `dispatch_authority: NONE`.** A GitHub App reading even every PR across 76 approved repositories does not take an atomic GitHub lock. PR heads and worker labels can change between page reads; missing claims do NOT mean a worker is free. This API therefore has no `verified`, `free_worker`, `ready_to_pair`, `prSnapshotVerified` or `authorized` return value. Never promote this output directly into the `evaluateWorkerEnrollment({prSnapshotVerified:true})` preflight or a real device lease. Future pairing needs a separate certified decision-time exact-head GitHub revalidation and atomic installation-scoped lease/claim mechanism.

## Required certification and locked rollout

Source-only exact-head Command Center CI: Node suite including 16 new negative/positive tests, syntax checks, Wrangler PREPRODUCTION dry-run, and independent boundary review. Test doubles for Cloudflare `ctx.access` and service binding are **not** live identity/scope proof.

Activation remains **unapproved**: the relay currently lacks `BKE_ADMIN_PR_INVENTORY_ENABLED=true`; Command Center also leaves this flag unset. Even if later set, an owner must certify the real GitHub App installation's `pull_requests:read` grant, broker binding, verified Cloudflare Access behavior, complete GraphQL pagination, Free-tier budget and a human Admin session. Any App installation permission changes, secrets, PREPRODUCTION rollout, DO pairing RPC, device key renewal, browser profiles and production changes require separate explicit gates. Parked Android PR #90 remains untouched.

The follow-up independent intent is the **server-only pairing decision and one-use human-action authorization**, joining the inactive P-256 ceremony (#40), dormant SQL Durable Object storage (#41), human admission gate (#42), and the newly available observed PR snapshot, under exact-head revalidation, race and human PREPRODUCTION certification.
