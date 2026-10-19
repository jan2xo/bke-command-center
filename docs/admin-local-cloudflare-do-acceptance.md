# Local Cloudflare SQLite Durable Object acceptance probe

**Scope: test-only CI proof, not a live enrollment or Cloudflare deployment.** Dependency of Command Center issue #30 after merged PR #48. All pairing, human Admin authentication, production, worker wakes, profile access and GitHub ownership changes remain locked.

## Why this is a separate PR

The previous pairing and replay tests used Node transaction simulators, while Wrangler dry-run only checked that the Cloudflare Worker bundle could compile. Neither proved that our bounded `createPairingAtomicStore(ctx.storage)` works on a real Cloudflare SQLite-backed Durable Object. This certifies that missing runtime dependency using local Workerd and a fixture that is *not* imported from the actual Cloudflare Command Center entrypoint.

## Test configuration

`scripts/pairing-sqlite-smoke/wrangler.toml` defines a dedicated disposable Worker `bke-pairing-sqlite-local-smoke` with a dedicated SQLite-backed `SmokeVault` class, a dedicated migration, no routes, `workers_dev=false`, no secrets and no external provider. This file is NEVER passed to `wrangler deploy` by the production/preproduction workflows.

`scripts/pairing-sqlite-smoke/worker.js` imports the real project `createPairingAtomicStore`, not a fake storage adapter. Each fixture DO extends Cloudflare's actual `DurableObject` runtime base class. It opens Cloudflare `ctx.storage.transaction` for the three real pairing registry keys (`paired`, `pending`, `admin_actions`). Its only test values are tiny non-sensitive placeholders; no device key, ChatGPT session, human credential or App private key is included.

`scripts/pairing-sqlite-smoke/run-local-smoke.mjs` starts **Wrangler `dev --local`** listening only on `127.0.0.1:8977`, waits for readiness and checks:
- Same-installation writes remain visible across multiple calls and a subsequent **separate HTTP request**.
- Distinct installation-derived DO identities do not share the same paired/pending/admin-action state.
- All three keys are committed together.
- An intentionally thrown error after writes to all three keys rolls back the full transaction, with no partial modifications.
- Two concurrent writes to the same installation's Durable Object produce four unique records, not lost updates.
- Unknown HTTP paths fail closed with 404.

The smoke runner emits only PASS/FAIL and short causal details and terminates the entire local Wrangler process group. It uses no real Github App permissions, Cloudflare tokens or production secrets. `package.json` includes `npm run cloudflare:local-do-smoke`; the existing exact-head Command Center CI runs it **after** `npm ci`, all Node tests/syntax checks and the Wrangler PREPRODUCTION dry-run, on a clean GitHub Actions runner. Run artifacts and exact-head source SHA remain GitHub PR ledger evidence.

## Important limits

Local Workerd SQLite acceptance is not proof that the live Cloudflare account's PREPRODUCTION Durable Object was deployed, that its real service bindings or private GitHub broker work, or that human Access/CSRF, human-controlled pairing ticket, authenticated device transport, Chromium/WebExtension/GeckoView profile isolation, active PR ownership and renewal are certified.

This fixture has a GET `/smoke` diagnostic endpoint **only on the isolated local-test Wrangler entrypoint**. There is no corresponding URL/handler in actual `src/index.js` or `src/cloudflare-worker-entry.js`. Any attempt to reference this fixture from deploy/release workflow is a security-scope regression.

Minimum certification: exact-head full Command Center `ci`, including this local Workerd probe, negative fixture confinement review, and SHA-locked merge if good. No separate Cloudflare deployment or secret provisioning authorized. Next intent should wire properly human-confirmed challenge and ticket issuance, then separately authorized live PREPRODUCTION acceptances.
