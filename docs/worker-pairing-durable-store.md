# Installation-scoped pairing Durable Object: source-only storage gate

**Status:** staged source contract and PREPRODUCTION-only Wrangler config. NOT deployed or activated. Related to [Command Center Issue #30](https://github.com/jan2xo/bke-command-center/issues/30), merged pairing ceremony PR #40, merged preflight PR #39.

This wave resolves one necessary dependency: `store.atomic(fn)` must be a **single Cloudflare Durable Object** transaction covering the *entire GitHub App installation*, not process memory, KV, D1 with independent request races, or one DO per worker.

## Implementation

- `src/worker-pairing-durable-store.js` provides `createPairingAtomicStore(ctx.storage)`. Uses the official Durable Object `storage.transaction(async txn => ...)` API, within the DO instance, with `paired` and `pending` in the **same atomic commit/rollback**. Keys and array-size budget are fixed. Exceptions return only a constant code through the existing pairing ceremony.
- `BkeWorkerPairingVault` is exported from the Worker entry module for Cloudflare class linking. It is **dormant**, exposes no pairing RPC, and every `fetch` returns 404 without exposing storage data.
- `wrangler.toml` adds PREPRODUCTION-only SQLite-backed Durable Object migration and binding in source. Default/production configuration does not include the new binding. These provisions only take effect if a separately authorized PREPRODUCTION upload/deployment applies them.
- Tests exercise transactional rollback on second-write exception, two independent adapters sharing one storage instance, two isolated cryptographically signed worker registrations, competing duplicate proofs, revocation, unauthorized key access, no public RPC or route, and bounded snapshots. The memory simulator only models serialization and rollback; the GitHub CI Cloudflare dry-run checks packaging, not a real live SQLite DO deployment.

## Boundary (must not be inferred as already operational)

A future authorized Cloudflare caller must resolve the **actual GitHub App installation ID** by its trusted server-side broker, and route *every worker in that installation* to exactly one stable DO object with deterministic name `installation:<trusted_installation_id>`. Never permit a device-supplied installation name, per-worker DO routing, or caller-created `verified` booleans. Cloudflare's own DO namespace provides atomic coordination, not GitHub engineering task authority.

The actual device ceremony must execute **inside** the Durable Object (functions cannot be serialized across a DO RPC), and a narrowly scoped trusted caller must supply preverified Admin action authorization plus a *complete* fresh cross-repository GitHub PR ownership snapshot. That verified snapshot cannot be minted by a browser, generic client header, or metadata-only GitHub App catalog token. Current 76-repository catalog does NOT provide repository-content/PR authorization, nor does it prove an active worker.

No Admin enrollment HTTP actions, no installation-enrollment credential, no user/device pairing, no active lease or renewal, no WebExtension/GeckoView bridge, no Cloudflare secret writes or production deployment. `PAIRED_INACTIVE` remains exactly that.

## Next gate

In a separate fresh-main PR, implement a **server-only, authenticated** command path from verified platform Cloudflare Access + per-action authorization to a single installation DO; acquire a complete, bounded GitHub PR inventory from authorized minimum read grants; handle CSRF/replay and admin/device origin separation; integrate the PR #40 ceremony with the DO *inside* the transaction boundary; add a real SQLite DO integration test and negative auth/tenant/race tests. Only after exact-head certification and explicit PREPRODUCTION Cloudflare binding/route/secret authorization may the owner undertake human-authenticated pairing acceptance.

Production, Android parked PR #90, all existing credentials and worker wake dispatch stay locked.
