# Protected inactive pairing: one atomic human + device proof commit

**Status: SOURCE-ONLY and default-OFF.** Parent [Command Center Issue #30](https://github.com/jan2xo/bke-command-center/issues/30). Builds on merged PRs #39–#45 and BKE Worker #104. This module has **no HTTP route, no named Durable Object RPC, no Cloudflare activation, and no live enrolled device**.

The earlier demonstration components use separate transactions: a human `admin_actions` ticket can be consumed before device-key proof is registered, or a valid signed device challenge can be finalized without consuming a human ticket. **Neither path is sufficient as the future protected enrollment operation.** The new internal `createProtectedInactivePairing` finalizer instead checks BOTH proofs and writes all three state keys in **one single installation-scoped serializable DO storage transaction**.

## Trust and proof contract

All inputs originate from trusted server components; client-controlled booleans, GitHub snapshots, installation IDs and plugin-provided callbacks are never authority. The future server-only integration MUST provide a Cloudflare platform-verified human Admin Access context (exact application AUD, allowlist, action-specific consent), a server-derived fixed installation ID, `authorizeHumanSubject("pair", worker, ctx)` returning a **keyed/opaque** 256-bit Admin fingerprint from validated human identity, and a complete authorized private GitHub App inventory reader. The action fingerprint must be the same deterministic keyed value used when issuing the 90-second human ticket. A raw, unsalted email SHA-256 is **not** acceptable.

The finalizer requires all PREPRODUCTION, Access, Admin-PR-inventory, pairing-actions and separate `BKE_ADMIN_PROTECTED_PAIRING_ENABLED` feature locks; this new flag is deliberately **not in Wrangler**. It checks verified human Access BEFORE any GitHub broker reads. The default GitHub reader is the source-certified private Command Center Admin reader; a trusted internal installer must inject the correct installation-scoped DO adapter and subject callback, never a browser-supplied object. It validates a bounded, unique candidate worker/GitHub claim view, never treats `NON_ATOMIC_ENUMERATION` as a lease, and refuses observed candidate assignments, duplicates or changed installation identity.

The single storage transaction reads `paired`, `pending` and `admin_actions`. It refuses malformed, ambiguous or duplicate registries; a missing/replayed/expired/mismatched human ticket; a missing/replayed/expired device challenge; a malformed signed message; incorrect installation/action/worker/public-key thumbprint/nonce/resource/expiry binding; and invalid ECDSA P-256 SHA-256 proof. It runs the existing resource collision/PR preflight policy on the current trusted registry. Only after all checks pass does it write:
1. a `PAIRED_INACTIVE` identity record with one-hour enrollment validity, **no executable lease**;
2. removal of the exact pending device challenge;
3. a consumed one-time human-action ticket tombstone.

The adapter uses **one `ctx.storage.transaction`** for the three writes; any failed write rolls them ALL back. A repeated or racing request cannot register or consume twice. Fixed error codes redact upstream secrets and identities; output contains neither original device signature nor human nonce.

## Critical limits / remaining protected runtime gate

A signed device and human ticket are NOT, by themselves, proof that the device owns a unique runnable ChatGPT target, bridge or browser profile; their hashes remain registry hints. An **inactive pairing is not a device grant, bearer, worker wake, GitHub PR claim, activation or credential renewal**.

The GitHub App's full PR inventory is **NON_ATOMIC_ENUMERATION**. Even a fresh read immediately before the storage transaction is NOT a cross-repo lock or a guarantee labels do not change milliseconds later. Thus source merging this finalizer does not certify assignment exclusivity under an active lease or dispatch. A future separate security intent must require exact-head GitHub claim/assignment validation at the protected delivery point, operational lease/renewal/revocation enforcement, authenticated device transport, and fail-closed recovery for uncertain provider or device responses. It must prove the worker target/profile isolation and bound real Cloudflare SQLite Durable Object persistence under actual human-authenticated PREPRODUCTION conditions.

The new finalizer does not call the earlier `inspectDecisionTimePairingPreflight` when completing the protected operation, because that old function intentionally **burns the one-use human ticket in a separate transaction** and returns only `CHECKED_NOT_RESERVED`. Mixing them would recreate a split-transaction vulnerability. The old preflight remains an independent non-authorizing diagnostic.

**Evidence:** full exact-head Command Center `ci` and security review, including real generated Web Crypto device signatures and original admin-ticket creation; atomic race, replay, rollback, denial, ownership changes, and isolation cases. No GitHub App grant changes, secrets, Cloudflare deployment, production, Android PR #90 wake or automated human authentication.
