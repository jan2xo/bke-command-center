# PREPRODUCTION Admin denial diagnosis (security boundary)

The Admin is already **deployed and enabled**, with `BKE_GITHUB_READ_BROKER` service binding present and the Access app configured. A human opening `https://cc.jl-bke.com/admin` received `{"error":"ADMIN_ACCESS_DENIED"}`.

That error arises **inside the Admin JWT verifier before the GitHub catalog RPC runs**. It does not identify why the signed token could not be verified. Neither worker deployment nor secret/bootstrap reruns are safe or useful for this failure; the activation script deliberately rejects partial/repeated setups.

This intent adds **coarse, non-sensitive denial stages** to the existing error response. No new URL, no authentication fallback, no App permissions, no increase in privilege:

| User-visible `auth_stage` | Interpretation |
| --- | --- |
| `EDGE_JWT_MISSING` | No `Cf-Access-Jwt-Assertion` header reached the Worker. Revisit official Cloudflare Access app login and edge-to-Worker protection. |
| `VERIFICATION_KEY_UNAVAILABLE` | Worker couldn't retrieve or parse accepted Access JWKS signing-key material. Check trusted team public certificates and key rotation. Never accept an unsigned request. |
| `JWT_REJECTED` | Bad JWT format, signature, issuer, audience, lifetime or operator allowlist; intentionally indistinguishable to the client to prevent identity guessing. |

The internal `inspectAdminAccess` contract distinguishes more stages for unit tests (missing, bad format, claims, key fetch, key selection, signature). **Do not log or return token text, headers, decoded payloads, email values, issuer, AUD, key IDs, private keys or exception text.**

Admin routes continue to require `BKE_PREPRODUCTION=true`, `BKE_ACCESS_POLICY_VERIFIED=true`, exact hostname, `BKE_ADMIN_DISCOVERY_ENABLED=true` and independent signed Access JWT verification. On failure, a 403 with `Cache-Control: no-store` is returned. Public error stages do not prove authorization; all failures remain fail-closed. Source tests cover human positive JWT and numerous negative stages.

## Deployment/acceptance gate

A source merge alone doesn't update the Cloudflare Worker. **Do not rerun** `activate-admin-preproduction.sh` after activation: its no-partial-state check should stop it. A separately authorized deployment of the Command Center Worker only (no secret writes or Access policy edits) is required if these diagnostics are needed on the live PREPRODUCTION page.

After the new version is deployed, the human Admin opens `/admin` again and shares only the short `auth_stage` value—not JWT/cookies/headers. This is an intermediate diagnosis, not a claim of successful Admin acceptance. Cloudflare Access login/MFA remains human-only; production remains locked.
