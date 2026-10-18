# PREPRODUCTION Admin — platform-verified Cloudflare Access context

## Intent

The protected Admin at `https://cc.jl-bke.com/admin` returned `VERIFICATION_KEY_UNAVAILABLE` while independently fetching `/cdn-cgi/access/certs` from the user's Mac returned HTTP 200 and two RSA public signing keys. That does **not** establish whether Worker-to-Access subrequests, key import, or key matching caused the failure.

Cloudflare's official [Worker Access documentation](https://developers.cloudflare.com/workers/configuration/cloudflare-access/) documents `ctx.access` for requests authenticated by Access **directly invoking the Worker**. The platform verifies Access identity before making the context available; `ctx.access.aud` is the Access application audience; `ctx.access.getIdentity()` returns authenticated user identity.

This PR changes **only Command Center Admin authorization** from per-request JWKS fetching to platform-verified `ctx.access`.

## Required security boundaries

- The original PREPRODUCTION-only flag, exact custom-domain hostname, `BKE_ACCESS_POLICY_VERIFIED` latch, Admin discovery enablement flag and encrypted issuer/AUD/allowlist configuration remain mandatory.
- Cloudflare supplies `ctx` as the third argument of the *direct* `fetch(request, env, ctx)` invocation. The application must never construct an Access context from `Cf-Access-Jwt-Assertion`, `Cf-Access-Authenticated-User-Email`, cookies, any other request header, a query string, or a service-binding RPC argument.
- Missing `ctx.access`, missing `getIdentity()`, audience mismatch, invalid/missing email, allowlist mismatch or identity lookup failure **DENY 403** before GitHub repository catalog/broker RPC.
- No fallback to the former remote JWKS verification path; it remains isolated solely for existing unit-test compatibility and does not authorize Admin routes.
- Browser-visible rejection buckets are coarse: `EDGE_ACCESS_CONTEXT_MISSING`, `VERIFIED_IDENTITY_UNAVAILABLE` or `ACCESS_IDENTITY_REJECTED`. No identity email, Access audience, JWT/key material or upstream error text is disclosed. `Cache-Control: no-store` remains.
- `ctx.access` **does not propagate across Service Binding HTTP or RPC calls**. Command Center verifies Admin identity first, and its existing narrowly scoped catalog broker RPC is unchanged and never receives the Access identity.
- No new Cloudflare Access policy, GitHub App installation, credential rotation, production release, Android wake, browser-profile access or ChatGPT authentication is part of this PR.

## PREPRODUCTION runtime acceptance

Source tests can establish handling of simulated platform contexts, but **do not prove that the live custom-domain routing path populates `ctx.access`**. Cloudflare documentation explicitly excludes some internal router/static-assets and RPC paths. The current deployment uses a directly invoked script with no Static Assets configured, but this must still be verified by the owner's human-authenticated browser smoke.

After exact-head CI ACCEPT and SHA-locked merge, deploy **Command Center PREPRODUCTION only**, using the exact merged main, with no secrets re-provisioned and no rerun of the one-time activation script. Human owner signs in at `/admin`:

- If the page shows the approved repository inventory: verify only the App-approved scope and capture human acceptance in GitHub Issue #30.
- If `EDGE_ACCESS_CONTEXT_MISSING`: stop. The platform did not populate its verified Access context on this invocation; do not synthesize context from headers or relax authorization. Investigate Cloudflare Worker Access route binding, Static Assets or HTTP router model.
- If `ACCESS_IDENTITY_REJECTED`: verify actual Access configuration using separately authorized Cloudflare Admin connector, without exposing email/AUD/JWT to PRs/chat; do not enlarge allowlist to bypass.
- If `VERIFIED_IDENTITY_UNAVAILABLE`: review official Cloudflare Access identity call availability without logging private user data.

No automatic admin acceptance claim is valid without this human browser proof. Production remains locked.
