# Admin catalog token validation — safe user-facing stages

Command Center receives only the existing private GitHub App repository catalog RPC. The current PREPRODUCTION error `GITHUB_CATALOG_TOKEN_PERMISSION_REJECTED` corresponds to an older relay's combined token validation error; it does not distinguish malformed bearer, invalid expiration or an unexpected grant.

BKE Worker PR #99 independently certified and merged three fixed broker error codes at Worker main `bebaf949851ad9d01938af7517ebddddbcb16d18`, relay certification `39170573143` SUCCESS:

| Exact private broker error | Admin-visible error |
| --- | --- |
| `ADMIN_CATALOG_TOKEN_BEARER_INVALID` | `GITHUB_CATALOG_TOKEN_BEARER_REJECTED` |
| `ADMIN_CATALOG_TOKEN_EXPIRY_INVALID` | `GITHUB_CATALOG_TOKEN_EXPIRY_REJECTED` |
| `ADMIN_CATALOG_TOKEN_GRANT_INVALID` | `GITHUB_CATALOG_TOKEN_GRANT_REJECTED` |
| Historic `ADMIN_CATALOG_TOKEN_SCOPE_INVALID` | Historic `GITHUB_CATALOG_TOKEN_PERMISSION_REJECTED` |

Only these predefined categories may surface to **verified, allowlisted human Admin users**, through the existing `/admin` and `/api/admin/discovery` routes. Unknown, unrecognized or secret-containing exceptions become `GITHUB_CATALOG_BROKER_UNAVAILABLE`. The Admin page receives no bearer, permissions object, TTL, issuer, email, installation ID, raw GitHub response or stack trace.

All failed token checks still stop **before** fetching repositories. Exact `metadata: "read"` sole granted permission remains mandatory in relay; a `GRANT_REJECTED` response is **not permission to broaden the GitHub App's installation or write privileges**.

## Minimum certification and rollout

1. Command Center full exact-head `ci`: `npm ci`, `npm test`, `npm run check`, `npm run cloudflare:dry-run`; independent privacy/security review, SHA-locked merge.
2. Deploy current verified **Worker relay PREPRODUCTION main** and **Command Center PREPRODUCTION main** to their existing services without secret, GitHub installation, or Cloudflare Access-policy mutations. Do not rerun the already-consumed one-time bootstrap script.
3. Human operator logs into `https://cc.jl-bke.com/admin` and shares only the fixed error code or confirms an App-approved repository inventory.

If `GITHUB_CATALOG_TOKEN_GRANT_REJECTED` persists, the next bounded investigation should review GitHub's *documented default metadata grant response* without logging, echoing or blindly accepting additional grants. If `GITHUB_CATALOG_TOKEN_EXPIRY_REJECTED` persists, investigate provider time/TTL behavior without weakening expiry checks. If `GITHUB_CATALOG_TOKEN_BEARER_REJECTED` persists, audit the modern opaque token contract without exposing bearer content. Production locked, Android parked.
