# PREPRODUCTION Admin — fixed private broker runtime-stage diagnostics

Human-authenticated `https://cc.jl-bke.com/admin` returned `GITHUB_CATALOG_BROKER_UNAVAILABLE` (2026-10-19 06:58 PHT) after Worker PR #101. The generic response **does not prove** service binding loss or Github API failure. Cloudflare Metrics reports error counts but the connected Observability API reported no ingested matching log events and zero detected Issues for that interval.

Worker PR #102, exact-head certified `5a090cbbe83030b856eb3afaf60cd0e8cec7c062`, PR Guard `39175221842` SUCCESS, `/certify relay` `39175241176` SUCCESS, SHA-locked merged Worker main `932c7c60fca151bc42a645e107827fb128cf451a`, introduced four fixed, redacted stage codes for runtime errors not previously classifiable.

Command Center exposes **only** these exact strings to an already Cloudflare-Access-authenticated and explicitly allowlisted Admin:

| Fixed private relay code | Safe displayed code |
|---|---|
| `ADMIN_CATALOG_APP_SIGNING_UNAVAILABLE` | `GITHUB_CATALOG_APP_SIGNING_UNAVAILABLE` |
| `ADMIN_CATALOG_INSTALLATION_LOOKUP_UNAVAILABLE` | `GITHUB_CATALOG_INSTALLATION_RUNTIME_UNAVAILABLE` |
| `ADMIN_CATALOG_TOKEN_TRANSPORT_UNAVAILABLE` | `GITHUB_CATALOG_TOKEN_TRANSPORT_UNAVAILABLE` |
| `ADMIN_CATALOG_REPOSITORIES_TRANSPORT_UNAVAILABLE` | `GITHUB_CATALOG_REPOSITORIES_TRANSPORT_UNAVAILABLE` |

Current known issuer/permission/grant/expiry/repository codes remain mapped as before. All unknown, forged, suffixed, multiline, secret-bearing or unexpectedly serialized exceptions still produce `GITHUB_CATALOG_BROKER_UNAVAILABLE`; never expose raw provider exception text, bearer, audience, JWT, key material, installation ID, permission object, headers or credentials.

No change to the private RPC or `ctx.access` allowlisted Admin verification; no PAT fallback or public bearer token API. No App permission expansion and no change to relay metadata-only mint or catalog selection.

Certification is the existing Command Center exact-head `ci` (npm ci, test, check, Cloudflare dry-run), independent security review, SHA-locked squash merge. After BOTH Worker and Command Center current-main source versions reach PREPRODUCTION, the human Admin refreshes /admin and shares only the fixed code. If generic still persists, diagnose Cloudflare RPC transport/serialization and request liveness via separately certified private capability witness; do not guess token scopes again. No production, Android wake, secrets or human login automation.
