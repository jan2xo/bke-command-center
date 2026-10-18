# PREPRODUCTION Admin — broker catalog failure diagnostics

## What we know

The human owner reached `https://cc.jl-bke.com/admin` and the page rendered `Admin · GitHub source discovery`, then displayed `GITHUB_CATALOG_BROKER_UNAVAILABLE`. This **proves the configured Admin authorization path allowed the page**, but does **not** establish whether GitHub App token issuance, the Worker Service Binding RPC, or GitHub's repository catalog API worked.

Read-only Cloudflare API inspection verified:

- Command Center has `BKE_GITHUB_READ_BROKER` service binding to `bke-worker-relay-preproduction` named entrypoint `CommandCenterReadBroker`.
- Relay includes encrypted `BKE_ADMIN_BROKER_ENABLED`, `BKE_ADMIN_REPO_CATALOG_ENABLED` and GitHub App configuration bindings.
- Both Workers have deployed versions. Secret **values** and the broker RPC's actual outcome were **not inspected or claimed**.
- Existing Command Center implementation catches **every** catalog RPC error and replaces it with the same generic error, destroying the first causal failure signal.

## Bounded diagnostic contract

Only at the already-verified, human-allowlisted Admin discovery route, expose a fixed, non-sensitive `AdminDiscoveryError.code` mapped from an **exact whitelist** of known broker codes, including:

| Admin-visible code | Meaning |
| --- | --- |
| `GITHUB_CATALOG_DISABLED` | Relay rejected broker/catalog latch |
| `GITHUB_CATALOG_REQUEST_REJECTED` | RPC purpose not accepted |
| `GITHUB_CATALOG_APP_CONFIGURATION_UNAVAILABLE` | GitHub App server configuration unavailable |
| `GITHUB_CATALOG_INSTALLATION_UNAVAILABLE` | GitHub App installation lookup failed |
| `GITHUB_CATALOG_INSTALLATION_SCOPE_REJECTED` | Installation lacks required granted permission |
| `GITHUB_CATALOG_TOKEN_ISSUANCE_REJECTED` | GitHub refused short-lived token request |
| `GITHUB_CATALOG_TOKEN_PERMISSION_REJECTED` | Issued token failed strict metadata-only permission attestation |
| `GITHUB_CATALOG_PROVIDER_UNAVAILABLE` | GitHub repository listing could not be fetched |
| `GITHUB_CATALOG_PROVIDER_RESPONSE_INVALID` | Incomplete, malformed, duplicate or invalid GitHub response |
| `GITHUB_CATALOG_BROKER_UNAVAILABLE` | Unknown error, RPC unavailable, or error not on allowlist |

Cloudflare RPC errors normally reconstruct an Error with its message on the caller side; classification must never trust free-form message text. Only exact known codes (plus finite recognized HTTP status and permission triplets) can be mapped. **Never** expose remote exception text, JWTs, GitHub App tokens/IDs, secret values, private key, raw JSON, email, request headers, or stack traces.

No fallback to `GITHUB_TOKEN` or to user-provided repositories. No new HTTP token endpoint, no server login automation, no permission expansion. A missing binding remains generic and fail closed. The authorized route can show known error categories but **cannot display the secret values that caused them**.

## Certification and rollout

- Existing Command Center `npm ci`, `npm test`, `npm run check`, `npm run cloudflare:dry-run` exact-head `ci` graph and independent security audit.
- Source-only SHA-locked merge if green, then owner-controlled **Command Center PREPRODUCTION only** deployment of exact main; do **not** rerun one-time Admin activation or modify Cloudflare Worker relay/credentials yet.
- Human refreshes the Admin page and shares only the single fixed code. If the result is generic again, investigate RPC reachability and effective runtime with an independently scoped, non-secret probe before changing permissions.
- A valid repository catalog response should instead show only the repositories approved by the existing GitHub App installation. This is not automatic App installation expansion.

Production locked; Android PR #90 remains parked.
