# Admin V0 — automatic GitHub discovery (PREPRODUCTION, disabled by default)

## User mission

The operator must NOT repeatedly copy repository links, installation IDs, service URLs, provider secrets, or source lists for each worker. A **human Admin** should authorize each provider once, after which backend provider adapters discover accessible resources and retrieve secrets or short-lived credentials inside trusted server boundaries.

This PR is the first independent implementation intent: **verified Admin identity + on-demand, read-only GitHub repository discovery**. It is NOT complete secret lifecycle automation, production deployment, or multi-worker readiness.

## Trust separation

- **GitHub** remains source / engineering / PR / certification / merge truth. No separate BKE task database.
- **Command Center** is a read-only projection and Admin UI. It MUST NOT create tasks or assign workers.
- **Cloudflare Access** authenticates the Admin's browser. Backend validates the signed Access JWT independently (RS256, exact issuer, application AUD, expiry, human `sub` and allowlisted email).
- **Command Center encrypted backend binding** `GITHUB_TOKEN` is reused *server-side only* for V0. The JWT, token or provider errors never appear in HTML or API responses.
- **Future credential broker** (fresh PR) should use the existing BKE Worker GitHub App pattern to mint bounded installation tokens and rotate/renew without distributing long-lived keys to worker instances. NEVER share the GitHub App private key through Actions, browsers, ChatGPT conversations, or workers.
- **Worker sessions** maintain unique identities and exclusive GitHub PR ownership. Admin authentication does not authorize bypassing ownership, human ChatGPT login, or a production lock.

## Routes

Existing PREPRODUCTION hostname / Access / environment latches remain unchanged.

- `GET /admin`: compact HTML list of server-discovered authorized GitHub repositories; token lifecycle explicitly marked **NOT YET AUTOMATED**.
- `GET /api/admin/discovery`: JSON for a verified Admin with safe repository ID, full name, default branch, visibility, canonical GitHub link, and no credentials or personal browser data.
- `POST` or other methods on these routes return **405**. These routes do not mutate any GitHub or Cloudflare state.

**OFF by default.** Without the explicit feature latch and complete signed-identity verification, the routes return 404/403 and make no GitHub discovery requests. Do not enable on the running deployment without exact-head review/certification and explicit PREPRODUCTION deployment authority.

### Required server-side settings for a later, separately authorized enablement

- `BKE_ADMIN_DISCOVERY_ENABLED=true` (default absent/OFF)
- `BKE_ADMIN_ACCESS_ISSUER=https://<approved-team>.cloudflareaccess.com`
- `BKE_ADMIN_ACCESS_AUD=<exact Access application audience>`
- `BKE_ADMIN_EMAILS=<human-admin-email[,second-admin-email]>` (identity allowlist, not a replacement for Access policies)
- Existing encrypted `GITHUB_TOKEN` reused in initial *user credential* mode; only repositories visible to that principal are enumerated.
- `GITHUB_DISCOVERY_PRINCIPAL=user` or `installation` (optional; defaults to `user`). The future GitHub App broker must supply a properly scoped installation token to use `installation` mode.

Never configure privileged settings or raw secrets in `wrangler.toml`, GitHub source, PR text, build artifacts, client storage, or chats. Do not treat a configured token as proof that it has correct permissions, a healthy quota, or automatic renewal.

## GitHub discovery contract

- Server makes **read-only** bounded GitHub REST requests. User principal: `GET /user/repos`; installation principal: `GET /installation/repositories`.
- Up to 5 pages × 100 repositories are enumerated; no silent truncation. A sixth page returns an explicit error.
- Repository response schema is validated and canonical GitHub links constructed from validated owner/name, rather than copied from an upstream arbitrary HTML URL.
- Any unavailable credential, rejected token, malformed response, over-limit page, missing admin JWT or unknown principal fails closed. Do not report an incomplete list as authoritative.
- Client gets `credential=SERVER_CONFIGURED|MISSING`, `token_lifecycle=EXTERNAL_OR_MANUAL`, `auto_rotation=false`, `scope_verified=false`, and `worker_liveness=UNKNOWN`—never token value, secret path, or copied error details.

## Operator experience target (future independent intents)

1. Admin signs in through the existing Cloudflare Access flow and explicitly authorizes the GitHub App installation and its repository scope. Provider login/MFA/challenges remain human-controlled.
2. Backend discovers accessible repos + approved product source files automatically, including Render Dock, without requiring user-supplied GitHub URLs.
3. Credential broker manages narrow short-lived tokens and renewal, provider API key rotation when genuinely supported, revocation, encrypted persistence and audited admin consent. Any irreversible owner-only or permission-escalating change asks the Admin.
4. Each worker pairs through a unique authenticated identity and receives only scoped, expiring access, never a reusable admin token. PR ownership remains in GitHub.
5. One admin can oversee multiple independent workers without repeating per-worker secret setup. Parallelism requires its own certification and no shared writable browser profile.

## Certification deferred by operator

The V0 Admin discovery implementation merged in PR #29 as **disabled-by-default code only**. No production action, PREPRODUCTION Admin activation, or credential migration was part of that merge. The next bounded integration is described in [admin-broker-integration.md](admin-broker-integration.md), which remains separate from live deployment and human Access smoke.

When authorized later: use exact-head `npm ci`, `npm run check`, `npm test`, `npm run cloudflare:dry-run`, independent auth/SSRF/tenant-isolation review, and PREPRODUCTION human-Access smoke with and without valid signed JWT before enabling any live Admin route. The normal Command Center CI mode may run automatically on draft PR creation; that is not a substitute for the explicit merge/deployment gate.
