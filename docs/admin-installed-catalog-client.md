# GitHub App installed-repository catalog — Command Center client

## Purpose

A human Admin should not repeatedly enter repository URLs, App installation IDs or bearer tokens to see resources the **existing** GitHub App was already allowed to access. The catalog is a read-only projection of current GitHub installation grants; GitHub remains the engineering/source truth.

Dependency: BKE Worker PR #93 (source-only merged main `57cca09a005c3dc782ee64c18a7fea0cf1c140c2`) exposing the private `CommandCenterReadBroker.listApprovedGitHubRepositories` RPC. The source implementation is not a live deployed service.

## Execution boundaries

- The established `/admin` and `/api/admin/discovery` routes verify **signed Cloudflare Access JWT plus Admin allowlist** before the new discovery function is called.
- The new mode `GITHUB_DISCOVERY_AUTH_MODE=catalog` is explicit and **not configured in Wrangler**. `BKE_ADMIN_DISCOVERY_ENABLED` remains OFF by default.
- A PREPRODUCTION same-account Service Binding `BKE_GITHUB_READ_BROKER` points to the existing relay named entrypoint. The only RPC request is `{purpose:"admin_installation_repository_catalog"}`, without user-provided repository or installation identity.
- The relay internally obtains a metadata-only GitHub App installation token and fetches existing installation-approved repository metadata. No credential, GitHub App private key, browser secret, or token is ever transferred to Command Center or the Admin browser.
- Command Center **independently validates** RPC authority/scope, bounded integer counts (0–500), repository IDs/names/default branch/privacy flags, duplicates and canonical URL equality; it returns a **new sanitized projection** rather than returning untrusted RPC data directly.
- If the private broker is absent, unavailable, returns malformed metadata, or has not been enabled, **FAIL CLOSED**. Even when `GITHUB_TOKEN` is present, catalog mode does NOT fall back to PAT.
- This mode does **not** install the App into other repositories, widen installation permissions, fetch media/product contents or provision new workers.

## Evidence and rollout

Source-only certification plan: exact-head Node tests including `tests/admin-catalog-client.test.js`, `npm run check`, `npm run cloudflare:dry-run`, security review, SHA-locked merge. No Cloudflare deployment or runtime flag activation is included.

Later **independent and owner-authorized** PREPRODUCTION activation must verify Cloudflare Access protection, both BKE Worker relay feature flags, the effective named service binding and installation permissions, and an actual human-Admin session with allowed/denied behavior. If installation has only the control repo, that is all the catalog may report; Render Dock and other repos require an explicit owner-approved App installation-scope change.

Production locked. Android PR #90 remains parked; worker enrollment and credential key lifecycle are separate engineering intents.
