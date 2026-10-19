# BKE Admin — safe repository-list redirect diagnosis

Owner's PREPRODUCTION human Admin reported `GITHUB_CATALOG_REPOSITORIES_TRANSPORT_UNAVAILABLE` after successful GitHub App mint and validation; the actual transport exception was hidden to protect credentials.

BKE Worker PR #103, SHA-locked merged `13ae553870f6915bd939d220a8745579164cc3f4`, adds `redirect:"manual"` ONLY at the `GET https://api.github.com/installation/repositories` call. It fails closed on any 3xx with private `ADMIN_CATALOG_REPOSITORIES_REDIRECT_BLOCKED` while refusing to follow/replay the short-lived installation token; all other GitHub App claims/permissions and catalog scoping are unchanged. **There is no evidence that GitHub actually redirected before this diagnostic is deployed and observed.**

This Command Center intent maps only exact `ADMIN_CATALOG_REPOSITORIES_REDIRECT_BLOCKED` to `GITHUB_CATALOG_REPOSITORIES_REDIRECT_BLOCKED` on the existing verified, allowlisted human Admin surface. Arbitrary error detail, location URL, bearer, JWT, grant and other secret-bearing/suffixed upstream exceptions remain generic.

Minimum complete proof: existing full CC CI `npm ci`, `npm test`, `npm run check`, `npm run cloudflare:dry-run`, independent security review and SHA-locked merge. Then targeted PREPRODUCTION Worker relay and Command Center exact-SHA version uploads/promotions with full bindings parity read-back. Human Access login remains manual.

If human Admin sees `...REDIRECT_BLOCKED`, stop and independently verify any legitimate redirect before allowing any same-origin handling; never auto-follow arbitrary Location with bearer. If `...TRANSPORT_UNAVAILABLE` persists, investigate Cloudflare transport/headers without weakening App grants. Production/Android/credentials locked.
