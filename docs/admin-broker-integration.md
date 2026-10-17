# Admin — expiring GitHub App token discovery client

**Status:** PREPRODUCTION source implementation. **No Cloudflare deployment, new app install, secret change, token cutover, live Admin access or production action authorized.** Parent: [issue #30](https://github.com/jan2xo/bke-command-center/issues/30). Depends on BKE Worker private broker [PR #92](https://github.com/jan2xo/bke-worker/pull/92) reaching certified/merged/released state before any activation.

## Design

Command Center's `/admin` and `/api/admin/discovery` still require all the existing PREPRODUCTION latches and a **cryptographically verified Cloudflare Access human Admin JWT**. The user/browser supplies no repository URL, App installation ID or token.

In the new *explicit* mode `GITHUB_DISCOVERY_AUTH_MODE=broker`:

1. Once signed human Admin access is checked, Command Center invokes the private **same-account Cloudflare Service binding**, not an HTTP URL:
   `BKE_GITHUB_READ_BROKER.mintReadOnlyGitHubToken({ purpose: "admin_source_discovery", repository: "jan2xo/bke-worker" })`.
2. GitHub App private key stays in BKE Worker's trusted Cloudflare relay secret boundary. Its named `CommandCenterReadBroker` RPC entrypoint is not a public HTTP route and is OFF unless independently enabled on the broker.
3. The returned `ghs_` token, GitHub installation identity, exact repository and strictly read-only `contents/issues/pull_requests` permissions, and 2–61 minute remaining TTL are checked **before** any GitHub request.
4. Command Center reads `GET /installation/repositories` with that expiring token in memory, then discards it. Each independent Admin request obtains its own token. It is never cached, logged, sent to browser, passed to ChatGPT or written to GitHub PRs.
5. UI/API only show metadata and `ON_DEMAND_SHORT_LIVED` credential lifecycle, never token or expiry-bearing credential values.

If the bound service is absent, disabled, rejects authorization, returns a malformed token, times out or returns an elevated permission, **FAIL CLOSED**. Even if a powerful legacy `GITHUB_TOKEN` is configured, broker mode **never falls back to it**.

The previous `GITHUB_TOKEN`-based `legacy_pat` mode is retained **only for compatibility**, never secretly selected by the broker. No production cutover takes place in this PR; enabling `GITHUB_DISCOVERY_AUTH_MODE=broker` must be an explicitly reviewed PREPRODUCTION operator action.

## Binding target

The checked-in *PREPRODUCTION-only* service binding is:

```toml
[[env.preproduction.services]]
binding = "BKE_GITHUB_READ_BROKER"
service = "bke-worker-relay-preproduction"
entrypoint = "CommandCenterReadBroker"
```

Both Workers must belong to the same Cloudflare account and the named entrypoint must actually be deployed before enabling. This private Cloudflare binding is an account-level capability, **not** an independent authentication mechanism. Authenticated Admin calls must be verified by Command Center before invoking the bound RPC; operators with deployment privileges in the same account remain a privileged trust boundary.

No new HTTP token endpoint, no OAuth automation, no browser-profile secrets, no static shared Admin password. Only `jan2xo/bke-worker` can be exposed by the first broker iteration. Expanding App installation scope to Render Dock and other repos requires a separate permission/audience/repository-scope gate with Admin consent; don't silently treat a one-repo broker as an all-repo solution.

## Certification / rollout

Minimum source proof: Command Center `npm ci`, `npm test`, `npm run check`, `npm run cloudflare:dry-run`; broker-client negative tests and independent cross-repo trust/secret-exfiltration audit.

**No deployment just because source tests pass.** Deployment needs explicit PREPRODUCTION authorization after Worker PR #92 and relay version are verified; verify Access protected domain, both Workers' effective bindings and flags, valid human Admin JWT, read-only exact GitHub App token permission/expiry and no browser response token. Revoke on compromise via GitHub App Admin; rotating the **long-lived App private key** still requires separate approved secure admin procedure. Production locked.

Worker enrollment and multiple independent worker identities remain separate security-critical intents. GitHub PR labels and the `one worker -> one active PR` invariant are unchanged.
