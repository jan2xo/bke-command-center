# Command Center — protected PREPRODUCTION activation

**Target:** `cc.jl-bke.com` in the **existing** `jl-bke.com` Cloudflare zone.
**Cloudflare Worker:** `bke-command-center-preproduction` (named `preproduction` Wrangler environment).
**Authority:** [Command Center issue #5](https://github.com/jan2xo/bke-command-center/issues/5).
**Current state:** This is a deployment runbook, **not** evidence that access, DNS, credentials, or a live deployment exist.

## Security invariants

- Only `cc.jl-bke.com` routes to the dedicated PREPRODUCTION Worker. Keep `airstack.jl-bke.com` (Cloudflare Pages) and other `jl-bke.com` services untouched.
- PREPRODUCTION `workers_dev = false` and `preview_urls = false`; no alternate public hostname.
- Default `bke-command-center` Worker has no domain, no PREPRODUCTION marker, and must not be deployed.
- GitHub is canonical engineering truth; the dashboard is read-only GitHub-derived.
- Access must enforce operator identity **at the Cloudflare edge** before the Worker can serve engineering data.
- The new `BKE_ACCESS_POLICY_VERIFIED` marker is only a **secondary operator release latch**; it is NOT authentication or cryptographic proof of Access. Configure it as an encrypted secret **only after** independent Access verification.
- Any unknown access policy, hostname collision, missing credentials, or unauthenticated dashboard data means **STOP**. Never compensate by enabling public `workers.dev` or bypassing Access.

## Operator preflight — existing Cloudflare zone

1. Open [Cloudflare Dashboard](https://dash.cloudflare.com/) using human authentication. Check that **existing** zone `jl-bke.com` is active in the intended account. Do not create a second zone.
2. Under `jl-bke.com → DNS → Records`, confirm `cc.jl-bke.com` is not already allocated to another app or conflicting CNAME. If occupied, stop and reconcile before continuing. **Do not modify `airstack.jl-bke.com`.**
3. In Cloudflare Zero Trust, open **Access → Applications**, create a **Self-hosted** application named `BKE Command Center PREPRODUCTION`. Protect the single public hostname **`cc.jl-bke.com`**, all paths. Restrict the **Allow** policy to the specific human operator identity/identities approved to view engineering evidence. Avoid broad email domains, Everyone/Any-valid-user policies, and public Bypass policies.
4. Select a human-controlled login method. Do **not** automate OAuth, MFA, CAPTCHA, session establishment, or security challenges. Confirm the application and exact policy in Cloudflare UI. If supported, consider Worker-level Access protection to cover any unforeseen domain alias; confirm it applies **only** to this dedicated PREPRODUCTION Worker.
5. Record in issue #5 **non-sensitive** evidence only: Access application name/ID (if safe), exact protected hostname, allowed identity category (do not publish the address if unnecessary), policy review, and date. **No sessions, keys, tokens, screenshots of secrets, or Access cookies.**

## Deploy and prove the protection (after preflight)

1. Confirm this PR's **latest exact head** has passed `npm ci`, `npm test`, `npm run check`, and `npm run cloudflare:dry-run`. Require explicit security review of the hostname and Access setup before converting this staging PR from draft to mergeable and merging with an expected-head SHA.
2. Before deploying, review Cloudflare least-privilege token scopes and environment isolation through the human-controlled account. No prod account cutover, default Worker or broad-zone routes. Record the approved merge SHA and intended Worker name in issue #5.
3. Use only the repo-pinned commands:
   - `npm run cloudflare:dry-run` (checks named PREPRODUCTION build, **does not publish**).
   - `npm run cloudflare:deploy:preproduction` (**publishes** the named Worker and its exact custom domain; use only after the previous gates).
4. The fresh Worker will respond `503 / COMMAND_CENTER_ACCESS_NOT_VERIFIED` until the separate `BKE_ACCESS_POLICY_VERIFIED` encrypted PREPRODUCTION secret has been set. **Do not interpret 503 as Access protection:** Access should intercept unauthenticated requests before the Worker, regardless of this latch.
5. From an **unauthenticated** independent browser session, request `https://cc.jl-bke.com/api/overview` and `/pr/82`. Expected: Cloudflare Access blocks or redirects to sign-in **before** a dashboard response is served. If either route returns dashboard JSON/HTML (including while the latch is still locked), STOP, remove the route if necessary, and do not provision the release latch.
6. Confirm approved human sign-in succeeds **through Access**, while unapproved identities are denied. An approved user may still see the intentional Worker 503 while the latch is absent.
7. After the Access deny/allow checks have been evidenced, provision the PREPRODUCTION-only encrypted secrets in Cloudflare, for example interactively (never paste secret values in chat or PR):
   - `npx wrangler@4.148.0 secret put GITHUB_TOKEN --env preproduction` with a read-only GitHub credential scoped as narrowly as possible; if public GitHub reads suffice, evaluate whether a token is needed.
   - `npx wrangler@4.148.0 secret put BKE_ACCESS_POLICY_VERIFIED --env preproduction` whose exact value is `true`, only as a **manual release acknowledgment** after the edge policy passes.
   Wrangler `secret put` can update a Worker version; repeat access-deny verification after configuration changes.
8. Recheck an unauthenticated `/api/overview` still meets the Cloudflare Access denial; then confirm authenticated `/`, `/api/overview`, `/worker`, `/pr/82` and relevant bounded evidence routes show actual current GitHub state. PR #82 has **merged and passed** its latest certification; do not report its historic failed relay run as current exact-head state. Historical failure reproduction is separate, from immutable GitHub run evidence.
9. Confirm no routine page load fetches job logs; foreign/old job IDs receive 404, sensitive upstream messages do not leak, and no dashboard outage blocks GitHub operations.
10. Record non-secret Access denial and authorized access evidence, deployment/version/commit, checks, and rollback in issue #5. Only close the issue when B1–B3 and C1–C3 are truly satisfied.

## GitHub API rate-limit recovery (B1)

If protected `/pr/:id` or `/` reports `RATE_LIMIT` at a GitHub REST read boundary, the Cloudflare Worker may be exhausting GitHub's anonymous API quota. The Command Center code already supports `GITHUB_TOKEN` through an Authorization header, but the binding **does not exist until explicitly provisioned by a human operator**.

1. Human GitHub repo owner creates a **fine-grained, read-only, short-lived** PAT for **only `jan2xo/bke-worker`**. Grant Actions read, Checks read, Issues read and Pull requests read, with Metadata read implicitly. No write/admin access.
2. Human operator puts the value as a Cloudflare **encrypted Secret** `GITHUB_TOKEN` under **only `bke-command-center-preproduction`** (Workers & Pages → Worker → Settings → Variables and Secrets), not a Wrangler plaintext variable. Never share the token with ChatGPT or PR comments.
3. Secret updates can create a new deployment/version. Before promoting/releasing, verify the exact scoped Access policy, preserved `BKE_ACCESS_POLICY_VERIFIED` secret, disabled workers.dev/preview and correct `cc.jl-bke.com` domain. The operator remains responsible for any required GitHub authentication/MFA.
4. Open protected `/github-quota` manually. The page queries GitHub `/rate_limit` **on demand** and shows observed remaining/total primary REST quota plus `CONFIGURED`/ `ABSENT`. Configured is NOT evidence that the token has sufficient repo read permissions.
5. Read live `/pr/82`, `/worker`, `/`, and at least one exact-head CI evidence route. Do not cache certification verdicts or infer Linux Worker liveness from ownership labels. If Access or GitHub read fails, leave B1/C1/C3 open and fail closed.

## Rollback

If the hostname or policy is wrong, **disable/remove the Worker Custom Domain** for `cc.jl-bke.com` in Cloudflare and revoke release secrets if needed. Do not remove the shared `jl-bke.com` zone or alter `airstack.jl-bke.com`. Record the action in issue #5. Treat any suspected unauthenticated data exposure as a security incident requiring human operator review.

## Source references

- [Cloudflare Access for Workers](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)
- [Worker Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)
- [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/)
- [Worker Preview URLs](https://developers.cloudflare.com/workers/versions-and-deployments/preview-urls/)
