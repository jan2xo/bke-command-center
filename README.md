# BKE Command Center V1

A lightweight, read-first Cloudflare Worker for **PREPRODUCTION** observability. GitHub remains the engineering authority; Command Center derives state and does not create a second task database.

## Local development and certification

1. Run `npm ci`.
2. Set a read-only GitHub credential in local environment `GITHUB_TOKEN` only when needed for private access or higher API limits. Never commit environment files.
3. Run `npm test`, `npm run check`, and `npm run cloudflare:dry-run`.
4. Run `npm run dev`.

Wrangler is pinned to `4.148.0`. The dry-run explicitly builds the **named `preproduction` environment** and does not deploy it.

## Routes

- `/` GitHub-derived engineering overview: open PRs, assignment conflicts, explicitly scoped recent merges and drill-down links (worker process liveness is **UNKNOWN**)
- `/api/overview` bounded read-only snapshot of open PRs and latest 12 closed PRs, with explicit collection scope
- `/worker` worker assignment/ownership-derived view (not independent process liveness)
- `/pr/:number` human-readable PR detail
- `/api/worker` normalized GitHub-derived worker ownership state
- `/api/pr/:number` exact-head PR state, required-certification status, causal failure capsule, downstream effects, and post-run summary
- `/api/pr/:number/evidence/job/:job_id` bounded failure excerpt for a job already proven to be failure evidence for that PR's current exact-head certification attempt

## Dashboard data integrity

The home view reads GitHub only; it stores nothing and never writes, dispatches, certifies, or merges. Open PRs are read with a bounded first page of 100; a completely filled page fails closed rather than presenting potentially incomplete ownership as authoritative. Recent merges are a **sample of the 12 most recently closed PRs**, not a total or complete archive. Ambiguous labels, invalid worker IDs, and one worker assigned across multiple open PRs are shown as ownership conflicts, not as healthy/online state.

The dashboard never equates a PR label with live worker process status; liveness stays UNKNOWN until an independently certified runtime/heartbeat integration exists. Routine overview loads do not fetch individual PR certification runs, check jobs, or logs. PR details are fetched on demand through the existing exact-head evidence routes. Dashboard and API responses are `Cache-Control: no-store`, and unexpected upstream failures return a generic UNKNOWN/502 rather than exposing GitHub error bodies.

This is **code/UI readiness**, not Cloudflare deployment. Protected PREPRODUCTION ingress, operator-managed encrypted credentials, deployment and live validation remain tracked in [issue #5](https://github.com/jan2xo/bke-command-center/issues/5).

## Exact-head certification correlation

BKE Worker's `Intent Certification` is triggered by `/certify` issue comments. GitHub reports those runs with the default-branch `head_sha`, not the PR source SHA. Command Center therefore does **not** treat the workflow-run `head_sha` as PR proof.

For the current BKE Worker contract it correlates the latest `/certify` command for the current PR head using durable PR history (exact-head relay/checkpoint evidence, with PR commit history as a bounded fallback), then matches the corresponding `issue_comment` workflow run by PR title, actor, and bounded event time. Only that latest correlated run fans out to jobs.

Generic successful checks such as PR Guard are shown as observed evidence but cannot make required certification PASS. The `Required certification` job is the decisive gate. If required proof is absent, state is `UNKNOWN`; an in-progress correlated certification run is `PENDING`.

## Failure evidence

The first failed step in the latest correlated certification attempt is surfaced as the actionable root. `Required certification` is classified as downstream when a more specific job failed first. Successful module jobs may be shown as positive/unaffected boundaries; skipped jobs are not positive proof.

Raw logs remain at GitHub. Command Center never mirrors them. A failure excerpt is fetched only on demand for a job already correlated to the PR's exact-head failure state, follows GitHub's short-lived log redirect without forwarding the GitHub Authorization header, reads at most 256 KiB, redacts common credential patterns, and returns only a compact failure excerpt.

## PREPRODUCTION deployment — operator-only, not yet completed

Issue [#5](https://github.com/jan2xo/bke-command-center/issues/5) tracks **actual** protected deployment and live verification. A passing dry-run is not proof of deployment.

### Why the default Worker is locked

- `wrangler.toml` defines a separate `[env.preproduction]` target. Wrangler resolves its script name to `bke-command-center-preproduction`, distinct from the top-level `bke-command-center` Worker.
- Only `[env.preproduction.vars]` contains `BKE_PREPRODUCTION = "true"`. The deployed entrypoint returns `503 LOCKED` without that exact value. The bare/default Worker is therefore not a supported deployment target.
- `workers_dev = false` on PREPRODUCTION prevents accidental public exposure through a workers.dev hostname; no route/custom domain is committed.
- All repo-provided Wrangler scripts include an explicit `--env preproduction`. The CI workflow runs only `cloudflare:dry-run`.
- This is a **deployment isolation guard, not an authentication system**. A protected route (for example Cloudflare Access or equivalently enforced private ingress) must be configured before serving real GitHub engineering data or log excerpts.

### Operator preflight

1. Confirm a dedicated PREPRODUCTION Cloudflare Worker and **protected ingress** design; no production routes, custom domains, or browser/security secrets may be reused. If the protected route cannot be confirmed, stop without making the service public.
2. Review the exact certified GitHub PR head, required CI, and the target Worker name. Do not deploy from an uncertified branch.
3. Human operator provisions a least-privilege GitHub read credential **in the Cloudflare PREPRODUCTION encrypted secret store** under `GITHUB_TOKEN`. The secret is environment-specific, never in `[vars]`, repository, chat, PR comments, or logs.
4. Human operator provisions Cloudflare deploy permissions through the appropriate secure credential mechanism. Do not automate Cloudflare login, OAuth, MFA, or security challenges.
5. Run `npm run cloudflare:dry-run` to inspect the target and bundle. The only repository-provided publish command is `npm run cloudflare:deploy:preproduction`, which uses explicit `--env preproduction`. Execute it **only after** access review and authorized approval. It is not run by CI.
6. Attach and verify a protected PREPRODUCTION route before sending users to the service. With `workers_dev = false`, a missing route means the deployment is deliberately not publicly reachable.

Cloudflare secrets are not inherited across named environments. If using Wrangler's `secret put` path, verify the intended `--env preproduction` target and ingress policy first; secret updates can affect live Worker versions. Never print a secret value.

### Live acceptance after a protected release

The operator must record the authenticated PREPRODUCTION host, immutable deployed version/commit, and evidence references in issue #5 **without publishing credentials or private URLs**. Against that protected host:

1. `GET /worker` and `GET /api/worker`: derive ownership from live BKE Worker open PR labels. For the known parked PR #82, no `bke-worker:android-worker-a` label means that PR is **UNASSIGNED**; do not infer worker process liveness from lack of assignment.
2. `GET /pr/82` and `GET /api/pr/82`: compare the displayed source `exact_head` against the then-current `jan2xo/bke-worker` PR #82 head (never hard-code an old handoff SHA). Required certification must stay separate from generic green PR checks.
3. Confirm the latest relevant exact-head certification shows Cloudflare relay test failure as **CAUSAL**, `Required certification` failure as **DOWNSTREAM**, and Core/Android passed as positive observed boundaries. If the PR was subsequently remediated, inspect its corresponding historical failing head rather than misrepresenting current state.
4. Exercise a currently correlated failed GitHub job through `/api/pr/82/evidence/job/:job_id`; check excerpt is bounded and redacted. A foreign/old/unrelated job ID must receive `404`.
5. Verify routine state reads do not download all raw logs, secret material never appears in response, and failure/unavailability of this dashboard does not interfere with GitHub or BKE Worker execution.
6. Report only demonstrated live results. If authentication, permissions, a protected route, or Cloudflare access are unavailable, record `BLOCKED` in issue #5 and **do not claim deployment or operational acceptance**.

No production deployment or credential cutover is authorized by this repository or by the dry-run.
