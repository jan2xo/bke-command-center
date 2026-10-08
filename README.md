# BKE Command Center V1

A lightweight, read-first Cloudflare Worker for **PREPRODUCTION** observability. GitHub remains the engineering authority; Command Center derives state and does not create a second task database.

## Engineering modes (Command Center experiment only)

This repository supports **NORMAL** (existing automatic PR/main CI) and **NITRO** (skip automatic PR/push CI on each Nitro commit and intentionally run a manual **pre-merge** exact-head gate). NITRO requires `nitro/*` PR branch, `bke-ci:nitro` PR label, explicit `**Engineering mode:** \`NITRO\`` ledger field, and `[skip ci]` in **every** Nitro commit message. These are operator-enforced GitHub conventions; a missing skip annotation can trigger unwanted automatic CI. The `workflow_dispatch` `ci` gate must be manually run on the exact Nitro PR branch with the exact PR number and SHA **only once the work is fully wired**. Never merge without certified exact-head proof. No PR Guard is added.

Read the [full mode contract, merge-gate instructions, branch-protection caveats, and failure procedure](docs/ENGINEERING-MODES.md). No changes to other BKE repositories, Cloudflare production, access controls, or deploys.

## Local development and certification

1. Run `npm ci`.
2. Set a read-only GitHub credential in local environment `GITHUB_TOKEN` only when needed for private access or higher API limits. Never commit environment files.
3. Run `npm test`, `npm run check`, and `npm run cloudflare:dry-run`.
4. Run `npm run dev`.

Wrangler is pinned to `4.148.0`. The dry-run explicitly builds the **named `preproduction` environment** and does not deploy it.

## Routes

- `/` GitHub-derived engineering overview: open PRs, assignment conflicts, explicitly scoped recent merges and drill-down links (worker process liveness is **UNKNOWN**)
- `/api/overview` bounded read-only snapshot of open PRs and latest 12 closed PRs, with explicit collection scope; also includes an independently degradable GitHub Actions failure-visibility snapshot (latest **30** workflow runs)
- `/worker` worker assignment/ownership-derived view (not independent process liveness)
- `/pr/:number` human-readable PR detail
- `/api/worker` normalized GitHub-derived worker ownership state
- `/api/pr/:number` exact-head PR state, required-certification status, causal failure capsule, downstream effects, and post-run summary
- `/api/pr/:number/evidence/job/:job_id` bounded failure excerpt for a job already proven to be failure evidence for that PR's current exact-head certification attempt

## Failure visibility (first Nitro pilot)

**Separate observation sources:** recent GitHub Actions runs (bounded to 30) and the official unauthenticated [Cloudflare global status API](https://www.cloudflarestatus.com/api) (`/api/v2/status.json`, bounded 2.5-second request). The public Cloudflare status is **platform-wide**, not the health of `bke-command-center-preproduction`, the linked Cloudflare account, or BKE Relay. Account-specific Worker runtime and relay connection health remain UNKNOWN until independently instrumented. A published global incident may or may not affect our Worker; an observed GitHub CI failure alone does not prove a Cloudflare outage. The sources degrade independently: outage of either observation feed never turns the other into green or prevents the PR overview from loading.

The home dashboard shows a compact **Failure visibility** section derived from the latest 30 workflow runs of `jan2xo/bke-worker` GitHub Actions. The section identifies workflow names, observed run status/conclusion, observed update time, source run head SHA and a safely constructed GitHub Actions run link. FAILED/TIMED_OUT, CANCELLED and ACTION_REQUIRED are distinct statuses; a cancellation is not an external service outage. A relay-named workflow failure is an **integration CI failure**, never proof that Cloudflare itself is down. **Cloudflare runtime status is UNKNOWN** without direct telemetry; absence of failure in this bounded sample is not proof of general health.

The homepage does **two independent bounded reads**: one GitHub Actions request (`actions/runs?per_page=30`) and one Cloudflare public global-status request. Neither needs a new credential. The homepage **does not fetch individual workflow jobs or raw logs**, avoiding costly fan-out. The **Inspect failing steps** link opens an on-demand, bounded `/failures/:run_id` HTML diagnosis (and `/api/failures/:run_id` JSON) for only the current sampled failures/cancellations. It retrieves that specific GitHub Actions job list once, summarizes the first **observed** failed step, any downstream required certification failures, and successful jobs; it never treats an observed failed step as definitive external root cause. A GitHub Actions run link remains the authoritative drill-down to full evidence. For incomplete, ambiguous, cancelled-without-jobs, or unavailable job evidence the answer remains explicitly UNKNOWN rather than inventing a cause. If GitHub Actions API access is unavailable or its evidence is malformed, the panel degrades to **UNKNOWN** while the existing PR overview remains accessible. All output is escaped and `/api/overview` is read-only/no-store.

This is a NITRO-engineered experiment: no automatic CI during PR implementation; manually dispatch the merge gate on the exact PR head only after code review. Do not publish until the required pre-merge proof has passed. Cloudflare hosting and production remain unchanged.

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

Selected private hostname: **`cc.jl-bke.com`**, in the existing `jl-bke.com` Cloudflare zone. A staging PR declares a dedicated Custom Domain under `[[env.preproduction.routes]]`; do not merge/deploy until Cloudflare Access protection is independently verified. See [protected PREPRODUCTION activation runbook](docs/PREPRODUCTION-ACCESS-RUNBOOK.md). The named Worker now also rejects all requests unless a human-provisioned encrypted `BKE_ACCESS_POLICY_VERIFIED` secret is exactly `true`, **and** the request Host is exactly `cc.jl-bke.com`. The marker is only a release latch, not authentication; Cloudflare Access at the edge is mandatory. Preview URLs are explicitly disabled.


Issue [#5](https://github.com/jan2xo/bke-command-center/issues/5) tracks **actual** protected deployment and live verification. A passing dry-run is not proof of deployment.

### Why the default Worker is locked

- `wrangler.toml` defines a separate `[env.preproduction]` target. Wrangler resolves its script name to `bke-command-center-preproduction`, distinct from the top-level `bke-command-center` Worker.
- Only `[env.preproduction.vars]` contains `BKE_PREPRODUCTION = "true"`. The deployed entrypoint returns `503 LOCKED` without that exact value. The bare/default Worker is therefore not a supported deployment target.
- `workers_dev = false` and `preview_urls = false` on PREPRODUCTION prevent public workers.dev and preview aliases. The staging branch proposes **only** the dedicated `cc.jl-bke.com` Custom Domain; it is not deployed or operationally accepted.
- All repo-provided Wrangler scripts include an explicit `--env preproduction`. The CI workflow runs only `cloudflare:dry-run`.
- This is a **deployment isolation guard, not an authentication system**. A protected route (for example Cloudflare Access or equivalently enforced private ingress) must be configured before serving real GitHub engineering data or log excerpts.

### Operator preflight

1. In the **existing** `jl-bke.com` zone, confirm `cc.jl-bke.com` is unused and independently verify Cloudflare Access protects that exact hostname for approved operators. Do not alter the Air Stack Pages hostname. If Access cannot be confirmed, stop before publishing; follow the runbook.
2. Review the exact certified GitHub PR head, required CI, and the target Worker name. Do not deploy from an uncertified branch.
3. Human operator provisions a least-privilege GitHub read credential **in the Cloudflare PREPRODUCTION encrypted secret store** under `GITHUB_TOKEN`. The secret is environment-specific, never in `[vars]`, repository, chat, PR comments, or logs.
4. Human operator provisions Cloudflare deploy permissions through the appropriate secure credential mechanism. Do not automate Cloudflare login, OAuth, MFA, or security challenges.
5. Run `npm run cloudflare:dry-run` to inspect the target and bundle. The only repository-provided publish command is `npm run cloudflare:deploy:preproduction`, which uses explicit `--env preproduction`. Execute it **only after** access review and authorized approval. It is not run by CI. The Worker remains intentionally LOCKED until Cloudflare Access denial/allow testing is evidenced and the `BKE_ACCESS_POLICY_VERIFIED` secret is provisioned through the human-owned Cloudflare secret store.
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
