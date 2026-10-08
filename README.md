# BKE Command Center V1

A lightweight, read-first Cloudflare Worker for PREPRODUCTION observability. GitHub remains the engineering authority; Command Center derives state and does not create a second task database.

## Local development

1. Run `npm ci`.
2. Set a GitHub credential with read-only repository/actions access in your local environment as `GITHUB_TOKEN` when higher API limits or private repository reads are needed.
3. Run `npm test`, `npm run check`, and `npm run cloudflare:dry-run`.
4. Run `npm run dev`.

Wrangler is pinned to `4.148.0` in the scripts. The dry-run builds the Worker without deploying it.

## Routes

- `/` overview
- `/worker` worker assignment/liveness view
- `/pr/:number` human-readable PR detail
- `/api/worker` normalized worker state
- `/api/pr/:number` exact-head PR state, required-certification status, causal failure capsule, downstream effects, and post-run summary
- `/api/pr/:number/evidence/job/:job_id` bounded failure excerpt for a job already proven to be failure evidence for that PR's current exact-head certification attempt

## Exact-head certification correlation

BKE Worker's `Intent Certification` is triggered by `/certify` issue comments. GitHub reports those runs with the default-branch `head_sha`, not the PR source SHA. Command Center therefore does **not** treat the workflow-run `head_sha` as PR proof.

For the current BKE Worker contract it correlates the latest `/certify` command for the current PR head using durable PR history (exact-head relay/checkpoint evidence, with PR commit history as a bounded fallback), then matches the corresponding `issue_comment` workflow run by PR title, actor, and bounded event time. Only that latest correlated run fans out to jobs.

Generic successful checks such as PR Guard are shown as observed evidence but cannot make required certification PASS. The `Required certification` job is the decisive gate. If required proof is absent, state is `UNKNOWN`; an in-progress correlated certification run is `PENDING`.

## Failure evidence

The first failed step in the latest correlated certification attempt is surfaced as the actionable root. `Required certification` is classified as downstream when a more specific job failed first. Successful module jobs may be shown as positive/unaffected boundaries; skipped jobs are not positive proof.

Raw logs remain at GitHub. Command Center never mirrors them. A failure excerpt is fetched only on demand for a job already correlated to the PR's exact-head failure state, follows GitHub's short-lived log redirect without forwarding the GitHub Authorization header, reads at most 256 KiB, redacts common credential patterns, and returns only a compact failure excerpt.

## PREPRODUCTION deployment

Use Wrangler only against a non-production environment after human review. Keep `GITHUB_TOKEN` in the Cloudflare secret store; never commit it. No production deployment is part of PR #4.
