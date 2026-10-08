# BKE Command Center V1

A lightweight, read-first Cloudflare Worker for preproduction observability.

## Local development

1. Install dependencies: `npm install`
2. Set a GitHub token with read-only repository/actions access in your local environment as `GITHUB_TOKEN`.
3. Run `npm test` and `npm run check`.
4. Run `npx --yes wrangler@4.148.0 dev`.

The worker reads GitHub on demand. It does not create a task database, mirror logs, deploy production, or store credentials in the repository.

## Routes

- `/` overview
- `/worker` worker overview
- `/pr/:number` PR detail
- `/api/worker` normalized live worker state
- `/api/pr/:number` exact-head PR state, certification summary, causal failure capsule, and post-run summary

## PREPRODUCTION deployment

Use Wrangler only against a non-production environment after human review. Keep `GITHUB_TOKEN` in the Cloudflare secret store; never commit it. No production deployment is part of PR #4.
