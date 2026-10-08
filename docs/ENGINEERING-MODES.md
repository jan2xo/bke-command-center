# Command Center engineering modes — repo-local experiment

**Scope:** `jan2xo/bke-command-center` only. Other BKE repos retain their own operating rules. No Cloudflare deploys, secrets, workflow automation of OAuth, or production actions.

GitHub is the sole task/PR/CI authority. Every independent intent uses a fresh branch from current `main` and a fresh PR; the PR is the durable intent/task/checkpoint ledger.

## NORMAL (current/default)

- Branch prefix such as `feat/*`, `fix/*` or other non-`nitro/*`.
- PR body: `**Engineering mode:** \u0060NORMAL\u0060`.
- CI remains configured on `pull_request` and `push` to `main`; every ordinary PR update can trigger a test run.
- Same certification graph: `npm ci`, `npm test`, `npm run check`, named PREPRODUCTION `cloudflare:dry-run`.
- Keep exact-head review and SHA-locked squash merge. The `main` push may trigger its existing CI as usual.

## NITRO (experimental; NO development CI by convention)

- New head branch **`nitro/<intent>`** from current `main`; target `main` in the **same** repo.
- PR has exactly one `bke-ci:*` label, namely **`bke-ci:nitro`**, and its body contains exactly `**Engineering mode:** \u0060NITRO\u0060`.
- **Every development commit, including the first PR-opening and every repair commit, contains the literal `[skip ci]` in the Git commit message.**
- Avoid using `git push --force` and never reuse merged branches. Using GitHub's Git data API or contents API must still set `[skip ci]` on every write.
- Do not trigger `workflow_dispatch` while engineering, editing, reviewing or fixing. Do not open a second workflow as a PR Guard.
- When all required engineering checklist items are DONE, review the diff, freeze the PR's current 40-character `head.sha` and **then intentionally invoke the merge gate**.
- CI runs only once per final head **when manually fired**. If the gate fails, remediate the PR with new skip-tagged commits, review again, and intentionally recertify the changed exact head. Old CI proof is stale.
- Never merge an uncertified head or bypass the exact-head merge-authority review.

### Manual merge-gate invocation

The `ci` GitHub Actions workflow must first exist in the default branch (installed by the NORMAL-mode contract PR). Thereafter:

```sh
# Read the exact current SHA from GitHub PR head before running.
gh workflow run ci.yml \
  --repo jan2xo/bke-command-center \
  --ref nitro/failure-visibility \
  -f pr_number=123 \
  -f expected_head_sha=0123456789abcdef0123456789abcdef01234567
```

This command is an **illustration**: replace the branch, PR and SHA with actual live values. In the Actions tab, select **ci → Run workflow**, select the `nitro/*` PR branch, enter the PR number and exact source SHA.

The workflow first:
1. checks out the selected Nitro commit;
2. checks GitHub PR number/state, repository, target `main`, declared label and mode, Nitro branch ref, workflow source commit SHA, exact operator-specified SHA, and the first page of PR commit history (fails closed at 100);
3. verifies every PR commit message contains `[skip ci]` and the last commit equals the expected SHA;
4. only then runs `npm ci`, tests, syntax and `wrangler deploy --env preproduction --dry-run`.

A **manual `workflow_dispatch` workflow run** is the certification event. Preserve the run ID, PR HEAD SHA, all required job/step conclusions, and independent audit verdict in PR comments. GitHub workflow results are evidence; the workflow does **not** merge or deploy. Execute SHA-locked squash merge only on explicit authorization and the exact certified PR head. Select a squash commit message with `[skip ci]` when the intent also requires suppressing redundant post-merge `main` CI.

### GitHub platform limits — do not misrepresent

**This is an experiment, not an infallible no-auto-CI enforcement mechanism.** On a conventional `pull_request` workflow, branch filters match the **base** branch, not the Nitro PR's head. GitHub has no native event-level filter for an arbitrary PR label/head branch. The GitHub-supported `[skip ci]` commit instruction suppresses automatic `push` and `pull_request` workflows when present, **but if a Nitro HEAD commit lacks it, unwanted CI can fire**. A `workflow_dispatch` run is unaffected.

**Pending required-check trap:** GitHub docs state workflows skipped by `[skip ci]` can leave required checks pending, and manually dispatched workflow checks may not satisfy `pull_request`-specific required status checks. If the repository's branch protection requires a conflicting automatic status, **STOP** and seek a separate explicitly reviewed ruleset/gate design. Never switch off branch protection, enable a bypass, or silently mark the PR certified.

**No Nitro PR Guard:** do not add `pull_request_target` or another automatic event that evades `[skip ci]`. The test workflow stays one run graph, and its manually triggered gate is the only intended Nitro certification. Exact-head evidence must be reviewed before merge; certification does not confer merge authority.

**This repo is already connected to a PREPRODUCTION Cloudflare hostname:** the CI command always uses `--dry-run` and cannot modify `cc.jl-bke.com`. Production remains locked.

### References

- [GitHub: skip workflow runs](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/skip-workflow-runs)
- [GitHub: manually run workflow on ref](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
- [GitHub: checks triggered with workflow_dispatch vs required PR checks](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
