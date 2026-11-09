# BKE Engineering Standard

This file is the canonical cross-project engineering instruction for BKE repositories.

Canonical source:

`jan2xo/bke-command-center/bke.md` on current `main`.

Every BKE repository must carry a local root copy named exactly:

`bke.md`

Do not use `AGENTS.md` as the BKE project instruction contract.

---

## 0. New-project bootstrap

For every new BKE repository, the **first engineering task** is to retrieve the current canonical `bke.md` from `jan2xo/bke-command-center` and place it at the new repository root.

The human operator is not expected to copy this file manually.

The bootstrap actor should:

1. read canonical `bke.md` from `jan2xo/bke-command-center` current `main`;
2. create root `bke.md` in the target repository;
3. record the canonical source commit SHA used for that copy in the bootstrap PR/issue;
4. only then begin project-specific engineering.

If a BKE repository does not yet contain `bke.md`, treat installing it as the first setup task before substantial engineering.

Project-specific architecture belongs in normal repository docs and GitHub PRs/issues. Do not fork the engineering standard silently.

When a project intentionally needs an exception, record the exception explicitly in the relevant PR/issue and explain its scope.

---

## 1. Authority hierarchy

For engineering work, use this order unless an explicit project decision establishes a stricter local rule:

1. explicit current operator authorization;
2. local root `bke.md`;
3. live GitHub PR/task/issue state;
4. repository implementation, tests, CI, release evidence;
5. relevant historical PRs/issues;
6. conversational memory or model-specific context.

Live GitHub state is canonical for implementation, PR, CI, merge, release, and repository truth.

Do not use Notion as a durable engineering task database or canonical execution truth.

## 2. Context recovery

Do not require a particular ChatGPT Project, model, conversation, or private memory to operate a BKE repository.

Before substantial engineering:

`read bke.md -> recover current main -> recover open PRs/issues/workflows -> identify exact authorized intent/head -> execute`

If rationale, prior decisions, constraints, or historical context are missing:

`search the relevant PRs and issues before asking the operator to repeat context or guessing`

Prefer the newest explicit GitHub decision over stale conversational context.

## 3. One intent, one fresh PR

One independent engineering intent belongs in one fresh PR from current `main`.

Canonical flow:

`current main -> fresh branch -> PR -> implementation -> certification -> exact-head review -> merge when authorized -> verify main`

Do not reuse merged or stale feature branches for unrelated intents.

A PR is both review surface and durable execution ledger.

## 4. PR execution ledger

The PR body should contain the current human-readable intent, scope, architecture/security boundaries, task checklist, and certification plan.

Chronological execution evidence belongs in PR comments/checkpoints.

Recommended durable checkpoints:

- `BKE EXECUTION CHECKPOINT — IMPLEMENTED`
- `BKE EXECUTION CHECKPOINT — CERTIFIED`
- `BKE EXECUTION CHECKPOINT — READY_FOR_AUDIT`
- `BKE EXECUTION CHECKPOINT — BLOCKED`
- `BKE EXECUTION CHECKPOINT — MERGED`

Record exact SHAs and workflow/run identifiers where relevant.

Do not turn the PR body into an append-only transcript.

## 5. Task checklist as execution completeness

Substantial worker-owned PRs should carry an explicit machine-readable task checklist.

Required items should resolve to a bounded state such as:

- `DONE`
- `BLOCKED`
- `NOT_REQUIRED`

`READY_FOR_AUDIT` must not be declared while required items remain unresolved or certification is stale.

Queue/task ordering and per-PR execution completeness are separate concepts.

## 6. Exact-head certification

Certification evidence is valid only for the exact PR head it proves.

Before merge:

1. record exact PR head;
2. resolve the minimum complete required certification graph;
3. run only the required graph;
4. verify every required proof passed against that exact head;
5. verify there is no relevant unresolved red;
6. review architecture/security boundaries;
7. merge only when authorized, preferably SHA-locked;
8. verify resulting `main`;
9. record the durable merged checkpoint.

Any head change makes old exact-head certification stale.

## 7. Intentional CI — PR-owned plans, stable trust

CI exists to prove the **authorized engineering intent**, not to run every suite because a PR was opened, synchronized, or pushed.

The default BKE model is:

`PR #NNN = execution ledger + editable certification plan; CI modules = proof tools; required-certification = exact-head proof aggregator.`

- **PR is the ledger, not a heavy-CI trigger.** Routine PR activity may run a cheap PR Guard where the repository has adopted one. Substantial tests, builds, containers, installers, security scans, and deployment verification run only when the declared intent requires them.
- **Certification is branch-editable.** A PR may introduce or change its own tests, certification manifest, integration fixtures, or temporary workflow while still unmerged. The certification plan declares the minimum complete graph, exact head, primary proof owners, and excluded modules. A PR need not merge its tests into `main` before they can run.
- **Default-branch entrypoints are routing infrastructure, not test authority.** A GitHub `issue_comment` workflow is registered from the default branch. It can verify an authorized `/certify ...` PR comment, read the declared plan from the **current PR SHA**, and test that exact candidate. Command syntax and manifest schema are repository-local; do not assume every repository implements `/certify pr core` identically.
- **Names express ownership.** Label *temporary PR-specific* tests, jobs, and manifests with the PR number (e.g. `PR #297` or `pr-297.json`). Name reusable modules for the behavior they prove (Identity, Legal, Licensing, packaging, etc.). A durable shared workflow must not be renamed whenever a PR changes.
- **Aggregate only declared proof.** `required-certification` must fail when a required module is missing, stale, or red, even if other jobs passed. A changed PR head invalidates previous proof. The plan must explain uncertain or security-sensitive ownership and intentionally excluded modules.
- **Retire disposable CI.** Once a PR-owned workflow or test recipe is merged, superseded, or incorporated into a reusable owner, remove it from active GitHub Actions and preserve useful historical source in an inert legacy archive. First verify no active caller still needs it. Never archive required shared modules merely because one PR did not select them.
- **Isolate privileges.** Branch-authored tests must not receive secrets, write tokens, privileged OIDC, or persisted checkout credentials. Protected Staging/Production, signing, release, and payment workflows use separate explicit authorization and environments. A reusable unprivileged workflow must not contain a nested job requesting higher token permissions, even if that job is usually skipped.
- **Keep failure evidence compact.** Record first causal failure, exact run and source SHAs, and reproducible follow-up. Avoid pouring entire raw logs into conversational context.

### Existing repositories and migration

The above is the **new cross-project standard**, not a claim that all current repositories have already migrated. Inspect each repository's real workflow triggers, privileges, branch protection, and certification ownership. Make CI migrations in focused, certified PRs.

For example, Command Center currently documents a repo-local NORMAL/NITRO experiment in `docs/ENGINEERING-MODES.md`; its NORMAL mode still runs automatic PR CI. That remains the live contract **until a separately certified Command Center CI migration**. Do not alter those active triggers merely by updating the shared standard.

If a broken default-branch dispatcher blocks its own repair, a **minimal explicitly owner-authorized CI-only bootstrap** may be unavoidable. Record which exact-head proof was unavailable, leave privileged and production paths locked, and immediately run post-bootstrap certification. This is not a general exemption allowing unrelated uncertified merges.

When CI fails, identify the earliest actionable causal failure and distinguish it from downstream aggregate failures.

## 8. First causal failure

For engineering failures, prefer a compact failure capsule containing:

- repository;
- PR;
- exact head;
- execution host;
- component/boundary;
- stage;
- causal vs downstream classification;
- short actionable summary;
- run/job evidence;
- next owner/action when determinable.

Humans should not need to read every raw log to know where the failure began.

Raw logs remain available for drill-down.

## 9. Authority vs execution

Separate execution from authority.

An executor may inspect, implement, test, debug, and certify only within its delegated intent.

Authority to create work, assign ownership, approve exceptional security/production actions, and merge must be explicit in the repository/project contract.

Do not let an executor invent unqueued work or silently assume authority it was not granted.

## 10. Fail closed

Fail closed when state is ambiguous, including:

- ownership conflicts;
- multiple possible active assignments;
- stale exact-head evidence;
- malformed or contradictory task state;
- uncertain dispatch/delivery state;
- unclear production/security authorization;
- conflicting instructions with no clear authority order.

Do not resolve ambiguity heuristically when doing so could duplicate work or cross a trust boundary.

## 11. GitHub-native durable truth

Where durable engineering state is required, prefer GitHub-native representation:

- issues/tasks;
- PRs;
- labels/assignment metadata;
- checklists;
- comments/checkpoints;
- CI runs;
- commits/releases.

Do not introduce a second authoritative task database unless the project explicitly requires one and the authority boundary is documented and certified.

Caches and analytics stores may exist only as explicitly non-authoritative derived state.

## 12. Security and production

Unless explicitly authorized:

- production is locked;
- no production deployment/cutover;
- no force push;
- no weakening of authentication/security boundaries;
- no credentials/secrets in code, logs, PR comments, artifacts, or prompts;
- no browser-profile secret exposure;
- no automation of OAuth, MFA, CAPTCHA, or security challenges.

Human authentication remains human-controlled.

## 13. Cross-repository work

When an intent touches another BKE repository:

- inspect that repository's local `bke.md` and live GitHub state;
- treat that repository as canonical for its own implementation;
- minimize cross-repository mutation;
- pin immutable SHAs/releases when a dependency requires reproducibility;
- do not silently import assumptions from one BKE project into another.

If the target BKE repository has no `bke.md`, bootstrap it before substantial work.

## 14. Portability

A capable new model/tool should be able to enter a BKE repository and operate by reading durable repository/GitHub context.

Essential architecture and operating knowledge must not exist only in private conversation memory.

The standard pattern is:

`local bke.md + live GitHub PRs/issues/CI + repository docs = executable project context`

## 15. Canonical maxims

`GitHub is truth. PR is intent + ledger. CI proves the exact head.`

`Context needed? Recover it from the repo, PRs, and issues before guessing.`

`One intent -> one fresh PR -> minimum complete certification -> exact-head proof -> authorized merge.`

`PR = ledger. PR-owned tests live on the candidate branch. Main hosts trusted dispatch, not every test definition.`

`Required-certification = declared exact-head proof; retire temporary CI to inert legacy after its intent.`

`New BKE repo? First task: get bke.md there.`
