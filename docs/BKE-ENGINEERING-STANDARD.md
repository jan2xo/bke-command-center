# BKE Engineering Standard

This document is the canonical cross-project engineering standard for BKE repositories.

New BKE projects should include a repository-local `AGENTS.md` that references this standard and then declares only the project-specific rules that extend it.

Canonical source:

`jan2xo/bke-command-center/docs/BKE-ENGINEERING-STANDARD.md` on current `main`.

When reproducibility matters for a particular PR or release, record the exact BKE Engineering Standard commit SHA used for that work.

---

## 1. Authority hierarchy

For engineering work, use this authority order unless a repository explicitly declares a stricter local rule:

1. explicit current operator authorization;
2. repository-local `AGENTS.md` from current `main`;
3. this BKE Engineering Standard;
4. live GitHub PR/task/issue state;
5. repository implementation, tests, CI, release evidence;
6. relevant historical PRs/issues;
7. conversational memory or model-specific context.

Live GitHub state is canonical for implementation, PR, CI, merge, release, and repository truth.

Do not use Notion as a durable engineering task database or canonical execution truth.

## 2. Context recovery

Do not require a particular ChatGPT Project, model, conversation, or private memory to operate a BKE repository.

Before substantial engineering:

`read local AGENTS.md -> read this standard -> recover current main -> recover open PRs/issues/workflows -> identify exact authorized intent/head -> execute`

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

PR body should contain the current human-readable intent, scope, architecture/security boundaries, task checklist, and certification plan.

Chronological execution evidence belongs in PR comments/checkpoints.

Recommended durable checkpoints:

- `BKE EXECUTION CHECKPOINT — IMPLEMENTED`
- `BKE EXECUTION CHECKPOINT — CERTIFIED`
- `BKE EXECUTION CHECKPOINT — READY_FOR_AUDIT`
- `BKE EXECUTION CHECKPOINT — BLOCKED`
- `BKE EXECUTION CHECKPOINT — MERGED`

Record exact SHAs and workflow/run identifiers where they are relevant.

Do not turn the PR description into an append-only transcript.

## 5. Task checklist as execution completeness

Substantial worker-owned PRs should carry an explicit machine-readable task checklist.

Use the checklist to answer whether the current intent is actually complete.

Each required item should resolve to a bounded state such as:

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

## 7. Intentional CI

CI exists to prove the authorized intent, not to generate noise.

Prefer:

- cheap automatic PR guards;
- explicit substantial certification;
- minimum complete graphs;
- compact causal failure summaries;
- exact-head proof.

Avoid dumping enormous logs into conversational context.

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

Separate intelligence/execution from authority.

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

- inspect that repository's local `AGENTS.md` and live GitHub state;
- treat that repository as canonical for its own implementation;
- minimize cross-repository mutation;
- pin immutable SHAs/releases when a dependency requires reproducibility;
- do not silently import assumptions from one BKE project into another.

## 14. Portability

A capable new model/tool should be able to enter a BKE repository and operate by reading durable repository/GitHub context.

Essential architecture and operating knowledge must not exist only in private conversation memory.

The standard pattern is:

`central BKE standard + local AGENTS.md + live GitHub PR/issues/CI = executable project context`

## 15. Canonical maxims

`GitHub is truth. PR is intent + ledger. CI proves the exact head.`

`Context needed? Recover it from the repo, PRs, and issues before guessing.`

`One intent -> one fresh PR -> minimum complete certification -> exact-head proof -> authorized merge.`
