# <PROJECT NAME> — Repository Instructions

> Template for every new BKE repository.
>
> Replace all `<PLACEHOLDERS>` before first substantial engineering work.

## 0. Read the BKE Engineering Standard first

This repository follows the canonical BKE Engineering Standard:

`jan2xo/bke-command-center/docs/BKE-ENGINEERING-STANDARD.md` on current `main`.

Before substantial engineering, architecture, debugging, CI, deployment-planning, certification, merge, or project-management work:

1. read the canonical BKE Engineering Standard;
2. read this repository-local `AGENTS.md`;
3. recover live GitHub state for this repository;
4. identify the exact authorized intent/PR/head;
5. if context is missing, search the relevant PRs and issues before asking the operator to repeat it or making assumptions.

If this local file conflicts with the central standard, the local file may only override it where the override is explicit and project-specific. Security/production locks must not be weakened implicitly.

For reproducible high-risk work, record the exact central-standard commit SHA in the PR.

---

## 1. Repository identity

- **Project:** `<PROJECT NAME>`
- **Canonical repository:** `<owner/repo>`
- **Primary purpose:** `<one-paragraph purpose>`
- **Default branch:** `main`
- **Primary runtime/platform:** `<runtime>`
- **Canonical deployment environments:** `DEVELOPMENT / PREPRODUCTION / PRODUCTION`

## 2. Project-specific authority

Live GitHub state in `<owner/repo>` is canonical implementation, PR, CI, merge, release, and repository truth.

Project-specific durable authority:

- `<what GitHub owns here>`
- `<external system that is authoritative for a narrowly defined domain, if any>`

Do not introduce a second authoritative task database.

## 3. Project architecture invariants

These are project-specific invariants that every implementation must preserve:

- `<INVARIANT 1>`
- `<INVARIANT 2>`
- `<INVARIANT 3>`

Canonical project maxim:

`<SHORT PROJECT-SPECIFIC MAXIM>`

## 4. Context recovery

If project-specific context is needed, use this order:

`local AGENTS.md -> active PR/task -> relevant issues/PR history -> implementation/tests -> external context only when necessary`

Do not rely on ChatGPT Project memory or a previous conversation as authoritative project state.

## 5. Execution model

Unless this repository explicitly requires a stricter flow:

`current main -> fresh branch -> one coherent PR -> implementation -> minimum complete certification -> exact-head review -> authorized merge -> verify main`

Project-specific delegation/ownership rules:

- `<OWNER/WORKER RULES OR N/A>`

## 6. Certification

Normal certification modules/checks:

- `<CHECK/MODULE 1>`
- `<CHECK/MODULE 2>`

Rules:

- certification plan determines required proof;
- only the minimum complete graph should run;
- exact-head proof is required before merge;
- any head change stales old certification.

## 7. Failure/observability expectations

Failures should expose the earliest actionable causal failure, not only an aggregate red gate.

Project-specific observability sources:

- `<CI>`
- `<RUNTIME HEALTH>`
- `<LOG SOURCE>`

Raw logs remain drill-down evidence; compact causal summaries are preferred for humans and AI orchestration.

## 8. Security and production locks

In addition to the central BKE standard:

- `<PROJECT-SPECIFIC SECURITY RULE>`
- `<PROJECT-SPECIFIC PRODUCTION RULE>`

Never expose credentials, tokens, signing material, browser-profile secrets, or human authentication challenges.

## 9. Cross-repository dependencies

Known BKE dependencies:

- `<repo@SHA/release or NONE>`

When another BKE repository matters, read that repository's `AGENTS.md` and live GitHub state before acting.

## 10. Current program intent

Current major program goal:

`<CURRENT GOAL>`

Do not infer unqueued independent work from this section; active GitHub issues/PRs remain the execution authority.

## 11. Local maxims

- `<PROJECT-SPECIFIC MAXIM>`
- `Context needed? Find it in the PRs and issues before guessing.`
- `GitHub is truth. Exact head is proof boundary.`
