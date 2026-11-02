---
name: bke-lean-engineering
description: Keep BKE engineering changes as small as safely possible. Use when scoping, implementing, debugging, reviewing, or certifying a BKE GitHub task; read the target repository's bke.md and live GitHub authority first.
---

# BKE Lean Engineering

**Goal:** Deliver the smallest complete, safe change for the *authorized* task. Simplicity is not permission to omit required security, correctness, or certification.

## Authority and scope

- Read the target repo's `bke.md`, live `main`, assigned issue/PR, and exact head. Those and explicit owner decisions outrank this skill.
- GitHub is engineering truth. Never use private conversation memory or Notion as a task ledger.
- One independent intent, one fresh PR from current `main`. Do not invent an issue, assignment, orchestrator seat, approval, credential, or live-send authority.
- Before writing, check the actual task gate: approved issue/labels, named documentation files, frozen paths, changed-line cap, and required checks. **If a known gate will fail, record BLOCKED before creating a doomed PR.** Never bypass a gate.

## The five-question filter

Answer privately, briefly, before any code:
1. What exact user-visible or testable result is required?
2. What existing code or contract already does most of it?
3. What is the **minimum** file set needed?
4. What is the smallest complete test and certification graph?
5. Which requirement would justify each extra file, abstraction, dependency, or protocol?

If question 5 has no concrete answer, **do not add it**.

## Execution rules

- **Reuse before building.** Extend existing code instead of adding parallel frameworks, wrappers, state stores, or speculative infrastructure.
- **No invented contracts.** If a protocol, field, expiry, receipt format, or trust source is unspecified, do not make one up. Reuse a canonical contract or mark that narrowly dependent part BLOCKED.
- **Keep changes local.** No opportunistic refactors, renames, cleanup, unrelated tests, new documentation, workflow edits, or future-phase scaffolding.
- **Preserve safety.** Fail closed on uncertain ownership, head, auth, claim, or dispatch state. No automatic replay after a possibly consumed send. Keep production and human authentication locked.
- **Use real evidence.** Run focused tests where possible, then only the minimum required exact-head CI. Say explicitly when a test was skipped, mocked, or not run; a passing unrelated check proves nothing.
- **Move past independent blockers.** Record the precise blocker and owner action in the relevant GitHub issue/PR, then continue only separately authorized independent work.
- **Stop at acceptance.** Do not manufacture a follow-up task because the implementation feels incomplete stylistically.

## Report, without ceremony

For each task, report **DONE**, **PARTIAL**, or **BLOCKED**; exact PR/head and relevant proof; then a short challenge:

- **Verdict:** what actually meets the acceptance criteria.
- **Counterevidence:** first concrete failure or limitation.
- **Unverified:** claims not established by real evidence.
- **Recommendation:** smallest necessary next action, or **none**.

**Default maxim:** *Make the smallest change that solves the authorized problem. Prove it. Stop.*
