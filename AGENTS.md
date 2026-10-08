# BKE Command Center — Canonical Repository Instructions

This file is the canonical operating instruction for engineering work in `jan2xo/bke-command-center`.

## 1. Authority

- Live GitHub state in `jan2xo/bke-command-center` is canonical implementation, PR, CI, deployment, and repository truth.
- Repository instructions are authoritative for project operation. ChatGPT Project custom instructions, conversation memory, or model-specific context are optional accelerators only.
- Do not depend on one ChatGPT Project, one model, or one conversation to understand this system.
- Do not use Notion as an execution database or canonical engineering truth.

## 2. Recover context from GitHub before guessing

Before substantial engineering, architecture, debugging, CI, deployment-planning, or project-management work:

1. Read this file from current `main`.
2. Recover current `main`, open PRs, active issues, and relevant workflow state.
3. Identify the exact authorized intent and exact head.
4. If rationale, prior decisions, constraints, or historical context are missing, search the relevant PRs and issues before asking the operator to repeat context or inventing an answer.
5. Prefer the newest explicit GitHub decision over stale conversation context.

For project-specific context, use this order:

`current repo instructions -> live PR/task -> relevant issues/PR history -> implementation/tests -> external context only when necessary`

## 3. Purpose

BKE Command Center is the lightweight cloud observation and bounded-control surface for the BKE ecosystem.

It should answer quickly:

- What systems are healthy?
- What workers are active, idle, blocked, or waiting?
- What PR/task is a worker executing?
- What is the current exact head?
- What checklist work remains?
- What certification boundary failed?
- Where did the first causal failure occur?
- What failures are merely downstream consequences?
- What is the next expected action or owner?

## 4. Command Center is not the source of engineering truth

GitHub remains authoritative for engineering state such as:

- tasks and task authorization;
- PR ownership;
- exact heads;
- task checklists;
- CI/certification;
- merge/release state;
- durable execution checkpoints.

Command Center may derive, cache, aggregate, and present state, but it must not create a second authoritative task database.

Canonical maxim:

`Command Center sees and controls; authoritative systems remain truth.`

## 5. V1 architecture

Prefer:

- Cloudflare Worker as the lightweight cloud runtime;
- lightweight web UI/static assets;
- GitHub App-backed reads;
- stable BKE system/repository slugs;
- relay/worker liveness reads when available;
- PREPRODUCTION-first delivery.

Avoid in V1 unless a concrete need is proven:

- D1 as an authoritative store;
- mirrored raw-log warehouses;
- duplicate task/ownership databases;
- heavyweight backend infrastructure.

Derived caches are allowed only when their non-authoritative nature is explicit.

## 6. Flagship diagnostic: FIRST CAUSAL FAILURE

Humans should not need to pull and read every log to understand a red run.

For a failure, derive a compact failure capsule containing, where available:

- repository;
- PR number;
- exact head;
- worker ID;
- occurred-at time;
- execution host;
- affected boundary/component;
- stage;
- classification: `CAUSAL` or `DOWNSTREAM`;
- short actionable summary;
- run/job evidence identifiers;
- unaffected boundaries when determinable;
- next owner;
- next expected action.

Prefer the earliest actionable causal failure over the final aggregate red gate.

Raw logs stay at their original source and are fetched only on demand for drill-down.

## 7. Slug model

Use stable routes/identities such as:

- `/worker`
- `/workers/:worker_id`
- `/repo/:slug`
- `/system/:slug`
- PR/run-specific views where useful.

The registry should be extensible to BKE Worker, Launcher, Licensing, Digital Solutions, and future BKE systems without coupling the UI to one implementation.

## 8. Observation before control

V1 is primarily observational:

- system/worker health;
- PR/checklist state;
- exact head;
- certification graph;
- progress/lease state;
- first causal failure;
- post-run summaries;
- notification-ready events.

Any control added later must translate into the authoritative underlying system, normally GitHub/relay, instead of mutating private Command Center task state.

## 9. MCP and Remote Controller sequencing

Do not prematurely make MCP or Remote Controller the architecture.

Sequence:

1. stabilize Command Center read/derived-state API;
2. add bounded MCP access over that API;
3. add tightly authorized control operations;
4. add Remote Controller as a human/mobile client of the same bounded control API.

MCP and Remote Controller must not become separate task databases or authorities.

## 10. Cross-repository behavior

When a Command Center task depends on another BKE repository:

- inspect the relevant live repository/PR/issues instead of relying on remembered state;
- treat that repository's own live GitHub state as canonical for its implementation;
- consume only the minimum state required for the Command Center feature;
- do not silently mutate another BKE repository unless the task explicitly authorizes it.

## 11. Engineering execution

Use one coherent intent per fresh PR from current `main`.

For substantial work:

`current main -> fresh branch -> PR -> implementation -> minimum complete certification -> exact-head review -> merge when authorized`

Keep chronological execution evidence in PR comments/checkpoints rather than turning PR descriptions into logs.

Any head change stales prior exact-head certification evidence.

## 12. Security and production locks

Unless explicitly authorized:

- no production deployment;
- no production credential cutover;
- no secret material in code, PR comments, logs, UI payloads, or artifacts;
- no browser-profile contents or credentials;
- no automation of ChatGPT authentication, OAuth, MFA, CAPTCHA, or security challenges.

Use least-privilege GitHub App permissions.

## 13. Failure behavior

Fail closed on:

- ambiguous authority;
- ambiguous ownership;
- stale exact-head proof;
- malformed derived state;
- conflicting control requests;
- uncertain security boundaries.

Do not hide uncertainty behind a healthy-looking dashboard state.

## 14. Context portability

This repository must remain operable by different capable models/tools.

Do not encode essential project knowledge only in a ChatGPT Project or private conversation.

When context is needed, recover it from GitHub PRs/issues and repository documentation first.
