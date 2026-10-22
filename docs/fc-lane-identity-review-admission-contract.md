# F/C lane identity and review-admission contract v1

**Status:** source-only contract; no trusted live-session source is claimed.
**Parent:** [Command Center #30](https://github.com/jan2xo/bke-command-center/issues/30) / [BKE Worker #121](https://github.com/jan2xo/bke-worker/issues/121).
**Contract implementation:** src/fc-lane-identity-contract.js.
**Read-side integration points already on main:** src/dashboard.js, src/admin-worker-assignments.js, and Worker cloudflare-relay/src/admin-assignment-inventory.js.
**Important:** a valid schema record, GitHub principal, lane name or CI pass is not an authenticated actor/session witness.

## 1. Stable lane identity is not actor identity

F1, F2… are stable execution-lane keys. C1, C2… are stable review-lane keys. A lane can outlive many ChatGPT conversations, providers, browser targets and actor sessions. Reassigning a lane changes its actor binding, not the lane ID.

Keep these fields separate in the versioned lane record:

| Field | Meaning | Trust rule |
|---|---|---|
| version, lane_id, lane_kind, lifecycle_state | Contract version, stable F/C lane and its lifecycle | Schema validates shape only. Only owner-controlled lane configuration can propose lifecycle changes. |
| actor_binding.status, actor_instance_id, witness | Current authenticated actor-instance binding and provenance reference | VERIFIED is only valid when created by a trusted private server verifier. Never accept a client-posted binding as proof. |
| worker_device.worker_id, registration_ref, status | Separate Worker/device registration identity, when relevant | Must come from server-owned registration/admission evidence. Desktop-only lanes may use NOT_APPLICABLE. |
| github_write_principal.login, evidence_ref, status | GitHub principal that authored durable evidence | Check using authoritative GitHub response. It neither proves nor disproves actor-instance separation. |
| provider_context.provider, model_ref, account_ref | Provider, model and opaque nonsecret account reference | Claimed provider metadata is not identity proof. Never store tokens, cookies, browser content, or authentication secrets. |
| provider_context.browser_profile_ref, chatgpt_target_ref, resource_status | Isolated browser profile and exact intended ChatGPT resource/target | Only a fresh trusted resource/session witness can mark these verified. Re-read/revalidate after async work. |
| active_target.repository, pr_number, head_sha, worker_id, assignment_state, evidence_ref | GitHub PR/head and current implementation assignment projection | Reuse the existing GitHub assignment inventory. A cached canvas record cannot grant or reserve a PR. |
| review target, decision and evidence reference | A specific finding against one exact PR head | Bind to repository + PR number + 40-character head. New head means old review evidence is superseded. |

An actor-binding witness has the contract shape { audience, verifier_id, witness_id, issued_at_ms, expires_at_ms }, with audience bke.fc.review-admission.v1 and bounded lifetime. These reference fields are not a signature format or cryptographic proof; the future private verifier must validate authentic origin, session and resource binding. The schema/freshness guard must never be exposed as an authentication endpoint.

Lane lifecycle values are PROPOSED, AVAILABLE, RESERVED, ACTIVE, PAUSED, BLOCKED and RETIRED. An ACTIVE or RESERVED lane must have a current verified actor/resource context and a single assigned exact-head target. Unknown or conflicting evidence is represented as blocked, not repaired heuristically.

## 2. Review classification and admission

Do not hard-code F1 → C1. An owner may propose F1 → C1, F1 → C2, F2 → C1, or any other pairing. A proposed edge expresses operator intent only. The backend decides qualification from current server-verified records; lane IDs and principal names do not confer review authority.

| Classification | Minimum meaning | Independence-required gate |
|---|---|---|
| SELF_AUDIT | Both fresh trusted witnesses resolve to the same actor-instance ID | Not satisfied. Findings are useful; an ACCEPT is findings-only. |
| CROSS_WORKER_AUDIT | Both fresh trusted witnesses resolve and their actor-instance IDs differ | Candidate only, still subject to current-head verification and applicable review policy. |
| INDEPENDENCE_UNVERIFIED | Either witness is absent, claimed-only, stale, expired, revoked, audience-mismatched, malformed or uncertain | Blocked. Do not infer a distinct reviewer. |

The actor-separation classifier compares authenticated actor-instance IDs only. A shared GitHub principal such as jan2xo neither collapses two proven actor instances into one nor creates two actor instances. Conversely, different C/F lane labels, models, accounts or conversations do not establish separation when actor witnesses are missing.

An official review-admission check must:

1. Authenticate the owner/admin at the platform boundary before inspecting private peer/session resources.
2. Obtain the implementing and reviewing actor bindings from a trusted server-only session verifier. Verify witness authenticity, issuer, audience, scope, current session generation, issue/expiry, revocation and exact target binding. Client JSON, a self-asserted flag, lane identity, GitHub author string and the contract validator are not this verifier.
3. Confirm reviewer-lane lifecycle/availability, fresh isolated profile and intended provider target, and absence of actor/resource/assignment conflicts. Any UNKNOWN, timeout, stale read, duplicate actor binding or inconsistent record fails closed.
4. Re-read the current authoritative GitHub repository, PR status, exact head and assignment inventory before returning a result. Enforce globally: one worker instance → at most one active implementing PR; one active implementing PR → one authorized worker. Reuse the existing inventory and atomic assignment control; do not build a parallel database. Revalidate the same target/head and witness after async reads immediately before returning the result.
5. Keep review evidence immutable per SHA. If the target head changes, mark the prior result SUPERSEDED for current admission. ACCEPT, REMEDIATE and BLOCKED are technical findings, not assignment writes.
6. Preserve the distinction between a BKE technical checkpoint and GitHub's native review record. A technical comment cannot be displayed as a native APPROVE. A self-authored review or checkpoint must never be represented as a separate-account approval. Native review state must be read from GitHub and displayed independently.

The pure contract helper returns authority NONE and native_github_review_status NOT_CHECKED; it does not admit, assign, dispatch, approve, sign, pair, or activate any worker. Its CROSS_WORKER_REVIEW_CANDIDATE display means only that the supplied contract-shaped actor bindings differ and the cited head matches the caller-supplied head. The trusted backend must perform the verifier and GitHub reads described above.

## 3. Command Canvas — read-only MVP interface

The first UI may extend the existing Command Center dashboard; its GitHub-backed assignment status must come from the existing readAdminWorkerAssignments / public projection and the established GitHub App inventory. Do not fork that inventory, expose its credentials, or invent a new authority store.

### View model

A read-only snapshot should contain:

- snapshot_version, observed_at_ms, source freshness/status and repository scope;
- F/C lane summaries with lifecycle, binding confidence, worker/device registration, GitHub write principal, provider/model/account references, browser profile/target status;
- implementation PR/repository/current head, assignment state and exact-head CI state, sourced from the current GitHub inventory;
- review finding (ACCEPT / REMEDIATE / BLOCKED), evidence category, evidence reference, reviewed SHA and current-head relation;
- native GitHub review state in a separate field (NOT_CHECKED, PENDING, APPROVED, CHANGES_REQUESTED, DISMISSED, UNKNOWN), populated only by an authoritative GitHub read;
- conflicts, missing evidence, source timestamps and typed fail-closed reason codes.

### Layout and interaction

- Infinite pan/zoom, viewport, lane positions, presentation grouping, visual add/remove of draft nodes, and tentative manual edges are presentation state only. They may be local layout preferences; they must never be interpreted as PR assignment, durable reviewer admission, or a worker/task database.
- An edge connects an implementation lane to any selected review lane. Show PROPOSED, AVAILABLE, CONFLICT, BLOCKED, INDEPENDENCE_UNVERIFIED, SELF_AUDIT, CROSS_WORKER_AUDIT, or SUPERSEDED from current evidence. Never auto-pick a reviewer or auto-wake one.
- Node/status views should show actor-witness freshness, resource validity, exact PR SHA, exact-head CI and review provenance. Missing source data shows UNKNOWN/BLOCKED, not a green default.
- Owner-only mutations are not enabled in this read-only MVP. A later separately authorized contract must use live Admin authentication, an exact-scope preview, explicit confirmation, single-use replay protection, authoritative GitHub readback and conflict checks. Its canonical assignment/review ledger stays GitHub, not canvas storage.
- Do not surface raw session tokens, GitHub tokens, private key material, cookies, ChatGPT messages, or unredacted browser content on nodes or issue/PR comments.

Suggested presentation-only JSON view model (not an endpoint or authorization record):

    {
      "version": "bke.command-canvas.view.v1",
      "source_status": "VERIFIED_CURRENT | STALE | UNKNOWN",
      "observed_at_ms": 1800000000000,
      "nodes": [
        { "lane_id": "F1", "kind": "EXECUTION", "x": 0, "y": 0, "layout_only": true },
        { "lane_id": "C2", "kind": "REVIEW", "x": 640, "y": 0, "layout_only": true }
      ],
      "edges": [
        { "from_lane_id": "F1", "to_lane_id": "C2", "state": "PROPOSED", "authority": "NONE" }
      ]
    }

## 4. Existing-source boundaries

- src/dashboard.js already validates bounded GitHub PR projections, head SHA and worker-label conflicts. Reuse its projections rather than duplicate assignment policy in the canvas.
- src/admin-worker-assignments.js is a PREPRODUCTION-only authenticated read-side consumer. It checks platform Admin identity and parses the existing private GitHub App inventory as NON_ATOMIC_ENUMERATION, which is evidence only, not a lease. Do not promote it to atomic assignment authority.
- Worker cloudflare-relay/src/admin-assignment-inventory.js is the existing private GitHub App inventory source; do not create another token broker or assignment database.
- CC #61/#62/#64/#68/#71 remain unmerged source-only foundations. Do not import their code. CC #66 remains blocked on genuine server-verified current-session/resource authority. Worker #90 remains quarantined; Worker #145 is separately owned.

## 5. Acceptance boundary

Tests for src/fc-lane-identity-contract.js prove strict schema behavior, witness freshness-shape, actor separation and exact-head classification using deterministic fixtures. They do not prove signatures, physical device identity, independent live sessions, a deployed resolver, GitHub-side atomicity or actual independent review. Keep runtime wiring, Canvas UI implementation, live owner actions, Cloudflare changes and production locked for separate explicit intents.
