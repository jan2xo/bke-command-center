# BKE Licensing 0.10.0 — ChatOps control and immutable GitHub release (verified checkpoint)

**As of:** 2026-11-12 (PHT)  
**Evidence owner:** `jan2xo/bke-libraries-typescript` GitHub source, CI and release API; final cross-repo ledger in `jan2xo/bke-digital-solutions` [issue #340](https://github.com/jan2xo/bke-digital-solutions/issues/340#issuecomment-6816998085).  
**Record type:** historical, read-only cross-repo certification/release checkpoint. This page does **not** grant BKE Command Center any release, signing, user, or production authority.

## Verified release status

| Evidence | Independently verified snapshot |
| --- | --- |
| Exact GitHub Release | [`licensing-v0.10.0`](https://github.com/jan2xo/bke-libraries-typescript/releases/tag/licensing-v0.10.0) |
| GitHub Release ID | `442576730` |
| Native GitHub release state | `draft=false`, **`immutable=true`**, four uploaded assets; published `2026-11-12T06:54:27Z` |
| Original release tag SHA | `b39fa5cc28c94c87a40a420e80f387c176564144` (unaltered) |
| Libraries `main` at checkpoint | `9beba07c4faa3d829673120e1f053177543bf5ee` (not a permanent current-head assertion) |
| Original certified producer run | [`43153573142`](https://github.com/jan2xo/bke-libraries-typescript/actions/runs/43153573142), source `d6b0159d9c22e0f9e468040777ea4591953c89f6` |
| Tarball | `bke-licensing-0.10.0.tgz`, 29,719 bytes |
| Tarball SHA-256 | `4d2f8e4295effcfd4aa3b6492944e8dbba3ec75e86c83727a30daa74e4f75d60` |
| Final recovery workflow | [`43171383139`](https://github.com/jan2xo/bke-libraries-typescript/actions/runs/43171383139), **SUCCESS** |
| Release/activation boundary | GitHub release **published**. npm package **not published**; DS signing, Agent/Launcher E2E and production **not activated**. |

The four exact released assets are (1) the original `.tgz`, (2) its `.sha256`, (3) `licensing-package-provenance.json`, and (4) `licensing-release-readiness.json`. The recovery run compared the original archive bytes against GitHub server-side asset SHA-256 values; the post-publication API read-back reported an immutable published release. The recovery did not rebuild, replace, retag or upload a second copy.

## GitHub ChatOps — observed operational control

The connected GitHub integration does not expose direct `workflow_dispatch` or repository-admin settings. Instead, owner-authorized actions use the dedicated [Libraries control issue #100](https://github.com/jan2xo/bke-libraries-typescript/issues/100):

```text
Explicit release/certification intent
→ GitHub-connected owner comment on one pinned control issue
→ cheap issue_comment.created router re-fetches authoritative comment/issue/main
→ verify owner account ID + exact issue ID + unedited fresh command + exact SHA
→ scoped actions:write dispatches an allowlisted workflow_dispatch
→ authorized workflow independently checks immutable archive, tag and evidence
→ GitHub software-release authority (where explicitly approved)
→ independent remote state read-back
```

The router is deliberately small, with job-scoped `contents:read`, `issues:read` and `actions:write`. The privileged publication/recovery job owns its own narrowly scoped `contents:write` permission and independently reauthenticates the owner comment before mutation. No arbitrary workflow ID, terminal command or generic repository-write permission is accepted from a comment. A contributor's ability to comment **never** grants release authority.

**Verified integration and source evidence:**

- [PR #101](https://github.com/jan2xo/bke-libraries-typescript/pull/101): owner-authenticated ChatOps source implementation, exact-head policy guard [#43168472549](https://github.com/jan2xo/bke-libraries-typescript/actions/runs/43168472549) PASS, SHA-locked merged.
- [Owner readiness comment](https://github.com/jan2xo/bke-libraries-typescript/issues/100#issuecomment-6816529147) → [router #43168697283](https://github.com/jan2xo/bke-libraries-typescript/actions/runs/43168697283) PASS → [read-only readiness #43168709538](https://github.com/jan2xo/bke-libraries-typescript/actions/runs/43168709538) PASS on original release-target exact SHA.
- [Owner publication comment](https://github.com/jan2xo/bke-libraries-typescript/issues/100#issuecomment-6816626228) → [router #43169339999](https://github.com/jan2xo/bke-libraries-typescript/actions/runs/43169339999) PASS → [publisher #43169356241](https://github.com/jan2xo/bke-libraries-typescript/actions/runs/43169356241) failed *after* creation of the correct tag/draft and upload of all four assets, but **before publication**, at a draft-invisible tag-based `gh release download` (HTTP 404). This was not a successful release claim.
- [Recovery PR #102](https://github.com/jan2xo/bke-libraries-typescript/pull/102) and [permission ownership repair PR #103](https://github.com/jan2xo/bke-libraries-typescript/pull/103) were separately exact-head certified and SHA-locked merged. First recovery router received HTTP 403 when trying to read a private draft under a read-only token; the fix moved that check to the separately authorized write-scoped recovery workflow.
- [Fresh owner recovery comment](https://github.com/jan2xo/bke-libraries-typescript/issues/100#issuecomment-6816952403) → [router #43171366098](https://github.com/jan2xo/bke-libraries-typescript/actions/runs/43171366098) PASS → [final recovery #43171383139](https://github.com/jan2xo/bke-libraries-typescript/actions/runs/43171383139) PASS. The recovery verified exact owner intent, original failed stage steps, the existing tag, **draft release ID 442576730**, four unchanged asset IDs/digests/bytes, then published **only** the existing draft. Final GitHub API returned `immutable=true`.
- [Final immutable release checkpoint](https://github.com/jan2xo/bke-digital-solutions/issues/340#issuecomment-6816998085) is the durable complete exact-evidence ledger. The detailed narrative/decision record is in [Notion: BKE GitHub ChatOps Release Control](https://app.notion.com/p/4169faa6ec14818fbac1f6a533533d20).

## Security controls — distinguish reported settings from GitHub-proven facts

| Layer | Boundary | Evidence level |
| --- | --- | --- |
| GitHub commenting restriction | Owner reports restricting issue/PR comments to collaborators. Reduces the outsider input surface while active, but may expire/be adjusted; do not rely on it for sole authorization. | **OWNER-REPORTED**, repository setting/duration not independently inspected |
| ChatOps authorization | Only owner `jan2xo` GitHub user ID `163499503`, exact control issue ID `6344112785`, matching current head, fresh unedited exact comment and allowlisted version/operation. | **IMPLEMENTED and LIVE TESTED** through routed readiness and release |
| Publication workflow | Separate `workflow_dispatch`, independent authorization, original archive SHA/provenance, tag/draft collision refusal and no-clobber recovery; no implicit heavy CI. | **IMPLEMENTED and VERIFIED** for Licensing 0.10.0 |
| GitHub native release immutability | Published release reports `immutable=true`; original tag and all four assets preserved. Repo-admin setting cannot be toggled or read directly using this GitHub connector. | **LIVE GITHUB RELEASE VERIFIED**; administrative setting separately owner-confirmed |

**Important:** A collaborator-only interaction restriction is defense in depth. It is not a substitute for identity authorization, exact-head certification, or a guarded, narrowly scoped release workflow.

## Command Center ownership and next engineering intent

BKE Command Center's live UI today is a read-first, GitHub-derived **PREPRODUCTION** view. This note is **documentation only**: no new UI route, database, release API proxy, workflow dispatcher, token/secret, Cloudflare deployment or runtime status badge is introduced. It does not assert that a new Licensing tile or dashboard integration exists.

The next separate product engineering intent belongs to **Digital Solutions**, not Command Center: pin the published immutable `@bke/licensing 0.10.0` archive and its SHA-256, implement authorized Ed25519 JWS issuance with key custody/rotation, transactional `ISSUED` audit and minimum complete exact-head certification. Then Licensing Agent enforcement and Launcher UX are independently owned consumer integration intents.

**Locked until separately authorized:** production DB/signing/deployment, real PayMongo/Resend, npm publication, installer/catalog release activation, force push. All stored SHAs are historical checkpoints; re-read current GitHub state before taking action.
