import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { validateNitroGate, runGate } from "../scripts/nitro-gate.mjs";

const HEAD = "a".repeat(40);
const OLD = "b".repeat(40);
const repository = "jan2xo/bke-command-center";
const branch = "nitro/failure-visibility";
const make = () => ({
  repository, prNumber: 12, expectedHead: HEAD, runHead: HEAD,
  runBranch: branch,
  pr: {
    number: 12, state: "open", merged: false,
    base: { ref: "main", repo: { full_name: repository } },
    head: { ref: branch, sha: HEAD, repo: { full_name: repository } },
    labels: [{ name: "bke-ci:nitro" }],
    body: "**Engineering mode:** `NITRO`",
  },
  commits: [
    { sha: OLD, commit: { message: "feat: add detection [skip ci]" } },
    { sha: HEAD, commit: { message: "test: complete scope [skip ci]" } },
  ],
});

test("exact Nitro merge gate accepts only matching PR/branch/commit chain", () => {
  assert.deepEqual(validateNitroGate(make()), { ok: true, faults: [] });
});

for (const [description, mutate, reason] of [
  ["wrong repository", (x) => { x.repository = "other/repo"; }, "UNEXPECTED_REPOSITORY"],
  ["wrong number", (x) => { x.prNumber = 99; }, "PR_NOT_OPEN"],
  ["closed PR", (x) => { x.pr.state = "closed"; }, "PR_NOT_OPEN"],
  ["wrong base", (x) => { x.pr.base.ref = "develop"; }, "PR_REPOSITORY_OR_BASE_INVALID"],
  ["cross-repo PR", (x) => { x.pr.head.repo.full_name = "attacker/repo"; }, "PR_REPOSITORY_OR_BASE_INVALID"],
  ["normal branch", (x) => { x.pr.head.ref = "feat/change"; x.runBranch = "feat/change"; }, "NITRO_HEAD_BRANCH_MISMATCH"],
  ["dispatch on main", (x) => { x.runBranch = "main"; }, "NITRO_HEAD_BRANCH_MISMATCH"],
  ["stale PR source head", (x) => { x.pr.head.sha = OLD; }, "STALE_EXACT_HEAD"],
  ["stale workflow head", (x) => { x.runHead = OLD; }, "STALE_EXACT_HEAD"],
  ["bad explicit SHA", (x) => { x.expectedHead = "bad"; }, "INVALID_SHA"],
  ["mode label missing", (x) => { x.pr.labels = []; }, "NITRO_MODE_NOT_EXPLICIT"],
  ["mode labels contradictory", (x) => { x.pr.labels.push({ name: "bke-ci:normal" }); }, "NITRO_MODE_NOT_EXPLICIT"],
  ["mode ledger missing", (x) => { x.pr.body = "Engineering mode: NORMAL"; }, "NITRO_MODE_NOT_EXPLICIT"],
  ["head skip marker missing", (x) => { x.commits[1].commit.message = "oops"; }, "NITRO_SKIP_COMMIT_CHAIN_INVALID"],
  ["earlier skip marker missing", (x) => { x.commits[0].commit.message = "oops"; }, "NITRO_SKIP_COMMIT_CHAIN_INVALID"],
  ["commit order/head mismatch", (x) => { x.commits.reverse(); }, "NITRO_SKIP_COMMIT_CHAIN_INVALID"],
  ["missing commits", (x) => { x.commits = []; }, "NITRO_SKIP_COMMIT_CHAIN_INVALID"],
  ["page cap reached", (x) => { x.commits = Array(100).fill({sha:HEAD,commit:{message:"[skip ci]"}}); }, "NITRO_SKIP_COMMIT_CHAIN_INVALID"],
  ["unknown labels malformed", (x) => { x.pr.labels = [{name:null}]; }, "NITRO_MODE_NOT_EXPLICIT"],
]) {
  test("Nitro merge gate fails closed: " + description, () => {
    const x = make();
    mutate(x);
    const result = validateNitroGate(x);
    assert.equal(result.ok, false);
    assert.ok(result.faults.includes(reason), JSON.stringify(result));
  });
}

test("manual dispatcher rejects invalid/no GitHub auth before making any network call", async () => {
  await assert.rejects(runGate({
    GITHUB_REPOSITORY: repository, NITRO_PR_NUMBER: "12",
    NITRO_EXPECTED_HEAD: HEAD, NITRO_RUN_HEAD: HEAD, NITRO_RUN_BRANCH: branch,
    GITHUB_TOKEN: "",
  }), /NITRO_GATE_INPUT_INVALID/);
});

test("NORMAL pull_request and main push events stay, Nitro dispatch is separate", () => {
  const yaml = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.match(yaml, /^  pull_request:$/m);
  assert.match(yaml, /^  push:\n    branches: \[main\]$/m);
  assert.match(yaml, /^  workflow_dispatch:$/m);
  assert.match(yaml, /if: github.event_name == 'workflow_dispatch'/);
  assert.match(yaml, /run: node scripts\/nitro-gate\.mjs/);
  assert.match(yaml, /NITRO_RUN_HEAD: \$\{\{ github\.sha \}\}/);
  assert.match(yaml, /NITRO_RUN_BRANCH: \$\{\{ github\.ref_name \}\}/);
  assert.match(yaml, /^      - run: npm ci$/m);
  assert.match(yaml, /^      - run: npm test$/m);
  assert.match(yaml, /^      - run: npm run check$/m);
  assert.match(yaml, /^      - run: npm run cloudflare:dry-run$/m);
  assert.doesNotMatch(yaml, /npm run cloudflare:deploy|wrangler deploy --env preproduction(?! --dry-run)/);
});
