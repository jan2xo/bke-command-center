import test from "node:test";
import assert from "node:assert/strict";
import { prState, renderPr, handleRequest, workerState } from "../src/index.js";

const exactHead = "51d7e2655d66f75e8d9402e7f849544a7028f90f";
const pr = {
  number: 82,
  title: "task #81: feat(worker): add durable task checklist + 30-minute continuation lease",
  state: "open",
  draft: true,
  html_url: "https://github.test/pr/82",
  labels: [],
  head: { sha: exactHead, ref: "bke/task-81" },
  base: { repo: { full_name: "jan2xo/bke-worker" } },
};
const comments = [
  { created_at: "2026-10-08T04:57:51Z", body: `BKE RELAY — sent • head=${exactHead}`, user: { login: "bke-worker[bot]" } },
  { created_at: "2026-10-08T04:58:10Z", body: "/certify core relay android", user: { login: "jan2xo" } },
];
const run = {
  id: 37730031840,
  name: "Intent Certification",
  display_title: pr.title,
  event: "issue_comment",
  actor: { login: "jan2xo" },
  status: "completed",
  conclusion: "failure",
  head_sha: "7fe9c19924dbf957591cc7ae8085b461c7800ec6",
  created_at: "2026-10-08T04:58:12Z",
  updated_at: "2026-10-08T05:01:47Z",
};

function fakeAdapter(overrides = {}) {
  return {
    repo: async () => ({ full_name: "jan2xo/bke-worker", default_branch: "main" }),
    openPullRequests: async () => [pr],
    pullRequest: async () => pr,
    checks: async () => ({ check_runs: [{ name: "Intent + CI policy", head_sha: exactHead, conclusion: "success" }] }),
    issueComments: async () => comments,
    pullCommits: async () => [{ sha: exactHead, commit: { committer: { date: "2026-10-08T04:57:49Z" } } }],
    workflowRuns: async () => ({ workflow_runs: [run] }),
    workflowJobs: async () => ({ jobs: [
      { id: 11, name: "Cloudflare durable relay", conclusion: "failure", completed_at: "2026-10-08T04:58:52Z", html_url: "https://github.test/job/11", steps: [{ name: "Verify Cloudflare relay protocol and config", conclusion: "failure" }] },
      { id: 12, name: "Core orchestration + GitHub boundary", conclusion: "success", completed_at: "2026-10-08T04:59:00Z", steps: [] },
      { id: 13, name: "Android Gecko Worker probe", conclusion: "success", completed_at: "2026-10-08T05:01:40Z", steps: [] },
      { id: 14, name: "Required certification", conclusion: "failure", completed_at: "2026-10-08T05:01:46Z", steps: [{ name: "Require requested exact-head proof", conclusion: "failure" }] },
    ] }),
    jobFailureExcerpt: async () => ({ found: true, truncated: false, excerpt: ["AssertionError: expected recovered"] }),
    ...overrides,
  };
}

test("worker state fails closed when one worker owns multiple open PRs", async () => {
  const assigned = { ...pr, labels: [{ name: "bke-worker:android-worker-a" }] };
  const state = await workerState({}, fakeAdapter({ openPullRequests: async () => [assigned, { ...assigned, number: 83 }] }));
  assert.equal(state.worker_state, "CONFLICT");
});

test("prState and rendered PR surface real causal/downstream/assignment semantics", async () => {
  const state = await prState({}, 82, fakeAdapter());
  assert.equal(state.certification.state, "FAILED");
  assert.equal(state.assignment.assignment_state, "UNASSIGNED");
  assert.equal(state.first_causal_failure.boundary, "cloudflare-relay");
  const page = renderPr(state);
  assert.match(page, /UNASSIGNED/);
  assert.match(page, /FAILED/);
  assert.match(page, /cloudflare-relay/);
  assert.match(page, /certification/);
  assert.match(page, /failure excerpt/);
});

test("API route emits normalized exact-head failure state", async () => {
  const response = await handleRequest(new Request("https://command.test/api/pr/82"), {}, () => fakeAdapter());
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.assignment.exact_head, exactHead);
  assert.equal(body.certification.state, "FAILED");
  assert.equal(body.first_causal_failure.boundary, "cloudflare-relay");
});

test("on-demand job evidence is scoped to correlated failure evidence for the PR", async () => {
  const adapter = fakeAdapter();
  const response = await handleRequest(new Request("https://command.test/api/pr/82/evidence/job/11"), {}, () => adapter);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.excerpt, ["AssertionError: expected recovered"]);
  const denied = await handleRequest(new Request("https://command.test/api/pr/82/evidence/job/999"), {}, () => adapter);
  assert.equal(denied.status, 404);
});
