import test from "node:test";
import assert from "node:assert/strict";
import {
  assignmentFromPullRequest,
  correlateCertificationRuns,
  collectEvidence,
  createGitHubAdapter,
} from "../src/github.js";
import { certificationSummary, buildFailureCapsule } from "../src/core.js";

const exactHead = "51d7e2655d66f75e8d9402e7f849544a7028f90f";
const mainHead = "7fe9c19924dbf957591cc7ae8085b461c7800ec6";
const pr = {
  number: 82,
  title: "task #81: feat(worker): add durable task checklist + 30-minute continuation lease",
  state: "open",
  labels: [],
  head: { sha: exactHead, ref: "bke/task-81" },
};
const comments = [
  { created_at: "2026-10-08T04:57:51Z", body: `BKE RELAY — self_synchronize_suppressed • head=${exactHead}`, user: { login: "bke-worker[bot]" } },
  { created_at: "2026-10-08T04:58:10Z", body: "/certify core relay android", user: { login: "jan2xo" }, html_url: "https://github.test/comment" },
];
const commits = [{ sha: exactHead, commit: { committer: { date: "2026-10-08T04:57:49Z" } } }];
const run = {
  id: 37730031840,
  name: "Intent Certification",
  display_title: pr.title,
  event: "issue_comment",
  actor: { login: "jan2xo" },
  status: "completed",
  conclusion: "failure",
  head_sha: mainHead,
  pull_requests: [],
  created_at: "2026-10-08T04:58:12Z",
  updated_at: "2026-10-08T05:01:47Z",
  html_url: "https://github.test/run/37730031840",
};
const jobs = [
  { id: 1, name: "Cloudflare durable relay", conclusion: "failure", completed_at: "2026-10-08T04:58:52Z", html_url: "https://github.test/job/1", steps: [{ name: "Verify Cloudflare relay protocol and config", conclusion: "failure", completed_at: "2026-10-08T04:58:49Z" }] },
  { id: 2, name: "Core orchestration + GitHub boundary", conclusion: "success", completed_at: "2026-10-08T04:59:00Z", html_url: "https://github.test/job/2", steps: [] },
  { id: 3, name: "Android Gecko Worker probe", conclusion: "success", completed_at: "2026-10-08T05:01:40Z", html_url: "https://github.test/job/3", steps: [] },
  { id: 4, name: "Published server + operator surface", conclusion: "skipped", completed_at: "2026-10-08T04:58:43Z", html_url: "https://github.test/job/4", steps: [] },
  { id: 5, name: "Required certification", conclusion: "failure", completed_at: "2026-10-08T05:01:46Z", html_url: "https://github.test/job/5", steps: [{ name: "Require requested exact-head proof", conclusion: "failure" }] },
];

test("PR with no worker label is UNASSIGNED, and multiple worker labels conflict", () => {
  const unassigned = assignmentFromPullRequest(pr);
  assert.equal(unassigned.assignment_state, "UNASSIGNED");
  assert.equal(unassigned.worker_id, null);
  assert.equal(unassigned.pr_state, "OPEN");
  const conflict = assignmentFromPullRequest({ ...pr, labels: [{ name: "bke-worker:a" }, { name: "bke-worker:b" }] });
  assert.equal(conflict.assignment_state, "CONFLICT");
  assert.equal(conflict.worker_id, null);
});

test("issue_comment run is correlated to PR exact head from durable PR history, not run.head_sha", () => {
  const result = correlateCertificationRuns({ pr, comments, commits, runs: [run], exactHead });
  assert.equal(result.length, 1);
  assert.equal(result[0].source_sha, exactHead);
  assert.equal(result[0].head_sha, mainHead);
});

test("latest same-head certification attempt is authoritative and fan-out stays bounded", async () => {
  let jobCalls = 0;
  const olderRun = { ...run, id: 37730000000, created_at: "2026-10-08T04:58:11Z", conclusion: "failure" };
  const gh = {
    checks: async () => ({ check_runs: [{ name: "Intent + CI policy", head_sha: exactHead, conclusion: "success" }] }),
    issueComments: async () => comments,
    pullCommits: async () => commits,
    workflowRuns: async (event) => ({ workflow_runs: event === "issue_comment" ? [olderRun, run] : [] }),
    workflowJobs: async (runId) => { jobCalls += 1; assert.equal(runId, olderRun.id); return { jobs }; },
  };
  const evidence = await collectEvidence(gh, pr, exactHead);
  assert.equal(jobCalls, 1);
  assert.equal(evidence.certificationRuns.length, 1);
});

test("PR #82-shaped live evidence cannot false-green from generic PR Guard checks", async () => {
  let jobCalls = 0;
  const gh = {
    checks: async () => ({ check_runs: [{ name: "Intent + CI policy", head_sha: exactHead, conclusion: "success" }] }),
    issueComments: async () => comments,
    pullCommits: async () => commits,
    workflowRuns: async (event) => ({ workflow_runs: event === "issue_comment" ? [run] : [] }),
    workflowJobs: async (runId) => { jobCalls += 1; assert.equal(runId, run.id); return { jobs }; },
  };
  const evidence = await collectEvidence(gh, pr, exactHead);
  const certification = certificationSummary({ exactHead, requiredEvidence: evidence.required, observedChecks: evidence.checks });
  const capsule = buildFailureCapsule({ repo: "jan2xo/bke-worker", pr_number: 82, exact_head: exactHead, worker_id: null, evidence: evidence.jobs });
  assert.equal(jobCalls, 1, "only the correlated certification run should fan out to jobs");
  assert.equal(certification.state, "FAILED");
  assert.equal(capsule.boundary, "cloudflare-relay");
  assert.match(capsule.summary, /Verify Cloudflare relay protocol and config/);
  assert.equal(capsule.downstream[0].boundary, "certification");
  assert.deepEqual(capsule.unaffected_boundaries.sort(), ["android", "core"]);
  assert.equal(capsule.evidence[0].failure_excerpt_url, "/api/pr/82/evidence/job/1");
});

test("in-progress correlated certification is PENDING before the required gate appears", async () => {
  const pendingRun = { ...run, status: "in_progress", conclusion: null };
  const gh = {
    checks: async () => ({ check_runs: [] }),
    issueComments: async () => comments,
    pullCommits: async () => commits,
    workflowRuns: async () => ({ workflow_runs: [pendingRun] }),
    workflowJobs: async () => ({ jobs: [{ id: 2, name: "Core orchestration + GitHub boundary", status: "in_progress", conclusion: null, steps: [] }] }),
  };
  const evidence = await collectEvidence(gh, pr, exactHead);
  const certification = certificationSummary({ exactHead, requiredEvidence: evidence.required, observedChecks: evidence.checks });
  assert.equal(certification.state, "PENDING");
});

test("job log retrieval follows GitHub redirect, omits auth on signed URL, bounds and redacts excerpt", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), headers: options.headers || {} });
    if (String(url).startsWith("https://api.github.com/")) {
      return new Response(null, { status: 302, headers: { location: "https://logs.example.test/job.txt" } });
    }
    return new Response("setup\nnot ok 4 - protocol\nAuthorization: Bearer TOPSECRET\nAssertionError: expected recovered\n", { status: 200 });
  };
  try {
    const adapter = createGitHubAdapter({ GITHUB_TOKEN: "read-token", GITHUB_OWNER: "jan2xo", GITHUB_REPO: "bke-worker" });
    const result = await adapter.jobFailureExcerpt(99);
    assert.equal(result.found, true);
    assert.match(result.excerpt.join("\n"), /not ok 4/);
    assert.doesNotMatch(result.excerpt.join("\n"), /TOPSECRET/);
    assert.equal(new Headers(calls[0].headers).get("Authorization"), "Bearer read-token");
    assert.equal(new Headers(calls[1].headers).has("Authorization"), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
