import test from "node:test";
import assert from "node:assert/strict";
import { normalizeDashboardData, renderDashboard, dashboardState } from "../src/dashboard.js";
import { handleRequest } from "../src/index.js";

const SHA = "f73c16af2d89d4aeba266a7e8adb5af468c08a60";
const repo = { full_name: "jan2xo/bke-worker", default_branch: "main" };
const openPr = (number, labels = [], title = "Safe PR") => ({
  number, state: "open", draft: true, title, labels: labels.map((name) => ({ name })),
  head: { sha: SHA, ref: "bke/task-" + number },
  updated_at: "2026-10-08T10:00:00Z",
});
const closedPr = (number, mergedAt = "2026-10-08T10:00:00Z") => ({
  ...openPr(number), state: "closed", draft: false, merged_at: mergedAt,
});
const fake = (open = [], closed = [], overrides = {}) => ({
  repo: async () => repo,
  openPullRequests: async () => open,
  recentClosedPullRequests: async () => closed,
  ...overrides,
});

test("GitHub-derived empty dashboard has UNKNOWN runtime liveness", async () => {
  const data = await dashboardState(fake());
  assert.deepEqual(data.metrics, {
    open_prs: 0, assigned_prs: 0, unassigned_prs: 0, ownership_conflicts: 0,
  });
  assert.equal(data.liveness, "UNKNOWN");
  assert.equal(data.collection_scope.recent_closed_prs, 12);
  assert.equal(data.authority, "read_only_derived");
  assert.match(renderDashboard(data), /No open PRs/);
});

test("dashboard detects ownership conflicts across distinct PRs", () => {
  const state = normalizeDashboardData(repo, [
    openPr(11, ["bke-worker:worker-b"]),
    openPr(12, ["bke-worker:worker-b"]),
    openPr(13, ["bke-worker:worker-a"]),
    openPr(14, []),
    openPr(15, ["bke-worker:worker-b", "bke-worker:worker-c"]),
    openPr(16, ["bke-worker:INVALID_OWNERSHIP"]),
  ], [closedPr(82), closedPr(81, null)]);
  assert.deepEqual(state.metrics, {
    open_prs: 6, assigned_prs: 1, unassigned_prs: 1, ownership_conflicts: 4,
  });
  assert.equal(state.open_pull_requests.find((x) => x.number === 11).conflict_reason,
    "WORKER_OWNS_MULTIPLE_OPEN_PRS");
  assert.equal(state.open_pull_requests.find((x) => x.number === 15).conflict_reason,
    "AMBIGUOUS_PR_LABELS");
  assert.equal(state.recently_merged_sample.length, 1);
  assert.equal(state.recently_merged_sample[0].number, 82);
  assert.equal(state.liveness, "UNKNOWN");
});

test("assignment matching normalizes case without claiming online", () => {
  const data = normalizeDashboardData(repo,
    [openPr(40, ["BKE-WORKER:WORKER-A"])], []);
  assert.equal(data.open_pull_requests[0].worker_id, "worker-a");
  assert.equal(data.open_pull_requests[0].assignment_state, "ASSIGNED");
  assert.equal(data.liveness, "UNKNOWN");
});

test("dashboard rejects ambiguous page caps and invalid GitHub evidence", () => {
  assert.throws(() => normalizeDashboardData(repo, Array.from({ length: 100 },
    (_, i) => openPr(i + 1)), []), /COLLECTION_AMBIGUOUS/);
  assert.throws(() => normalizeDashboardData(repo, [], new Array(13).fill(closedPr(82))),
    /COLLECTION_AMBIGUOUS/);
  assert.throws(() => normalizeDashboardData(repo, [openPr(11), openPr(11)], []),
    /DUPLICATE_PR/);
  assert.throws(() => normalizeDashboardData(repo, [openPr(11, [] , "ok"),
    { ...openPr(20), head: { sha: null, ref: "broken" } }], []),
    /PR_EVIDENCE_INVALID/);
  assert.throws(() => normalizeDashboardData(repo, {}, []), /COLLECTION_AMBIGUOUS/);
  assert.throws(() => normalizeDashboardData({ full_name: "bad/repo/extra", default_branch: "main" }, [], []),
    /REPOSITORY_INVALID/);
});

test("real overview route is read-only, no-store, and escapes GitHub titles", async () => {
  let calls = 0;
  const adapter = fake([openPr(40, [], "<script>alert('x')</script>")], [closedPr(82)], {
    repo: async () => { calls += 1; return repo; },
    openPullRequests: async () => { calls += 1; return [openPr(40, [], "<script>alert('x')</script>")]; },
    recentClosedPullRequests: async () => { calls += 1; return [closedPr(82)]; },
  });
  const page = await handleRequest(new Request("https://command.test/"),
    { BKE_PREPRODUCTION: "true" }, () => adapter);
  assert.equal(page.status, 200);
  assert.equal(page.headers.get("Cache-Control"), "no-store");
  const html = await page.text();
  assert.match(html, /Engineering overview/);
  assert.match(html, /UNKNOWN/);
  assert.match(html, /href="\/pr\/40"/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>alert/);
  assert.equal(calls, 3, "overview must not fan out per PR or load job logs");

  const api = await handleRequest(new Request("https://command.test/api/overview"),
    { BKE_PREPRODUCTION: "true" }, () => fake([openPr(40)], [closedPr(82)]));
  assert.equal(api.headers.get("Cache-Control"), "no-store");
  assert.equal((await api.json()).metrics.open_prs, 1);
});

test("overview upstream outages fail closed without exposing sensitive details", async () => {
  const response = await handleRequest(new Request("https://command.test/api/overview"),
    { BKE_PREPRODUCTION: "true" }, () => fake([], [], {
      repo: async () => { throw new Error("GitHub token secret-must-not-leak"); },
    }));
  assert.equal(response.status, 502);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  const body = await response.text();
  assert.match(body, /GITHUB_EVIDENCE_UNAVAILABLE/);
  assert.doesNotMatch(body, /secret-must-not-leak/);
  const missing = await handleRequest(new Request("https://command.test/not-a-route"),
    { BKE_PREPRODUCTION: "true" }, () => fake());
  assert.equal(missing.status, 404);
});

test("default deployment is still LOCKED before evaluating adapter", async () => {
  const worker = (await import("../src/index.js")).default;
  const response = await worker.fetch(new Request("https://command.test/api/overview"), {});
  assert.equal(response.status, 503);
  assert.equal((await response.json()).state, "LOCKED");
});
