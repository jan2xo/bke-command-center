import test from "node:test";
import assert from "node:assert/strict";
import { normalizeFailureVisibility, unknownFailureVisibility, renderFailureVisibility } from "../src/failure-visibility.js";
import { dashboardState, renderDashboard } from "../src/dashboard.js";
import { handleRequest } from "../src/index.js";

const REPO = "jan2xo/bke-worker";
const SHA = "f73c16af2d89d4aeba266a7e8adb5af468c08a60";
const actionRun = (id, overrides={}) => ({
  id, name: "Intent Certification", status:"completed", conclusion:"failure",
  head_sha: SHA, updated_at:"2026-10-08T19:00:00Z",
  ...overrides,
});
const base = () => ({
  repo: async () => ({full_name:REPO,default_branch:"main"}),
  openPullRequests: async () => [],
  recentClosedPullRequests: async () => [],
});
test("known GitHub Actions failure is observable, but Cloudflare remains UNKNOWN", () => {
  const data = normalizeFailureVisibility({
    workflow_runs: [
      actionRun(1001, {name:"Cloudflare relay integration"}),
      actionRun(1002, {conclusion:"success"}),
    ],
  }, REPO);
  assert.equal(data.status, "FAILURES_OBSERVED");
  assert.equal(data.failed_run_count,1);
  assert.equal(data.pending_run_count,0);
  assert.equal(data.cloudflare_runtime,"UNKNOWN");
  assert.match(data.failures[0].boundary,/Relay/);
  assert.equal(data.failures[0].causal_state,"UNVERIFIED");
  assert.equal(data.failures[0].url,"https://github.com/jan2xo/bke-worker/actions/runs/1001");
});
test("no failure in sampled window does not establish overall health", () => {
  const result = normalizeFailureVisibility({workflow_runs:[actionRun(1,{conclusion:"success"})]},REPO);
  assert.equal(result.status,"NO_FAILURES_IN_SAMPLE");
  assert.equal(result.scope,"latest_8_workflow_runs");
  assert.equal(result.cloudflare_runtime,"UNKNOWN");
  assert.match(renderFailureVisibility(result),/does not establish system-wide health/);
});
test("zero workflow runs is UNKNOWN, not successful CI", () => {
  const result = normalizeFailureVisibility({workflow_runs:[]},REPO);
  assert.equal(result.status,"UNKNOWN");
  assert.equal(result.fetched_run_count,0);
  assert.equal(result.reason,"NO_WORKFLOW_RUNS_OBSERVED");
});
test("pending runs are separate from failures", () => {
  const result=normalizeFailureVisibility({workflow_runs:[actionRun(2,{status:"in_progress",conclusion:null})]},REPO);
  assert.equal(result.status,"PENDING_RUNS");
  assert.equal(result.pending_run_count,1);
  assert.equal(result.failed_run_count,0);
});
test("other failed workflow cannot be attributed to Cloudflare service",()=>{
  const d=normalizeFailureVisibility({workflow_runs:[actionRun(3,{name:"Core tests"})]},REPO);
  assert.equal(d.failures[0].boundary,"GitHub Actions workflow");
});
for (const [description,payload] of [
  ["too many runs",{workflow_runs:Array.from({length:9},(_,i)=>actionRun(i+1))}],
  ["not an array",{workflow_runs:{}}],
  ["duplicate IDs",{workflow_runs:[actionRun(5),actionRun(5)]}],
  ["malformed IDs",{workflow_runs:[actionRun("5")]}],
  ["invalid SHA",{workflow_runs:[actionRun(6,{head_sha:"bad"})]}],
  ["invalid workflow name",{workflow_runs:[actionRun(7,{name:""})]}],
  ["unknown conclusion",{workflow_runs:[actionRun(8,{conclusion:"mystery"})]}],
  ["non-completed run with conclusion",{workflow_runs:[actionRun(9,{status:"in_progress",conclusion:"failure"})]}],
  ["completed run with null conclusion",{workflow_runs:[actionRun(10,{conclusion:null})]}],
]) {
  test("fail closed on "+description,()=>{
    assert.throws(()=>normalizeFailureVisibility(payload,REPO),/GITHUB_FAILURE_/);
  });
}
test("unknown/unavailable GitHub Actions feed is explicit and safe",async()=>{
  let calls=0;
  const gh={...base(),recentWorkflowRuns:async()=>{calls++;throw new Error("secret-do-not-leak");}};
  const state=await dashboardState(gh);
  assert.equal(state.metrics.open_prs,0);
  assert.equal(state.failure_visibility.status,"UNKNOWN");
  assert.equal(calls,1);
  assert.doesNotMatch(JSON.stringify(state),/secret-do-not-leak/);
  assert.match(renderDashboard(state),/Failure evidence unavailable/);
});
test("overview fetches one bounded Actions page, no jobs, logs or per PR fanout",async()=>{
  const calls=[];
  const gh={...base(),recentWorkflowRuns:async()=>{calls.push("runs");return {workflow_runs:[actionRun(11)]};},
    workflowJobs:async()=>{throw new Error("job fanout not allowed");},
    jobFailureExcerpt:async()=>{throw new Error("logs not allowed");}};
  const state=await dashboardState(gh);
  assert.deepEqual(calls,["runs"]);
  assert.equal(state.failure_visibility.failed_run_count,1);
  const response=await handleRequest(new Request("https://command.test/api/overview"),
    {BKE_PREPRODUCTION:"true"},()=>gh);
  assert.equal(response.status,200);
  assert.equal(response.headers.get("cache-control"),"no-store");
  assert.equal((await response.json()).failure_visibility.failed_run_count,1);
});
test("dashboard escapes workflow names and uses constructed GitHub evidence URL",()=>{
  const d=normalizeFailureVisibility({workflow_runs:[
    actionRun(13,{name:'<img src=x onerror="evil()">'}),
  ]},REPO);
  const html=renderFailureVisibility(d);
  assert.match(html,/&lt;img/);
  assert.doesNotMatch(html,/<img/);
  assert.match(html,/href="https:\/\/github.com\/jan2xo\/bke-worker\/actions\/runs\/13"/);
  assert.doesNotMatch(html,/javascript:/);
});
test("missing GitHub Actions adapter is UNKNOWN, not falsely healthy",async()=>{
  const data=await dashboardState(base());
  assert.deepEqual(data.failure_visibility,unknownFailureVisibility());
});
