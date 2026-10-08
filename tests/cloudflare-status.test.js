import test from "node:test";
import assert from "node:assert/strict";
import { normalizeCloudflareStatus, unknownCloudflareStatus, cloudflarePublicStatus } from "../src/cloudflare-status.js";
import { normalizeFailureVisibility, renderFailureVisibility } from "../src/failure-visibility.js";
import { dashboardState, renderDashboard } from "../src/dashboard.js";

const known={page:{id:"yh6f0r4529hb",updated_at:"2026-10-08T13:40:00Z"},
  status:{indicator:"major",description:"Partial System Outage"}};
const repo={full_name:"jan2xo/bke-worker",default_branch:"main"};
const run={id:88,name:"Cloudflare relay CI",head_sha:"a".repeat(40),
  conclusion:"failure",status:"completed",updated_at:"2026-10-08T12:00:00Z"};
const make=()=>({
  repo:async()=>repo,openPullRequests:async()=>[],recentClosedPullRequests:async()=>[],
  recentWorkflowRuns:async()=>({workflow_runs:[run]}),
  cloudflarePlatformStatus:async()=>normalizeCloudflareStatus(known),
});

test("Cloudflare public status is a GLOBAL signal, not project Worker health",()=>{
  const data=normalizeCloudflareStatus(known);
  assert.equal(data.state,"MAJOR_INCIDENT");
  assert.equal(data.scope,"global_cloudflare_platform_not_account_or_worker");
  assert.equal(data.worker_runtime,"UNKNOWN");
  assert.equal(data.relay_connection,"NOT_MEASURED");
  const rendered=renderFailureVisibility(normalizeFailureVisibility({workflow_runs:[run]},repo.full_name),data);
  assert.match(rendered,/Published global status: major incident/);
  assert.match(rendered,/Worker runtime: <b>UNKNOWN/);
  assert.match(rendered,/not proof this Worker is unhealthy/);
});
test("normal operational global state does not imply local Worker healthy",()=>{
  const d=normalizeCloudflareStatus({...known,status:{indicator:"none",description:"All Systems Operational"}});
  assert.equal(d.state,"OPERATIONAL");
  assert.equal(d.worker_runtime,"UNKNOWN");
});
for(const [description,bad] of [
  ["missing page id",{page:{updated_at:"2026-10-08T13:40:00Z"},status:known.status}],
  ["invalid indicator",{page:known.page,status:{indicator:"unknown",description:"X"}}],
  ["bad timestamp",{page:{...known.page,updated_at:"nonsense"},status:known.status}],
  ["missing description",{page:known.page,status:{indicator:"major"}}],
  ["oversized description",{page:known.page,status:{indicator:"major",description:"x".repeat(300)}}],
]) {
  test("reject malformed global provider status: "+description,()=>{
    assert.throws(()=>normalizeCloudflareStatus(bad),/CLOUDFLARE_PUBLIC_STATUS_INVALID/);
  });
}
test("provider output escaped, no untrusted raw html",()=>{
  const d=normalizeCloudflareStatus({...known,status:{indicator:"major",
    description:'<img src=x onerror="alert()">'}});
  const rendered=renderFailureVisibility(normalizeFailureVisibility({workflow_runs:[run]},repo.full_name),d);
  assert.match(rendered,/&lt;img/);
  assert.doesNotMatch(rendered,/<img/);
});
test("Cloudflare outage never suppresses GitHub Actions failure overview",async()=>{
  const gh={...make(),cloudflarePlatformStatus:async()=>{throw Error("offline_secret_token");}};
  const d=await dashboardState(gh);
  assert.equal(d.failure_visibility.status,"FAILURES_OBSERVED");
  assert.deepEqual(d.cloudflare_platform,unknownCloudflareStatus());
  assert.doesNotMatch(JSON.stringify(d),/offline_secret_token/);
  assert.match(renderDashboard(d),/Published global status: UNKNOWN/);
});
test("GitHub Actions outage never suppresses independent Cloudflare global status",async()=>{
  const gh={...make(),recentWorkflowRuns:async()=>{throw Error("api unavailable");}};
  const d=await dashboardState(gh);
  assert.equal(d.failure_visibility.status,"UNKNOWN");
  assert.equal(d.cloudflare_platform.state,"MAJOR_INCIDENT");
});
test("only two extra provider calls for homepage; never per-run job or logs",async()=>{
  const calls=[];
  const gh={...make(),
    recentWorkflowRuns:async()=>{calls.push("github_runs");return {workflow_runs:[run]};},
    cloudflarePlatformStatus:async()=>{calls.push("cloudflare_public");return normalizeCloudflareStatus(known);},
    workflowJobs:async()=>{throw Error("job fanout prohibited");},
    jobFailureExcerpt:async()=>{throw Error("logs prohibited");},
  };
  const d=await dashboardState(gh);
  assert.equal(d.failure_visibility.failed_run_count,1);
  assert.equal(d.cloudflare_platform.state,"MAJOR_INCIDENT");
  assert.deepEqual(calls.sort(),["cloudflare_public","github_runs"]);
});
test("public Cloudflare HTTP fetch has timeout, no credentials, and normalized result",async()=>{
  const prev=globalThis.fetch;
  try {
    globalThis.fetch=async (url,opt)=>{
      assert.equal(url,"https://www.cloudflarestatus.com/api/v2/status.json");
      assert.equal(opt.headers.Accept,"application/json");
      assert.ok(opt.signal,"must bound fetch");
      assert.equal(opt.headers.Authorization,undefined);
      return {ok:true,json:async()=>known};
    };
    assert.equal((await cloudflarePublicStatus()).state,"MAJOR_INCIDENT");
  } finally {globalThis.fetch=prev;}
});
