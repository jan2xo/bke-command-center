import test from "node:test";
import assert from "node:assert/strict";
import { normalizeGitHubQuota, githubQuotaState } from "../src/github-quota.js";
import { createGitHubAdapter } from "../src/github.js";
import { handleRequest, preproductionFetch } from "../src/index.js";

const quotas = { resources: { core: {
  limit: 5000, remaining: 4800, used: 200, reset: 1791500000,
}} };
const url = "https://cc.jl-bke.com/api/github-quota";

test("bounded public quota observation never confuses token presence with verified permissions", () => {
  const anonymous = normalizeGitHubQuota({resources:{core:{...quotas.resources.core,limit:60,remaining:20,used:40}}},false);
  assert.equal(anonymous.state,"OBSERVED");
  assert.equal(anonymous.credential,"ABSENT");
  assert.equal(anonymous.permission_scopes,"NOT_VERIFIED");
  assert.equal(anonymous.runtime_liveness,"UNKNOWN");
  const configured = normalizeGitHubQuota(quotas,true);
  assert.equal(configured.credential,"CONFIGURED");
  assert.equal(configured.core.limit,5000);
  assert.equal(configured.core.remaining,4800);
  assert.equal(configured.core.used,200);
  assert.match(configured.core.resets_at,/Z$/);
  assert.doesNotMatch(JSON.stringify(configured),/Bearer|token=|secret_text/);
});
for (const [name, payload] of [
  ["missing response",null],
  ["missing core",{resources:{}}],
  ["bad numeric",{resources:{core:{...quotas.resources.core,remaining:"4800"}}}],
  ["negative remaining",{resources:{core:{...quotas.resources.core,remaining:-1}}}],
  ["remaining more than limit",{resources:{core:{...quotas.resources.core,remaining:5001}}}],
  ["negative used",{resources:{core:{...quotas.resources.core,used:-1}}}],
  ["invalid limit",{resources:{core:{...quotas.resources.core,limit:0}}}],
  ["floating reset",{resources:{core:{...quotas.resources.core,reset:1.5}}}],
  ["date overflow",{resources:{core:{...quotas.resources.core,reset:9000000001}}}],
]) {
  test("quota normalization rejects "+name, () => {
    assert.throws(()=>normalizeGitHubQuota(payload), (e)=>
      e.category==="INVALID_RESPONSE" && e.boundary==="RATE_LIMIT_PROBE");
  });
}
test("quota route returns no-store authenticated-mode indication without secret value",async()=>{
  let n=0;
  const gh={rateLimit:async()=>{n++;return quotas;}};
  const response=await handleRequest(new Request(url),
    {GITHUB_TOKEN:"ghp_NOT_FOR_DISPLAY"},()=>gh);
  assert.equal(response.status,200);
  assert.equal(response.headers.get("cache-control"),"no-store");
  const result=await response.json();
  assert.equal(result.credential,"CONFIGURED");
  assert.equal(result.permission_scopes,"NOT_VERIFIED");
  assert.equal(result.core.remaining,4800);
  assert.equal(n,1);
  assert.doesNotMatch(JSON.stringify(result),/NOT_FOR_DISPLAY|ghp_/);
});
test("quota HTML page is human-readable, with no extra calls",async()=>{
  const gh={rateLimit:async()=>quotas};
  const response=await handleRequest(new Request("https://cc.jl-bke.com/github-quota"),
    {GITHUB_TOKEN:"hidden"},()=>gh);
  assert.equal(response.status,200);
  assert.equal(response.headers.get("cache-control"),"no-store");
  const html=await response.text();
  assert.match(html,/GitHub API budget/);
  assert.match(html,/4800/);
  assert.match(html,/Repository permissions:<\/b> NOT VERIFIED/);
  assert.doesNotMatch(html,/hidden|Authorization|Bearer /);
});
test("quota route fails closed with classified GitHub authorization error",async()=>{
  const original=globalThis.fetch;
  globalThis.fetch=async()=>new Response('{"message":"Bearer do-not-leak"}',{status:401});
  try {
    const adapter=createGitHubAdapter({GITHUB_TOKEN:"secret"});
    const response=await handleRequest(new Request(url),{},
      ()=>adapter);
    assert.equal(response.status,502);
    assert.equal(response.headers.get("cache-control"),"no-store");
    const data=await response.json();
    assert.equal(data.state,"UNKNOWN");
    assert.equal(data.failure_class,"ACCESS_DENIED");
    assert.equal(data.boundary,"RATE_LIMIT_PROBE");
    assert.doesNotMatch(JSON.stringify(data),/secret|do-not-leak/);
  } finally {globalThis.fetch=original;}
});
test("quota route fails closed on malformed GitHub rate payload",async()=>{
  const response=await handleRequest(new Request(url),{},
    ()=>({rateLimit:async()=>({resources:{core:{remaining:"secret"}}})}));
  assert.equal(response.status,502);
  const data=await response.json();
  assert.equal(data.failure_class,"INVALID_RESPONSE");
  assert.equal(data.boundary,"RATE_LIMIT_PROBE");
});
test("normal worker assignment view never triggers on-demand quota call",async()=>{
  let quotaCalls=0;
  const gh={
    repo:async()=>({full_name:"jan2xo/bke-worker",default_branch:"main"}),
    openPullRequests:async()=>[],
    rateLimit:async()=>{quotaCalls++;throw Error("must not be called");}
  };
  const response=await handleRequest(new Request("https://cc.jl-bke.com/worker"),{},()=>gh);
  assert.equal(response.status,200);
  assert.equal(quotaCalls,0);
});
test("PREPRODUCTION identity and Access latch reject unauthenticated and alternate hosts before quota probe",async()=>{
  const probe=async(req,env)=>preproductionFetch(req,env);
  const wrongEnv=await probe(new Request(url),{});
  assert.equal(wrongEnv.status,503);
  const missingAccess=await probe(new Request(url),{BKE_PREPRODUCTION:"true"});
  assert.equal(missingAccess.status,503);
  const wrongHost=await probe(new Request("https://random.example/api/github-quota"),{
    BKE_PREPRODUCTION:"true",BKE_ACCESS_POLICY_VERIFIED:"true"});
  assert.equal(wrongHost.status,503);
});
