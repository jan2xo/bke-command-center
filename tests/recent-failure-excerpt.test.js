import test from "node:test";
import assert from "node:assert/strict";
import { handleRequest } from "../src/index.js";
import preproduction from "../src/index.js";

const SHA = "f73c16af2d89d4aeba266a7e8adb5af468c08a60";
const sample = () => ({workflow_runs: [
  {id:37877137333,name:"Serial Master Queue Dispatcher",head_sha:SHA,
   status:"completed",conclusion:"failure",updated_at:"2026-10-09T03:00:00Z"},
  {id:500,name:"Healthy",head_sha:SHA,status:"completed",
   conclusion:"success",updated_at:"2026-10-09T03:01:00Z"},
]});
const jobPayload = () => ({total_count:2,jobs:[
  {id:113600000001,name:"Reconcile GitHub Master Queue",conclusion:"failure",
   completed_at:"2026-10-09T03:01:00Z",steps:[
     {name:"Mint scoped BKE GitHub App installation token",conclusion:"failure"}]},
  {id:113600000002,name:"Required certification",conclusion:"success",
   completed_at:"2026-10-09T03:02:00Z",steps:[]}
]});
const setup = (override={}) => {
  const counters = {repo:0,runs:0,jobs:0,logs:0};
  const adapter={
    repo:async()=>{counters.repo++;return {full_name:"jan2xo/bke-worker",default_branch:"main"};},
    recentWorkflowRuns:async()=>{counters.runs++;return sample();},
    workflowJobs:async()=>{counters.jobs++;return jobPayload();},
    jobFailureExcerpt:async()=>{counters.logs++;return {found:true,truncated:false,
      excerpt:["setup","not ok - step failed","Authorization: Bearer SECRET_AND_MORE","AssertionError: expected successful token"]};},
    ...override,
  };
  return {adapter,counters};
};
const url=(run,job)=>`https://cc.jl-bke.com/api/failures/${run}/jobs/${job}/excerpt`;

test("authorized recent failed job yields on-demand scoped redacted excerpt",async()=>{
  const {adapter,counters}=setup();
  const r=await handleRequest(new Request(url(37877137333,113600000001)),{},()=>adapter);
  assert.equal(r.status,200);
  assert.equal(r.headers.get("cache-control"),"no-store");
  const data=await r.json();
  assert.equal(data.state,"BOUNDED_HISTORICAL_RUN_EVIDENCE");
  assert.equal(data.scope,"LATEST_30_FIRST_OBSERVED_FAILED_JOB_ONLY");
  assert.equal(data.run_head_sha,SHA);
  assert.equal(data.job_id,113600000001);
  assert.equal(data.found,true);
  assert.equal(data.current_pr_certification,"NOT_ASSERTED");
  assert.equal(data.worker_runtime,"UNKNOWN");
  assert.deepEqual(counters,{repo:1,runs:1,jobs:1,logs:1});
  assert.doesNotMatch(JSON.stringify(data),/SECRET_AND_MORE/);
  assert.match(data.excerpt.join(" "),/REDACTED/);
});

test("only first observed failed job of the selected run can fetch log",async()=>{
  const {adapter,counters}=setup();
  for(const id of [113600000002,113156952418,1234]){
    const r=await handleRequest(new Request(url(37877137333,id)),{},()=>adapter);
    assert.equal(r.status,404);
    assert.equal((await r.json()).error,"JOB_NOT_FIRST_FAILED_IN_RECENT_INCIDENT_WINDOW");
  }
  assert.equal(counters.logs,0);
});

test("successful, unknown and out-of-window runs never fetch jobs or logs",async()=>{
  const {adapter,counters}=setup();
  for(const run of [500,499,37730031840]){
    const r=await handleRequest(new Request(url(run,113600000001)),{},()=>adapter);
    assert.equal(r.status,404);
  }
  assert.equal(counters.jobs,0);
  assert.equal(counters.logs,0);
});

test("partial job enumeration or invalid job data fails closed, never downloads log",async()=>{
  const {adapter,counters}=setup({workflowJobs:async()=>({total_count:41,
    jobs:jobPayload().jobs})});
  const r=await handleRequest(new Request(url(37877137333,113600000001)),{},()=>adapter);
  assert.equal(r.status,404);
  assert.equal(counters.logs,0);
});

test("upstream job log fetch failure is unknown evidence, never upstream details",async()=>{
  const {adapter,counters}=setup({jobFailureExcerpt:async()=>{counters.logs++;
    throw new Error("upstream ghp_NO_LOGGING_ALLOWED");}});
  const r=await handleRequest(new Request(url(37877137333,113600000001)),{},()=>adapter);
  assert.equal(r.status,502);
  assert.equal((await r.json()).state,"UNKNOWN");
  assert.equal(counters.logs,1);
});

test("excerpts are at most twelve lines, each at most 220 characters",async()=>{
  const long="X".repeat(1000);
  const lines=Array.from({length:12},()=>long);
  const {adapter}=setup({jobFailureExcerpt:async()=>({found:true,
    truncated:false,excerpt:lines})});
  const r=await handleRequest(new Request(url(37877137333,113600000001)),{},()=>adapter);
  assert.equal(r.status,200);
  const body=await r.json();
  assert.equal(body.excerpt.length,12);
  assert.ok(body.excerpt.every(x=>x.length<=220));
  assert.equal(body.truncated,true);
});
test("malformed or too-many excerpt lines fail closed, not partial disclosure",async()=>{
  const {adapter}=setup({jobFailureExcerpt:async()=>({found:true,
    truncated:false,excerpt:Array(13).fill("raw")})});
  const r=await handleRequest(new Request(url(37877137333,113600000001)),{},()=>adapter);
  assert.equal(r.status,502);
  assert.equal((await r.json()).state,"UNKNOWN");
});
test("failure diagnosis HTML links only to current first failed job excerpt",async()=>{
  const {adapter}=setup();
  const r=await handleRequest(new Request("https://cc.jl-bke.com/failures/37877137333"),{},()=>adapter);
  assert.equal(r.status,200);
  const html=await r.text();
  assert.match(html,/\/api\/failures\/37877137333\/jobs\/113600000001\/excerpt/);
  assert.doesNotMatch(html,/\/api\/failures\/37877137333\/jobs\/113600000002\/excerpt/);
});
test("no public alternate host or missing Access latch can reach run-scoped logs",async()=>{
  const route=url(37877137333,113600000001);
  const missing=await preproduction.fetch(new Request(route),{});
  assert.equal(missing.status,503);
  const access=await preproduction.fetch(new Request(route),{BKE_PREPRODUCTION:"true"});
  assert.equal(access.status,503);
  const wrong=await preproduction.fetch(
    new Request("https://evil.example/api/failures/37877137333/jobs/113600000001/excerpt"),
    {BKE_PREPRODUCTION:"true",BKE_ACCESS_POLICY_VERIFIED:"true"});
  assert.equal(wrong.status,503);
});
