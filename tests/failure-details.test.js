import test from "node:test";
import assert from "node:assert/strict";
import { selectRecentIncident, summarizeFailureJobs, failureDetailState,
         renderFailureDetail } from "../src/failure-details.js";
import { handleRequest } from "../src/index.js";

const SHA = "f73c16af2d89d4aeba266a7e8adb5af468c08a60";
const repo = { full_name:"jan2xo/bke-worker",default_branch:"main" };
const sample = () => ({ workflow_runs:[
  {id:100,name:"Intent Certification",head_sha:SHA,status:"completed",
   conclusion:"failure",updated_at:"2026-10-08T11:20:00Z"},
  {id:101,name:"Other healthy workflow",head_sha:SHA,status:"completed",
   conclusion:"success",updated_at:"2026-10-08T11:21:00Z"},
]});
const jobs = () => ({total_count:3,jobs:[
  {id:10001,name:"Cloudflare Relay Integration",conclusion:"failure",
   completed_at:"2026-10-08T11:20:02Z",
   steps:[{name:"checkout",conclusion:"success"},
     {name:"Relay endpoint availability assertion",conclusion:"failure"}]},
  {id:10002,name:"Required certification",conclusion:"failure",
   completed_at:"2026-10-08T11:20:04Z",
   steps:[{name:"Check all required tests",conclusion:"failure"}]},
  {id:10003,name:"Core tests",conclusion:"success",
   completed_at:"2026-10-08T11:20:01Z",
   steps:[{name:"Core assertions",conclusion:"success"}]},
]});
const gh = (overrides={}) => ({
  repo:async()=>repo, recentWorkflowRuns:async()=>sample(),
  workflowJobs:async()=>jobs(), ...overrides,
});

test("select only an incident in current bounded run window",()=>{
  assert.equal(selectRecentIncident(sample(),repo.full_name,100).id,100);
  assert.equal(selectRecentIncident(sample(),repo.full_name,101),null);
  assert.equal(selectRecentIncident(sample(),repo.full_name,999),null);
});
test("identify first observed failed step, not downstream certification gate",()=>{
  const d=summarizeFailureJobs({
    id:100,name:"Intent Certification",sha:SHA,conclusion:"failure",
    observed_at:"2026-10-08T11:20:00Z",
    url:"https://github.com/jan2xo/bke-worker/actions/runs/100",
  },jobs(),repo.full_name);
  assert.equal(d.first_observed_failure.id,10001);
  assert.equal(d.first_observed_failure.first_failed_step,
    "Relay endpoint availability assertion");
  assert.equal(d.detail_status,"FIRST_OBSERVED_FAILED_STEP");
  assert.equal(d.downstream_gate_failures.length,1);
  assert.equal(d.unaffected_successful_jobs.length,1);
  assert.equal(d.cloudflare_runtime,"UNKNOWN");
  assert.match(d.claim_boundary,/not a confirmed external-service root cause/);
  assert.match(renderFailureDetail(d),/First observed failed job/);
  assert.match(renderFailureDetail(d),/Required certification/);
});
test("failed job without failing step is explicitly uncertain",()=>{
  const p=jobs();
  p.jobs[0].steps=[];
  const d=summarizeFailureJobs({
    id:100,name:"Intent Certification",sha:SHA,conclusion:"failure",
    url:"https://github.com/jan2xo/bke-worker/actions/runs/100",
  },p,repo.full_name);
  assert.equal(d.detail_status,"JOB_FAILED_STEP_UNAVAILABLE");
  assert.equal(d.first_observed_failure.first_failed_step,null);
});
test("multiple plausible failed jobs are not misreported as definitive cause",()=>{
  const p=jobs();
  p.jobs.push({id:10004,name:"Server integration",conclusion:"failure",
    completed_at:"2026-10-08T11:20:03Z",steps:[{name:"server test",conclusion:"failure"}]});
  p.total_count=4;
  const d=summarizeFailureJobs({
    id:100,name:"Intent Certification",sha:SHA,conclusion:"failure",
    url:"https://github.com/jan2xo/bke-worker/actions/runs/100",
  },p,repo.full_name);
  assert.equal(d.detail_status,"MULTIPLE_FAILED_JOBS_CAUSE_UNVERIFIED");
  assert.equal(d.failed_job_count,3);
});
test("cancelled/skipped jobs with null step lists do not hide real failures",()=>{
  const p=jobs();
  p.jobs.push({id:10004,name:"Skipped optional job",conclusion:"skipped",steps:null});
  p.total_count=4;
  const d=summarizeFailureJobs({
    id:100,name:"CI",sha:SHA,conclusion:"failure",
    url:"https://github.com/jan2xo/bke-worker/actions/runs/100",
  },p,repo.full_name);
  assert.equal(d.first_observed_failure.id,10001);
  assert.equal(d.reported_job_count,4);
});
test("no jobs means UNKNOWN cause, not platform outage",()=>{
  const d=summarizeFailureJobs({
    id:100,name:"Cancelled",sha:SHA,conclusion:"cancelled",url:"https://github.com/jan2xo/bke-worker/actions/runs/100",
  },{total_count:0,jobs:[]},repo.full_name);
  assert.equal(d.detail_status,"NO_JOBS_REPORTED");
  assert.equal(d.first_observed_failure,null);
});
for(const [description, x] of [
  ["more jobs than permitted",{jobs:Array.from({length:40},(_,i)=>({id:i+1,name:"Job",conclusion:"success",steps:[]}))}],
  ["incomplete pagination",{total_count:5,jobs:jobs().jobs}],
  ["duplicate job",{jobs:[jobs().jobs[0],jobs().jobs[0]]}],
  ["invalid job id",{jobs:[{id:"1",name:"unsafe",conclusion:"failure",steps:[]}]}],
  ["too many steps",{jobs:[{id:42,name:"Test",conclusion:"failure",steps:Array(71).fill({name:"x",conclusion:"success"})}]}],
]) {
 test("reject ambiguous job evidence: "+description,()=>{
    assert.throws(()=>summarizeFailureJobs({
      id:100,sha:SHA,name:"CI",conclusion:"failure",
    },x,repo.full_name),/GITHUB_FAILURE_JOB/);
 });
}
test("real HTML and JSON detail routes call jobs only after selecting allowed recent failed run",async()=>{
  let jobsRead=0;
  const adapter=gh({workflowJobs:async()=>{jobsRead++;return jobs();}});
  const page=await handleRequest(new Request("https://command.test/failures/100"),
    {BKE_PREPRODUCTION:"true"},()=>adapter);
  assert.equal(page.status,200);
  const html=await page.text();
  assert.match(html,/Relay endpoint availability assertion/);
  assert.match(html,/Cloudflare runtime health: <b>UNKNOWN<\/b>/);
  assert.equal(page.headers.get("cache-control"),"no-store");
  const api=await handleRequest(new Request("https://command.test/api/failures/100"),
    {BKE_PREPRODUCTION:"true"},()=>adapter);
  assert.equal(api.status,200);
  assert.equal((await api.json()).first_observed_failure.id,10001);
  assert.equal(jobsRead,2);
});
test("out-of-sample or successful runs are 404 and never fetch jobs",async()=>{
  const adapter=gh({workflowJobs:async()=>{throw Error("unreachable");}});
  for(const id of [101,999]){
    const p=await handleRequest(new Request("https://command.test/api/failures/"+id),
      {BKE_PREPRODUCTION:"true"},()=>adapter);
    assert.equal(p.status,404);
  }
});
test("GitHub jobs outage degrades to UNKNOWN safely",async()=>{
  const data=await failureDetailState(gh({workflowJobs:async()=>{throw Error("secret ghp_somesecret");}}),100);
  assert.equal(data.detail_status,"JOB_EVIDENCE_UNAVAILABLE");
  assert.doesNotMatch(JSON.stringify(data),/somesecret/);
  assert.equal(data.cloudflare_runtime,"UNKNOWN");
});
test("job and step names are escaped/redacted, no injected markup",()=>{
  const p={jobs:[{id:1,name:'<img src=x onerror="boom">',conclusion:"failure",
    steps:[{name:"bad ghp_FAKESECRET",conclusion:"failure"}]}]};
  const d=summarizeFailureJobs({
    id:100,name:"CI",sha:SHA,conclusion:"failure",
    url:"https://github.com/jan2xo/bke-worker/actions/runs/100",
  },p,repo.full_name);
  const h=renderFailureDetail(d);
  assert.match(h,/&lt;img/);
  assert.doesNotMatch(h,/<img/);
  assert.match(h,/REDACTED_GITHUB_TOKEN/);
  assert.doesNotMatch(h,/FAKESECRET/);
});


test("new diagnostics never bypass the PREPRODUCTION and private-host release latches",async()=>{
  const deployed=(await import("../src/index.js")).default;
  const missing=await deployed.fetch(new Request("https://cc.jl-bke.com/api/failures/100"),{});
  assert.equal(missing.status,503);
  assert.equal((await missing.json()).state,"LOCKED");
  const accessMissing=await deployed.fetch(new Request("https://cc.jl-bke.com/failures/100"),
    {BKE_PREPRODUCTION:"true"});
  assert.equal(accessMissing.status,503);
  assert.equal((await accessMissing.json()).error,"COMMAND_CENTER_ACCESS_NOT_VERIFIED");
  const wrongHostname=await deployed.fetch(new Request("https://wrong.example/failures/100"),
    {BKE_PREPRODUCTION:"true",BKE_ACCESS_POLICY_VERIFIED:"true"});
  assert.equal(wrongHostname.status,503);
  assert.equal((await wrongHostname.json()).error,"COMMAND_CENTER_HOSTNAME_NOT_APPROVED");
});
