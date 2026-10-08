import test from "node:test";
import assert from "node:assert/strict";
import {assignmentFromPullRequest,collectEvidence,evidenceFromJob,resolveSourceShaFromLog} from "../src/github.js";
import {renderPr} from "../src/index.js";

test("assignment is UNKNOWN without exactly one worker label",()=>{
  assert.equal(assignmentFromPullRequest({number:4,state:"open",labels:[]}).state,"UNKNOWN");
  assert.equal(assignmentFromPullRequest({number:4,state:"open",labels:[{name:"bke-worker:android-worker-a"},{name:"bke-worker:other"}]}).state,"UNKNOWN");
});

test("real PR #82-shaped relay job resolves SOURCE_SHA from bounded log evidence",async()=>{
  const calls={runs:0,jobs:0,logs:0};
  const source="51d7e2655d66f75e8d9402e7f849544a7028f90f";
  const gh={
    checks:async()=>({check_runs:[{sha:source,conclusion:"success",name:"PR Guard"}]}),
    workflowRuns:async()=>{calls.runs++;return {workflow_runs:[{id:37730031840,name:"Intent Certification",event:"issue_comment",head_sha:"7fe9c19924dbf957591cc7ae8085b461c7800ec6",conclusion:"failure"}]};},
    issueComments:async()=>[],
    workflowJobs:async()=>{calls.jobs++;return {jobs:[
      {id:113156952418,name:"Cloudflare durable relay",conclusion:"failure",steps:[{name:"Verify Cloudflare relay protocol and config",conclusion:"failure"}],html_url:"https://github.com/jan2xo/bke-worker/actions/runs/37730031840/job/113156952418"},
      {id:113157730931,name:"Required certification",conclusion:"failure",steps:[{name:"Require requested exact-head proof",conclusion:"failure"}],html_url:"https://github.com/jan2xo/bke-worker/actions/runs/37730031840/job/113157730931"},
      {id:113156952287,name:"Core orchestration + GitHub boundary",conclusion:"success",steps:[],html_url:"https://example.invalid/core"}
    ]};},
    workflowJobLogs:async id=>{calls.logs++;return {content:id===113156952418||id===113157730931||id===113156952287?`SOURCE_SHA: ${source}`:""};}
  };
  const evidence=await collectEvidence(gh,{number:82},source);
  const relay=evidence.jobs.find(x=>x.boundary==="Cloudflare durable relay");
  const cert=evidence.jobs.find(x=>x.boundary==="Required certification");
  assert.equal(relay.source_sha,source);
  assert.equal(relay.summary,"Cloudflare durable relay: Verify Cloudflare relay protocol and config");
  assert.equal(relay.causal,true);
  assert.equal(cert.required,true);
  assert.ok(calls.runs===1 && calls.jobs===1 && calls.logs<=3);
});

test("log source resolver only trusts explicit SHA fields",()=>{
  assert.equal(resolveSourceShaFromLog("SOURCE_SHA: 51d7e2655d66f75e8d9402e7f849544a7028f90f"),"51d7e2655d66f75e8d9402e7f849544a7028f90f");
  assert.equal(resolveSourceShaFromLog("head_sha=not-a-sha"),null);
});

test("rendered PR state exposes causal, downstream, and exact head",()=>{
  const html=renderPr({
    pr:{number:82,title:"fixture",state:"open",draft:true},
    assignment:{worker_id:"android-worker-a",state:"ASSIGNED",exact_head:"51d7e2655d66f75e8d9402e7f849544a7028f90f"},
    certification:{state:"FAILED",required_seen:1},
    post_run_summary:"First causal failure: protocol/reconnect test assertion.",
    first_causal_failure:{
      boundary:"Cloudflare durable relay",stage:"test",classification:"CAUSAL",summary:"Verify Cloudflare relay protocol and config",
      downstream:[{classification:"DOWNSTREAM",boundary:"Required certification",summary:"Require requested exact-head proof"}],
      unaffected_boundaries:["Core orchestration + GitHub boundary"],evidence:[{id:"113156952418",url:"https://example.invalid/job"}]
    }
  });
  assert.match(html,/51d7e2655d66f75e8d9402e7f849544a7028f90f/);
  assert.match(html,/CAUSAL/);
  assert.match(html,/DOWNSTREAM/);
  assert.match(html,/113156952418/);
});
