import test from "node:test";
import assert from "node:assert/strict";
import { collectEvidence, correlateCertificationRuns } from "../src/github.js";
import { buildFailureCapsule, certificationSummary } from "../src/core.js";

const oldHead = "51d7e2655d66f75e8d9402e7f849544a7028f90f";
const newHead = "07e66b16a6f772ba17eb0ef80aa0b838b31ce117";
const workflowMainHead = "1f5947df9e9efe2e1a19701764a664ed6431973f";
const title = "task #81: feat(worker): add durable task checklist + 30-minute continuation lease";
const pr = {number:82,title,state:"closed",head:{sha:newHead},labels:[]};
const comments = [
  {created_at:"2026-10-08T11:07:32Z",body:`BKE EXECUTION CHECKPOINT — ORCHESTRATOR RESUME\nExisting exact head: \`${oldHead}\``,user:{login:"jan2xo"}},
  {created_at:"2026-10-08T11:14:46Z",body:"/certify core relay android",
   user:{login:"jan2xo"},html_url:"https://github.test/82#comment-final"}
];
const commits = [
  {sha:oldHead,commit:{committer:{date:"2026-10-08T04:57:49Z"}}},
  {sha:newHead,commit:{committer:{date:"2026-10-08T11:14:13Z"}}}
];
const run = {
  id:37768790839,name:"Intent Certification",display_title:title,
  event:"issue_comment",actor:{login:"jan2xo"},
  created_at:"2026-10-08T11:14:48Z",updated_at:"2026-10-08T11:18:00Z",
  status:"completed",conclusion:"success",head_sha:workflowMainHead,
  html_url:"https://github.test/actions/runs/37768790839"
};
const job = (id,name,conclusion="success")=>({
  id,name,conclusion,status:"completed",
  steps:[{name:"Verify exact checkout",conclusion:"success"}],
  html_url:`https://github.test/actions/jobs/${id}`,
  completed_at:"2026-10-08T11:17:00Z"
});
const jobs = [
  job(113282929435,"Core orchestration + GitHub boundary"),
  job(113282929584,"Android Gecko Worker probe"),
  job(113282929711,"Cloudflare durable relay"),
  job(113283967941,"Required certification")
];

test("PR 82 final command correlates to newer final commit, not an old checkpoint",()=>{
  const correlated=correlateCertificationRuns({pr,comments,commits,runs:[run],exactHead:newHead});
  assert.equal(correlated.length,1);
  assert.equal(correlated[0].source_sha,newHead);
  assert.equal(correlated[0].head_sha,workflowMainHead,
    "issue_comment workflow HEAD remains default main, not the PR's source");
});

test("final exact-head Core/Android/Relay/Required PASS is represented without phantom failure",async()=>{
  let calls=0;
  const gh={
    checks:async sha=>({check_runs:[{head_sha:sha,conclusion:"success",name:"PR Guard"}]}),
    issueComments:async()=>comments,
    pullCommits:async()=>commits,
    workflowRuns:async event=>{assert.equal(event,"issue_comment");return {workflow_runs:[run]}},
    workflowJobs:async id=>{calls++;assert.equal(id,run.id);return {jobs}}
  };
  const evidence=await collectEvidence(gh,pr,newHead);
  assert.equal(calls,1,"one correlated run, one bounded jobs request");
  assert.equal(evidence.certificationRuns.length,1);
  assert.equal(evidence.required.length,1);
  const summary=certificationSummary({
    exactHead:newHead,requiredEvidence:evidence.required,observedChecks:evidence.checks
  });
  assert.equal(summary.state,"PASSED");
  assert.equal(summary.required_evidence_seen,1);
  const capsule=buildFailureCapsule({
    repo:"jan2xo/bke-worker",pr_number:82,exact_head:newHead,
    worker_id:null,evidence:evidence.jobs
  });
  assert.equal(capsule.boundary,null);
  assert.deepEqual(capsule.downstream,[]);
  assert.deepEqual(capsule.unaffected_boundaries.sort(),["android","certification","cloudflare-relay","core"]);
});

test("a head introduced after the certification command cannot inherit its success",async()=>{
  const later="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const changed={
    ...pr,head:{sha:later}
  };
  const changes=[
    ...commits,
    {sha:later,commit:{committer:{date:"2026-10-08T11:15:30Z"}}}
  ];
  assert.deepEqual(correlateCertificationRuns({
    pr:changed,comments,commits:changes,runs:[run],exactHead:later
  }),[]);
  let jobCalls=0;
  const evidence=await collectEvidence({
    checks:async()=>({check_runs:[{head_sha:later,conclusion:"success"}]}),
    issueComments:async()=>comments,pullCommits:async()=>changes,
    workflowRuns:async()=>({workflow_runs:[run]}),
    workflowJobs:async()=>{jobCalls++;return {jobs};}
  },changed,later);
  assert.equal(jobCalls,0);
  assert.equal(certificationSummary({
    exactHead:later,requiredEvidence:evidence.required,observedChecks:evidence.checks
  }).state,"UNKNOWN");
});

test("conflicting equally recent head observations fail closed",()=>{
  const ambiguous=[
    ...comments.slice(0,1),
    {created_at:"2026-10-08T11:14:13Z",body:`head=${oldHead}`,user:{login:"jan2xo"}},
    comments[1]
  ];
  assert.deepEqual(correlateCertificationRuns({
    pr,comments:ambiguous,commits,runs:[run],exactHead:newHead
  }),[]);
});

test("stale historical success cannot be mistaken for a new exact-head run",()=>{
  const earlier= {...run,id:37768105709,
    created_at:"2026-10-08T11:08:30Z",
    updated_at:"2026-10-08T11:09:30Z",
    conclusion:"success"
  };
  assert.deepEqual(correlateCertificationRuns({
    pr,comments,commits,runs:[earlier],exactHead:newHead
  }),[]);
  const last=correlateCertificationRuns({pr,comments,commits,
    runs:[earlier,run],exactHead:newHead});
  assert.deepEqual(last.map(x=>x.id),[run.id]);
});

test("untrusted or mismatched actors and workflow names never prove current exact head",()=>{
  const imposter={...run,actor:{login:"someone-else"}};
  const wrongTitle={...run,display_title:"unrelated pull request"};
  assert.deepEqual(correlateCertificationRuns({
    pr,comments,commits,runs:[imposter,wrongTitle],exactHead:newHead
  }),[]);
});
