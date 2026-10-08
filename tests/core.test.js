import test from "node:test";
import assert from "node:assert/strict";
import {certificationSummary,reduceFirstCausalFailure,buildFailureCapsule} from "../src/core.js";

test("exact-head certification ignores other heads",()=>{
  assert.equal(certificationSummary({exactHead:"abc",checks:[{sha:"abc",conclusion:"success"},{sha:"old",conclusion:"failure"}],workflowRuns:[{head_sha:"abc",conclusion:"success"},{head_sha:"old",conclusion:"failure"}],requiredProof:[{source_sha:"abc",status:"success"}]}).state,"PASSED");
});
test("zero evidence is UNKNOWN, never PASS",()=>assert.equal(certificationSummary({exactHead:"abc"}).state,"UNKNOWN"));
test("source_sha correlates certification proof",()=>assert.equal(certificationSummary({exactHead:"abc",proof:[{source_sha:"abc",status:"success"}],requiredProof:[{source_sha:"abc",status:"success"}]}).state,"PASSED"));
test("first causal failure preserves downstream",()=>{
  const r=reduceFirstCausalFailure([{occurred_at:"2026-10-08T08:00:00Z",boundary:"cloudflare-relay",stage:"test",conclusion:"failure",summary:"protocol/reconnect test assertion",causal:true},{occurred_at:"2026-10-08T08:01:00Z",boundary:"certification",conclusion:"failure",summary:"required certification failed"}]);
  assert.equal(r.causal.boundary,"cloudflare-relay"); assert.equal(r.downstream[0].classification,"DOWNSTREAM");
});
test("skipped is not unaffected",()=>assert.deepEqual(reduceFirstCausalFailure([{boundary:"android",conclusion:"skipped"}]).unaffected,[]));
test("capsule preserves evidence and downstream",()=>{
  const c=buildFailureCapsule({repo:"jan2xo/bke-worker",pr_number:82,exact_head:"h",worker_id:"android-worker-a",evidence:[{boundary:"relay",conclusion:"failure",summary:"root",causal:true,evidence:[{id:"job-1",url:"https://example.invalid/job"}]},{boundary:"certification",conclusion:"failure",summary:"aggregate"}]});
  assert.equal(c.classification,"CAUSAL"); assert.equal(c.downstream[0].classification,"DOWNSTREAM"); assert.equal(c.evidence[0].url,"https://example.invalid/job");
});
