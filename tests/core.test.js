import test from "node:test";
import assert from "node:assert/strict";
import { certificationSummary, reduceFirstCausalFailure, buildFailureCapsule } from "../src/core.js";

test("exact-head certification ignores evidence for other heads", () => {
  const result = certificationSummary({
    exactHead:"abc",
    checks:[{sha:"abc",conclusion:"success"},{sha:"old",conclusion:"failure"}],
    workflowRuns:[{head_sha:"abc",conclusion:"success"},{head_sha:"old",conclusion:"failure"}]
  });
  assert.equal(result.state,"PASSED");
});

test("first causal failure separates downstream red gates", () => {
  const result = reduceFirstCausalFailure([
    {occurred_at:"2026-10-08T08:00:00Z",boundary:"cloudflare-relay",stage:"test",conclusion:"failure",summary:"protocol/reconnect test assertion",causal:true},
    {occurred_at:"2026-10-08T08:01:00Z",boundary:"certification",stage:"certification",conclusion:"failure",summary:"required certification failed"}
  ]);
  assert.equal(result.causal.boundary,"cloudflare-relay");
  assert.equal(result.causal.classification,"CAUSAL");
  assert.equal(result.downstream[0].classification,"DOWNSTREAM");
});

test("PR #82 fixture capsule does not hard-code the PR in reducer", () => {
  const capsule = buildFailureCapsule({
    repo:"jan2xo/bke-worker",pr_number:82,exact_head:"fixture-head",worker_id:"android-worker-a",
    evidence:[{occurred_at:"2026-10-08T08:00:00Z",host:"github_actions",boundary:"cloudflare-relay",stage:"test",conclusion:"failure",summary:"protocol/reconnect test assertion",causal:true,evidence_run_ids:["run-1"],next_owner:"worker",next_action:"fix protocol test"}]
  });
  assert.equal(capsule.boundary,"cloudflare-relay");
  assert.equal(capsule.classification,"CAUSAL");
});
