import test from "node:test";
import assert from "node:assert/strict";
import {
  certificationSummary,
  reduceFirstCausalFailure,
  buildFailureCapsule,
  boundaryFromJobName,
  extractFailureExcerpt,
} from "../src/core.js";

test("generic checks cannot turn missing required certification into PASS", () => {
  const state = certificationSummary({
    exactHead: "abc",
    observedChecks: [{ head_sha: "abc", conclusion: "success" }],
  });
  assert.equal(state.state, "UNKNOWN");
  assert.equal(state.reason, "NO_REQUIRED_CERTIFICATION_EVIDENCE");
  assert.equal(state.observed_checks.positive, 1);
});

test("required exact-head certification decides certification state", () => {
  assert.equal(certificationSummary({
    exactHead: "abc",
    requiredEvidence: [{ source_sha: "abc", conclusion: "failure" }],
    observedChecks: [{ head_sha: "abc", conclusion: "success" }],
  }).state, "FAILED");
  assert.equal(certificationSummary({
    exactHead: "abc",
    requiredEvidence: [{ source_sha: "abc", conclusion: "success" }],
  }).state, "PASSED");
});

test("causal failure preserves downstream and only positive unaffected boundaries", () => {
  const result = reduceFirstCausalFailure([
    { occurred_at: "2026-10-08T04:58:52Z", boundary: "cloudflare-relay", conclusion: "failure", summary: "root", causal: true },
    { occurred_at: "2026-10-08T04:59:00Z", boundary: "core", conclusion: "success" },
    { occurred_at: "2026-10-08T05:01:40Z", boundary: "android", conclusion: "success" },
    { occurred_at: "2026-10-08T05:01:46Z", boundary: "certification", conclusion: "failure", summary: "aggregate", causal: false },
    { occurred_at: "2026-10-08T05:01:00Z", boundary: "server", conclusion: "skipped" },
  ]);
  assert.equal(result.causal.boundary, "cloudflare-relay");
  assert.equal(result.downstream[0].boundary, "certification");
  assert.deepEqual(result.unaffected.sort(), ["android", "core"]);
});

test("capsule exposes causal evidence and downstream evidence", () => {
  const capsule = buildFailureCapsule({
    repo: "jan2xo/bke-worker",
    pr_number: 82,
    exact_head: "h",
    worker_id: null,
    evidence: [
      { boundary: "cloudflare-relay", conclusion: "failure", summary: "root", causal: true, evidence: [{ id: "job", url: "https://example.invalid/job" }] },
      { boundary: "certification", conclusion: "failure", summary: "aggregate", causal: false },
    ],
  });
  assert.equal(capsule.boundary, "cloudflare-relay");
  assert.equal(capsule.downstream[0].classification, "DOWNSTREAM");
  assert.equal(capsule.evidence[0].url, "https://example.invalid/job");
});

test("worker job names map to stable boundaries", () => {
  assert.equal(boundaryFromJobName("Cloudflare durable relay"), "cloudflare-relay");
  assert.equal(boundaryFromJobName("Core orchestration + GitHub boundary"), "core");
  assert.equal(boundaryFromJobName("Android Gecko Worker probe"), "android");
  assert.equal(boundaryFromJobName("Required certification"), "certification");
});

test("bounded log extraction prefers actionable failure text and redacts tokens", () => {
  const result = extractFailureExcerpt("setup\nnot ok 4 - protocol\nAssertionError: expected recovered\nghp_SECRET123\nProcess completed with exit code 1");
  assert.equal(result.found, true);
  assert.match(result.excerpt.join("\n"), /not ok 4/);
  assert.doesNotMatch(result.excerpt.join("\n"), /ghp_SECRET123/);
});
