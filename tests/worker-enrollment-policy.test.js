import test from "node:test";
import assert from "node:assert/strict";
import { evaluateWorkerEnrollment } from "../src/worker-enrollment-policy.js";

const hex = (ch) => ch.repeat(64);
const candidate = () => ({
  worker_id: "worker-b",
  identity_public_key_sha256: hex("a"),
  chatgpt_target_sha256: hex("b"),
  browser_profile_sha256: hex("c"),
  bridge_identity_sha256: hex("d"),
  nonce_sha256: hex("e"),
  expires_at_ms: 110_000,
  dispatch_state: "IDLE",
});
const input = (changes = {}) => ({
  candidate: candidate(), pairedWorkers: [], openPullRequests: [],
  inventoryVerified: true, prSnapshotVerified: true, nowMs: 100_000,
  ...changes,
});
function blocked(value, code) {
  const result = evaluateWorkerEnrollment(value);
  assert.deepEqual(result, { state: "BLOCKED", code });
  assert.doesNotMatch(JSON.stringify(result), /worker-b|nonce|github|chatgpt|https|ghs_/iu);
}

test("isolated idle candidate is reviewable but not paired or authorized", () => {
  const result = evaluateWorkerEnrollment(input({
    pairedWorkers: [{ ...candidate(), worker_id: "worker-a",
      identity_public_key_sha256: hex("1"), chatgpt_target_sha256: hex("2"),
      browser_profile_sha256: hex("3"), bridge_identity_sha256: hex("4"), nonce_sha256: hex("5") }],
    openPullRequests: [{ repository: "jan2xo/bke-worker", number: 90, state: "open", labels: ["triage"] }],
  }));
  assert.deepEqual(result, { state: "READY_FOR_HUMAN_REVIEW", code: "ENROLLMENT_PREFLIGHT_OK" });
  assert.equal(Object.isFrozen(result), true);
  assert.equal("token" in result || "lease" in result, false);
});

test("unverified/missing inventories fail closed", () => {
  for (const value of [null, {}, input({ inventoryVerified: false }),
    input({ prSnapshotVerified: false }), input({ pairedWorkers: null }),
    input({ openPullRequests: null })]) {
    blocked(value, "ENROLLMENT_EVIDENCE_UNAVAILABLE");
  }
});

test("invalid identity, expiry or uncertain dispatch fail closed", () => {
  for (const patch of [
    { worker_id: "worker_A" }, { worker_id: "-bad" },
    { nonce_sha256: "raw_nonce" }, { identity_public_key_sha256: hex("Z") },
    { expires_at_ms: 100_000 }, { expires_at_ms: 400_001 },
    { dispatch_state: "DISPATCHING" }, { dispatch_state: "BLOCKED_UNCERTAIN_TURN" },
  ]) blocked(input({ candidate: { ...candidate(), ...patch } }), "ENROLLMENT_CANDIDATE_INVALID_OR_BUSY");
});

test("existing ID or any shared resource is rejected", () => {
  const prior = candidate();
  blocked(input({ pairedWorkers: [prior] }), "ENROLLMENT_ID_ALREADY_PAIRED");
  const keys = ["identity_public_key_sha256", "chatgpt_target_sha256",
    "browser_profile_sha256", "bridge_identity_sha256", "nonce_sha256"];
  for (const key of keys) {
    const existing = { ...prior, worker_id: "worker-a", ...Object.fromEntries(
      keys.map((k, i) => [k, k === key ? prior[k] : hex(String(i + 1))])) };
    blocked(input({ pairedWorkers: [existing] }), "ENROLLMENT_RESOURCE_ALREADY_PAIRED");
  }
});

test("ambiguous paired registry fails closed", () => {
  const prior = { ...candidate(), worker_id: "worker-a",
    identity_public_key_sha256: hex("1"), chatgpt_target_sha256: hex("2"),
    browser_profile_sha256: hex("3"), bridge_identity_sha256: hex("4"), nonce_sha256: hex("5") };
  blocked(input({ pairedWorkers: [prior, { ...prior }] }), "ENROLLMENT_REGISTRY_AMBIGUOUS");
  blocked(input({ pairedWorkers: [prior, { ...prior, worker_id: "worker-c" }] }), "ENROLLMENT_REGISTRY_AMBIGUOUS");
  blocked(input({ pairedWorkers: [{ ...prior, worker_id: "WORKER-A" }] }), "ENROLLMENT_REGISTRY_AMBIGUOUS");
});

test("active ownership and ambiguous multi-label PRs block enrollment", () => {
  const pr = { repository: "jan2xo/bke-worker", number: 123, state: "open", labels: ["bke-worker:worker-b"] };
  blocked(input({ openPullRequests: [pr] }), "ENROLLMENT_ACTIVE_PR_REQUIRES_RECOVERY");
  blocked(input({ openPullRequests: [{ ...pr, labels: ["bke-worker:worker-a", "bke-worker:worker-b"] }] }),
    "ENROLLMENT_PR_ASSIGNMENT_CONFLICT");
  blocked(input({ openPullRequests: [{ ...pr, labels: ["bke-worker:worker-a", "bke-worker:worker-a"] }] }),
    "ENROLLMENT_PR_ASSIGNMENT_CONFLICT");
});

test("incomplete, malformed or duplicate PR snapshot blocks preflight", () => {
  const pr = { repository: "jan2xo/bke-worker", number: 123, state: "open", labels: [] };
  for (const list of [[pr, pr], [{ ...pr, state: "closed" }],
    [{ ...pr, labels: ["bke-worker:BAD"] }], [{ ...pr, labels: [3] }],
    [{ ...pr, repository: "https://example.com/x" }]]) {
    blocked(input({ openPullRequests: list }), "ENROLLMENT_PR_SNAPSHOT_AMBIGUOUS");
  }
});

test("another worker on an independently assigned PR does not block", () => {
  const result = evaluateWorkerEnrollment(input({
    openPullRequests: [{ repository: "jan2xo/bke-worker", number: 90,
      state: "open", labels: ["no-wake", "bke-worker:android-worker-a"] }],
  }));
  assert.equal(result.state, "READY_FOR_HUMAN_REVIEW");
});
