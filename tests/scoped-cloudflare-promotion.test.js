import test from "node:test";
import assert from "node:assert/strict";
import {
  B1_PROMOTION_LOCK, validateBefore, validateAfter, promoteScopedVersion,
} from "../scripts/promote-scoped-cloudflare-version.mjs";

const lock = B1_PROMOTION_LOCK;
const commandSha = "f".repeat(40);
const old = Object.freeze({
  deploymentId: lock.previousDeployment, activeVersion: lock.previousVersion,
  versionIds: [lock.stagedVersion, lock.previousVersion],
  versionItems: [
    { id: lock.stagedVersion, metadata: { source: "wrangler", created_on: lock.stagedCreatedOn } },
    { id: lock.previousVersion, metadata: { source: "api" } },
  ],
});
const nextDeployment = "22222222-2222-4222-8222-222222222222";
const newer = Object.freeze({
  ...old, deploymentId: nextDeployment, activeVersion: lock.stagedVersion,
});

test("promotion lock pins existing stage, source and one previous live deployment", () => {
  assert.equal(lock.stagedVersion, "6cd1fcc5-8c44-43a5-9ef9-af23452f2a4a");
  assert.equal(lock.stagedSourceSha, "eb825653a25271149f0934746683a5f0bbeb87b8");
  assert.equal(validateBefore(old), lock);
  assert.deepEqual(validateAfter(old, newer), {
    oldDeployment: lock.previousDeployment,
    oldVersion: lock.previousVersion,
    newDeployment: nextDeployment,
    newVersion: lock.stagedVersion,
  });
});

test("baseline drift, any other live version or deployment blocks promotion", () => {
  const candidates = [
    { ...old, deploymentId: nextDeployment },
    { ...old, activeVersion: lock.stagedVersion },
    { ...old, deploymentId: undefined },
    { ...old, activeVersion: undefined },
    { ...old, versionItems: [] },
    { ...old, versionIds: [lock.previousVersion] },
    { ...old, versionItems: [
      { id: lock.stagedVersion, metadata: { source: "api", created_on: lock.stagedCreatedOn } },
    ] },
    { ...old, versionItems: [
      { id: lock.stagedVersion, metadata: { source: "wrangler", created_on: "2026-10-09T08:02:23Z" } },
    ] },
    { ...old, versionItems: [
      { id: lock.stagedVersion, metadata: { source: "wrangler", created_on: lock.stagedCreatedOn } },
      { id: lock.stagedVersion, metadata: { source: "wrangler", created_on: lock.stagedCreatedOn } },
    ] },
  ];
  for (const candidate of candidates) {
    assert.throws(() => validateBefore(candidate),
      /ACTIVE_PREPRODUCTION_BASELINE_CHANGED|PINNED_STAGED_VERSION_NOT_VERIFIED|PROMOTION_SCOPE_OR_VERSION_INVALID/u);
  }
});

test("post-promotion demands a genuinely new deployment, 100% staged version", () => {
  const bads = [
    { ...newer, deploymentId: lock.previousDeployment },
    { ...newer, activeVersion: lock.previousVersion },
    { ...newer, activeVersion: "a".repeat(36) },
    { ...newer, versionIds: [lock.stagedVersion] },
    { ...newer, deploymentId: "not-a-uuid" },
  ];
  for (const after of bads) {
    assert.throws(() => validateAfter(old, after),
      /PROMOTION_RESULT_UNKNOWN_OR_WRONG_TARGET|VERSION_HISTORY_CHANGED_DURING_PROMOTION/u);
  }
});

test("real-token verification and source are required before any promotion call", async () => {
  const order = [];
  const res = await promoteScopedVersion("mock-token-not-real", {
    checkSource: () => { order.push("source"); return commandSha; },
    verifyToken: async () => { order.push("verify"); },
    snapshot: async () => {
      const seen = order.filter(x => x === "snapshot").length;
      order.push("snapshot");
      return seen === 0 ? old : newer;
    },
    promote: async value => { assert.equal(value, "mock-token-not-real"); order.push("promote"); },
  });
  assert.deepEqual(order, ["source", "verify", "snapshot", "source", "promote", "snapshot", "source"]);
  assert.equal(res.commandSha, commandSha);
  assert.equal(res.newVersion, lock.stagedVersion);
});

test("missing token verification stops before promotion", async () => {
  let called = false;
  await assert.rejects(promoteScopedVersion("mock", {
    checkSource: () => commandSha,
    verifyToken: async () => { throw Error("TOKEN_INVALID"); },
    snapshot: async () => old,
    promote: async () => { called = true; },
  }), /TOKEN_INVALID/u);
  assert.equal(called, false);
});

test("changed live deployment stops before promotion", async () => {
  let called = false;
  await assert.rejects(promoteScopedVersion("mock", {
    checkSource: () => commandSha,
    verifyToken: async () => {},
    snapshot: async () => ({ ...old, activeVersion: lock.stagedVersion }),
    promote: async () => { called = true; },
  }), /ACTIVE_PREPRODUCTION_BASELINE_CHANGED/u);
  assert.equal(called, false);
});

test("source drift before promotion stops any write", async () => {
  let called = false;
  let count = 0;
  await assert.rejects(promoteScopedVersion("mock", {
    checkSource: () => (++count === 1 ? commandSha : "a".repeat(40)),
    verifyToken: async () => {},
    snapshot: async () => old,
    promote: async () => { called = true; },
  }), /CANONICAL_SOURCE_MOVED_BEFORE_PROMOTION/u);
  assert.equal(called, false);
});

test("ambiguous CLI outcome requires operator investigation, never auto-retries", async () => {
  let count = 0;
  await assert.rejects(promoteScopedVersion("mock", {
    checkSource: () => commandSha,
    verifyToken: async () => {},
    snapshot: async () => old,
    promote: async () => { count++; throw Error("PROMOTION_COMMAND_FAILED_OR_AMBIGUOUS_DO_NOT_RETRY"); },
  }), /PROMOTION_COMMAND_FAILED_OR_AMBIGUOUS_DO_NOT_RETRY/u);
  assert.equal(count, 1);
});

test("post-promotion source drift remains blocked, even when deployment succeeded", async () => {
  let count = 0, reads = 0, promoted = false;
  await assert.rejects(promoteScopedVersion("mock", {
    checkSource: () => (++count <= 2 ? commandSha : "a".repeat(40)),
    verifyToken: async () => {},
    snapshot: async () => (++reads === 1 ? old : newer),
    promote: async () => { promoted = true; },
  }), /CANONICAL_SOURCE_MOVED_AFTER_PROMOTION/u);
  assert.equal(promoted, true);
});

test("production/default Worker and route edits are absent from command declaration", async () => {
  const { readFileSync } = await import("node:fs");
  const text = readFileSync("scripts/promote-scoped-cloudflare-version.mjs", "utf8");
  assert.match(text, /"versions", "deploy"/u);
  assert.match(text, /"preproduction"/u);
  assert.match(text, /"@100%"/u);
  assert.doesNotMatch(text, /"wrangler", "deploy"|".*routes", "deploy"/u);
  assert.doesNotMatch(text, /execSync\(|shell:\s*true/u);
});
