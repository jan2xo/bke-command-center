import test from "node:test";
import assert from "node:assert/strict";
import { readAdminWorkerAssignments, publicWorkerAssignmentProjection,
  AdminWorkerAssignmentError } from "../src/admin-worker-assignments.js";
import { preproductionFetch } from "../src/index.js";
import { readFileSync } from "node:fs";

const SHA = "a".repeat(40);
const base = {
  principal: "github_app_installation",
  authority: "EXISTING_GITHUB_APP_INSTALLATION",
  repository_scope: "INSTALLATION_APPROVED_ONLY",
  installation_id: "51",
  total_visible_repositories: 76,
  enumerated_open_pull_requests: 123,
  consistency: "NON_ATOMIC_ENUMERATION",
  worker_assignments: [
    { repository: "jan2xo/bke-worker", repository_id: 1354026486,
      number: 104, state: "open", head_sha: SHA,
      labels: ["bke-worker:worker-a"] },
    { repository: "jan2xo/bke-command-center", repository_id: 123456,
      number: 42, state: "open", head_sha: "b".repeat(40),
      labels: ["bke-worker:worker-b"] },
  ],
};
const stage = {
  BKE_PREPRODUCTION: "true",
  BKE_ACCESS_POLICY_VERIFIED: "true",
  BKE_ADMIN_PR_INVENTORY_ENABLED: "true",
  BKE_ADMIN_DISCOVERY_ENABLED: "true",
  BKE_ADMIN_ACCESS_ISSUER: "https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD: "0123456789abcdef0123456789abcdef",
  BKE_ADMIN_EMAILS: "admin@example.test",
};
const authorized = (email = "admin@example.test", aud = stage.BKE_ADMIN_ACCESS_AUD) => ({
  access: {
    aud, async getIdentity() { return { email }; },
  },
});
const makeEnv = (value = base, onCall) => ({
  ...stage,
  BKE_GITHUB_READ_BROKER: {
    async listVerifiedWorkerAssignments(params) {
      assert.deepEqual(params, { purpose: "admin_worker_assignment_inventory" });
      onCall?.();
      return value;
    },
  },
});
const denied = (fn, code) => assert.rejects(fn,
  err => err instanceof AdminWorkerAssignmentError && err.code === code &&
    Object.keys(err).every(key => key === "name" || key === "code"));

test("Admin-only trusted RPC returns bounded NON_ATOMIC observation, not authority", async () => {
  let calls = 0;
  const state = await readAdminWorkerAssignments(makeEnv(base, () => calls++), authorized());
  assert.equal(calls, 1);
  assert.equal(state.trusted_installation_id, "51");
  assert.equal(state.consistency, "NON_ATOMIC_ENUMERATION");
  assert.equal(state.dispatch_authority, "NONE");
  assert.equal(state.state, "OBSERVED_ONLY");
  assert.equal(Object.isFrozen(state), true);
  const publicView = publicWorkerAssignmentProjection(state);
  assert.deepEqual(publicView.assignments.map(x => x.worker_id), ["worker-a", "worker-b"]);
  assert.equal(publicView.total_visible_repositories, 76);
  assert.equal(publicView.enumerated_open_pull_requests, 123);
  assert.match(publicView.warning, /not an atomic lease/u);
  assert.doesNotMatch(JSON.stringify(publicView), /installation_id|ghs_|token|private_key|verified|paired|bearer/iu);
});

test("default-OFF despite configured discovery mode and valid Access", async () => {
  for (const settings of [
    { BKE_ADMIN_PR_INVENTORY_ENABLED: undefined },
    { BKE_ADMIN_PR_INVENTORY_ENABLED: false },
    { BKE_ADMIN_PR_INVENTORY_ENABLED: "false" },
    { BKE_PREPRODUCTION: false },
    { BKE_ACCESS_POLICY_VERIFIED: undefined },
  ]) {
    let calls = 0;
    await denied(() => readAdminWorkerAssignments({
      ...makeEnv(base, () => calls++), ...settings,
    }, authorized()), "ADMIN_ASSIGNMENT_READ_DISABLED");
    assert.equal(calls, 0);
  }
});

test("no ctx.access, forged browser JWT/email header cannot substitute", async () => {
  let calls = 0;
  const env = makeEnv(base, () => calls++);
  for (const ctx of [
    undefined, {}, { access: { aud: stage.BKE_ADMIN_ACCESS_AUD } },
    { access: { aud: stage.BKE_ADMIN_ACCESS_AUD,
      async getIdentity() { throw Error("do not expose identity"); } } },
    authorized("other@example.test"), authorized("admin@example.test", "wrong-aud"),
  ]) {
    await denied(() => readAdminWorkerAssignments(env, ctx),
      "ADMIN_ASSIGNMENT_ACCESS_DENIED");
  }
  assert.equal(calls, 0);
});

test("missing broker RPC and upstream failures never leak provider exceptions", async () => {
  await denied(() => readAdminWorkerAssignments(stage, authorized()),
    "ADMIN_ASSIGNMENT_BROKER_UNAVAILABLE");
  await denied(() => readAdminWorkerAssignments({
    ...stage, BKE_GITHUB_READ_BROKER: {
      listVerifiedWorkerAssignments() { throw Error("ghs_fake-secret"); },
    },
  }, authorized()), "ADMIN_ASSIGNMENT_BROKER_UNAVAILABLE");
});

test("rejects tampered authority, scope and unknown top-level fields", async () => {
  for (const patch of [
    { principal: "user" }, { authority: "ARBITRARY" },
    { repository_scope: "ALL_ORG_REPOSITORIES" },
    { consistency: "ATOMIC" }, { installation_id: "0" },
    { installation_id: "5;secret" }, { token: "ghs_secret" },
    { verified: true }, { dispatch_authority: "ACTIVE" },
  ]) {
    await denied(() => readAdminWorkerAssignments(makeEnv({ ...base, ...patch }),
      authorized()), "ADMIN_ASSIGNMENT_RESPONSE_INVALID");
  }
});

test("rejects invalid totals, truncation, over-capacity and inconsistent claims", async () => {
  for (const patch of [
    { total_visible_repositories: 0 }, { total_visible_repositories: 101 },
    { enumerated_open_pull_requests: -1 },
    { enumerated_open_pull_requests: 2001 },
    { enumerated_open_pull_requests: 1 },
    { worker_assignments: null },
    { worker_assignments: Array.from({ length: 501 }, () => base.worker_assignments[0]) },
  ]) {
    await denied(() => readAdminWorkerAssignments(makeEnv({ ...base, ...patch }),
      authorized()), "ADMIN_ASSIGNMENT_RESPONSE_INVALID");
  }
});

test("duplicate worker ID anywhere in installation fails closed", async () => {
  const duplicate = { ...base.worker_assignments[1], labels: ["bke-worker:worker-a"] };
  await denied(() => readAdminWorkerAssignments(makeEnv({
    ...base, worker_assignments: [base.worker_assignments[0], duplicate],
  }), authorized()), "ADMIN_ASSIGNMENT_RESPONSE_INVALID");
});

test("duplicate PR identity, even case-variant repo, fails closed", async () => {
  const one = base.worker_assignments[0];
  const duplicate = { ...one, repository: "JAN2XO/BKE-WORKER",
    labels: ["bke-worker:worker-c"] };
  await denied(() => readAdminWorkerAssignments(makeEnv({
    ...base, worker_assignments: [one, duplicate],
  }), authorized()), "ADMIN_ASSIGNMENT_RESPONSE_INVALID");
});

test("repository ID mismatch and invalid repository path fail closed", async () => {
  const one = base.worker_assignments[0];
  for (const corrupt of [
    { ...base.worker_assignments[1], repository_id: one.repository_id },
    { ...base.worker_assignments[1], repository: one.repository },
    { ...base.worker_assignments[1], repository: "../outside" },
    { ...base.worker_assignments[1], repository: "jan2xo/sub/owner" },
  ]) {
    await denied(() => readAdminWorkerAssignments(makeEnv({
      ...base, worker_assignments: [one, corrupt],
    }), authorized()), "ADMIN_ASSIGNMENT_RESPONSE_INVALID");
  }
});

test("rejects malformed head, PR, state, unrecognized worker label or extra fields", async () => {
  const valid = base.worker_assignments[0];
  for (const patch of [
    { head_sha: "x" }, { number: 0 }, { state: "closed" },
    { labels: [] }, { labels: ["bke-worker:Worker-B"] },
    { labels: ["bke-worker:worker-c", "bke-worker:worker-d"] },
    { labels: ["triage"] }, { token: "ghs_fake" },
  ]) await denied(() => readAdminWorkerAssignments(makeEnv({
    ...base, worker_assignments: [{ ...valid, ...patch }],
  }), authorized()), "ADMIN_ASSIGNMENT_RESPONSE_INVALID");
});

test("empty observed claims remains UNKNOWN for free-worker status", async () => {
  const state = await readAdminWorkerAssignments(makeEnv({
    ...base, enumerated_open_pull_requests: 0, worker_assignments: [],
  }), authorized());
  const safe = publicWorkerAssignmentProjection(state);
  assert.equal(safe.state, "OBSERVED_ONLY");
  assert.equal(safe.dispatch_authority, "NONE");
  assert.equal(safe.assignments.length, 0);
  assert.equal("prSnapshotVerified" in safe, false);
  assert.equal("free_worker" in safe, false);
});

const request = (route = "/api/admin/worker-assignments", init = {}) =>
  new Request("https://cc.jl-bke.com" + route, init);

test("read-only API route defaults OFF and never calls broker", async () => {
  let calls = 0;
  const env = makeEnv(base, () => calls++);
  env.BKE_ADMIN_PR_INVENTORY_ENABLED = undefined;
  const res = await preproductionFetch(request(), env, authorized());
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(),
    { error: "ADMIN_ASSIGNMENT_READ_DISABLED", state: "LOCKED" });
  assert.equal(calls, 0);
  assert.equal(res.headers.get("cache-control"), "no-store");
});

test("API requires human Access and rejects browser-supplied identity assertion", async () => {
  let calls = 0;
  const env = makeEnv(base, () => calls++);
  const rq = request(undefined, {
    headers: { "cf-access-jwt-assertion": "forged.jwt", "cf-access-authenticated-user-email": "admin@example.test" },
  });
  const res = await preproductionFetch(rq, env);
  assert.equal(res.status, 403);
  assert.deepEqual(await res.json(),
    { error: "ADMIN_ASSIGNMENT_ACCESS_DENIED", state: "DENIED" });
  assert.equal(calls, 0);
});

test("on-demand Admin GET returns sanitized observations, no installation identity", async () => {
  let calls = 0;
  const env = makeEnv(base, () => calls++);
  const res = await preproductionFetch(request(), env, authorized());
  assert.equal(res.status, 200);
  const value = await res.json();
  assert.equal(calls, 1);
  assert.equal(value.state, "OBSERVED_ONLY");
  assert.equal(value.assignments.length, 2);
  assert.equal(value.dispatch_authority, "NONE");
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.doesNotMatch(JSON.stringify(value), /installation_id|ghs_|Bearer|token/iu);
});

test("API cannot accept mutation, arbitrary query or leaked provider exception", async () => {
  const env = makeEnv(base);
  const post = await preproductionFetch(request(undefined, { method: "POST" }), env, authorized());
  assert.equal(post.status, 405);
  const query = await preproductionFetch(request("/api/admin/worker-assignments?repo=evil"),
    env, authorized());
  assert.equal(query.status, 400);
  const broken = await preproductionFetch(request(), {
    ...env, BKE_GITHUB_READ_BROKER: {
      async listVerifiedWorkerAssignments() { throw Error("ghs_should-stay-private"); },
    },
  }, authorized());
  assert.equal(broken.status, 503);
  assert.deepEqual(await broken.json(),
    { error: "ADMIN_ASSIGNMENT_BROKER_UNAVAILABLE", state: "UNKNOWN" });
});

test("runtime source still leaves pairing and inventory flags OFF", () => {
  const wr = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.doesNotMatch(wr, /BKE_ADMIN_PR_INVENTORY_ENABLED\s*=\s*"true"/u);
  assert.doesNotMatch(wr, /BKE_ADMIN_PAIRING_ACTIONS_ENABLED\s*=\s*"true"/u);
});
