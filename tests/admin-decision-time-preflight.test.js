import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { inspectDecisionTimePairingPreflight } from "../src/admin-decision-time-preflight.js";
import { webcrypto } from "node:crypto";
import { createAdminOneTimeActionTickets } from "../src/admin-one-time-action-tickets.js";
import { createPairingAtomicStore } from "../src/worker-pairing-durable-store.js";

const ctx = { access: {
  aud: "0123456789abcdef0123456789abcdef",
  async getIdentity() { return { email: "admin@example.test" }; },
} };
const env = {
  BKE_PREPRODUCTION: "true", BKE_ACCESS_POLICY_VERIFIED: "true",
  BKE_ADMIN_PR_INVENTORY_ENABLED: "true",
  BKE_ADMIN_PAIRING_ACTIONS_ENABLED: "true",
  BKE_ADMIN_DECISION_RECHECK_ENABLED: "true",
  BKE_ADMIN_DISCOVERY_ENABLED: "true",
  BKE_ADMIN_ACCESS_ISSUER: "https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD: ctx.access.aud,
  BKE_ADMIN_EMAILS: "admin@example.test",
};
const claim = (worker_id = "worker-a", head_sha = "c".repeat(40)) => ({
  worker_id, head_sha, repository: "jan2xo/bke-worker",
  repository_id: 1354026486, pr_number: 104,
});
const snapshot = (patch = {}) => ({
  state: "OBSERVED_ONLY", source: "GITHUB_APP_INSTALLATION",
  consistency: "NON_ATOMIC_ENUMERATION", dispatch_authority: "NONE",
  trusted_installation_id: "51", approved_repository_count: 76,
  enumerated_open_pr_count: 123, worker_claims: [claim()], ...patch,
});
const proof = { challenge_id: "a".repeat(32), one_time_nonce: "b".repeat(64) };
function fixture({ reads = [snapshot(), snapshot()], result, envPatch, ticket, executionCtx,
  readFailure, failTicket, times } = {}) {
  let calls = 0, consumes = 0, clockIndex = 0;
  const input = {
    env: { ...env, ...envPatch },
    executionCtx: executionCtx === undefined ? ctx : executionCtx,
    trustedInstallationId: "51", workerId: "worker-b",
    ticket: ticket ?? proof,
    ticketManager: { async consume() {
      consumes++;
      if (failTicket) throw Error("UPSTREAM_FAILURE");
      return result ?? { state: "CONSUMED_FOR_PREFLIGHT", code: "ADMIN_ACTION_SINGLE_USE_OK" };
    } },
    readAssignments: async () => {
      const i = calls++;
      if (readFailure === i) throw Error("UPSTREAM_FAILURE");
      return structuredClone(reads[Math.min(i, reads.length - 1)]);
    },
    clock: () => times ? times[Math.min(clockIndex++, times.length - 1)] : 100000,
  };
  return { input, stats: () => [calls, consumes] };
}
function blocked(output, code) {
  assert.deepEqual(output, { state: "BLOCKED", code });
}

test("stable two-read preflight consumes exactly once and never authorizes pairing", async () => {
  const f = fixture();
  const output = await inspectDecisionTimePairingPreflight(f.input);
  assert.deepEqual(output, {
    state: "CHECKED_NOT_RESERVED", code: "DECISION_PREFLIGHT_NON_ATOMIC",
    dispatch_authority: "NONE", pairing_authority: "NONE",
  });
  assert.deepEqual(f.stats(), [2, 1]);
  assert.equal(Object.isFrozen(output), true);
});

test("feature locks fail before reading provider data", async () => {
  for (const flag of ["BKE_PREPRODUCTION", "BKE_ACCESS_POLICY_VERIFIED",
    "BKE_ADMIN_PR_INVENTORY_ENABLED", "BKE_ADMIN_PAIRING_ACTIONS_ENABLED",
    "BKE_ADMIN_DECISION_RECHECK_ENABLED"]) {
    const f = fixture({ envPatch: { [flag]: undefined } });
    blocked(await inspectDecisionTimePairingPreflight(f.input), "DECISION_PREFLIGHT_LOCKED");
    assert.deepEqual(f.stats(), [0, 0]);
  }
});

test("unverified human Access and invalid ticket are rejected without I/O", async () => {
  const deniedCtx = { access: { ...ctx.access,
    async getIdentity() { return { email: "different@example.test" }; } } };
  const f = fixture({ executionCtx: deniedCtx });
  blocked(await inspectDecisionTimePairingPreflight(f.input), "DECISION_PREFLIGHT_ADMIN_DENIED");
  assert.deepEqual(f.stats(), [0, 0]);
  const bad = fixture({ ticket: { ...proof, invalid: true } });
  blocked(await inspectDecisionTimePairingPreflight(bad.input), "DECISION_PREFLIGHT_INPUT_INVALID");
  assert.deepEqual(bad.stats(), [0, 0]);
});

test("pre-existing worker assignment blocks before ticket consumption", async () => {
  const f = fixture({ reads: [snapshot({ worker_claims: [claim("worker-b")] })] });
  blocked(await inspectDecisionTimePairingPreflight(f.input),
    "DECISION_PREFLIGHT_WORKER_CLAIMED");
  assert.deepEqual(f.stats(), [1, 0]);
});

test("new competing claim after ticket burn blocks without granting authority", async () => {
  const f = fixture({ reads: [snapshot(),
    snapshot({ worker_claims: [claim("worker-b")] })] });
  blocked(await inspectDecisionTimePairingPreflight(f.input),
    "DECISION_PREFLIGHT_WORKER_CLAIMED");
  assert.deepEqual(f.stats(), [2, 1]);
});

test("changed PR head, repository totals and installation all fail closed", async () => {
  for (const patch of [
    { worker_claims: [claim("worker-a", "d".repeat(40))] },
    { approved_repository_count: 75 },
    { enumerated_open_pr_count: 124 },
    { worker_claims: [] },
  ]) {
    const f = fixture({ reads: [snapshot(), snapshot(patch)] });
    blocked(await inspectDecisionTimePairingPreflight(f.input),
      "DECISION_PREFLIGHT_GITHUB_CHANGED");
  }
  const changed = fixture({ reads: [snapshot(), snapshot({ trusted_installation_id: "52" })] });
  blocked(await inspectDecisionTimePairingPreflight(changed.input),
    "DECISION_PREFLIGHT_EVIDENCE_INVALID");
});

test("incomplete, polluted, duplicate, or unavailable snapshot never authorizes", async () => {
  for (const patch of [
    { state: "ACTIVE" },
    { consistency: "ATOMIC" },
    { worker_claims: [claim(), claim()] },
    { worker_claims: [{ ...claim(), head_sha: "unknown" }] },
    { worker_claims: null },
    { installation_id: "untrusted" },
  ]) {
    const f = fixture({ reads: [snapshot(patch)] });
    blocked(await inspectDecisionTimePairingPreflight(f.input),
      "DECISION_PREFLIGHT_EVIDENCE_INVALID");
  }
  for (const idx of [0, 1]) {
    const f = fixture({ readFailure: idx });
    blocked(await inspectDecisionTimePairingPreflight(f.input),
      "DECISION_PREFLIGHT_EVIDENCE_UNAVAILABLE");
    assert.equal(f.stats()[1], idx === 0 ? 0 : 1);
  }
});

test("ticket rejection and storage failure forbid post-consume status", async () => {
  const invalid = fixture({ result: { state: "BLOCKED", code: "USED" } });
  blocked(await inspectDecisionTimePairingPreflight(invalid.input),
    "DECISION_PREFLIGHT_TICKET_REJECTED");
  assert.deepEqual(invalid.stats(), [1, 1]);
  const failed = fixture({ failTicket: true });
  blocked(await inspectDecisionTimePairingPreflight(failed.input),
    "DECISION_PREFLIGHT_TICKET_UNAVAILABLE");
  assert.deepEqual(failed.stats(), [1, 1]);
});

test("30s window and reversed server clock fail closed", async () => {
  for (const times of [[100000, 130001], [100000, 99999]]) {
    const f = fixture({ times });
    blocked(await inspectDecisionTimePairingPreflight(f.input),
      "DECISION_PREFLIGHT_WINDOW_EXPIRED");
  }
});

test("source remains off and disconnected from public routes and Durable Object RPC", () => {
  const index = readFileSync(new URL("../src/index.js", import.meta.url), "utf8");
  const wrangler = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.doesNotMatch(index, /admin-decision-time-preflight/u);
  assert.doesNotMatch(wrangler, /BKE_ADMIN_DECISION_RECHECK_ENABLED/u);
});

test("actual installation ticket is consumed once across repeated decision checks", async () => {
  let data = new Map(), gate = Promise.resolve();
  const storage = { async transaction(fn) {
    let unlock;
    const next = new Promise(resolve => { unlock = resolve; });
    const previous = gate; gate = next;
    await previous;
    const staged = new Map(structuredClone([...data]));
    try {
      const answer = await fn({
        get: async key => structuredClone(staged.get(key)),
        put: async (key, value) => { staged.set(key, structuredClone(value)); },
      });
      data = staged;
      return answer;
    } finally { unlock(); }
  } };
  const tickets = createAdminOneTimeActionTickets({
    store: createPairingAtomicStore(storage), installationId: "51",
    cryptoImpl: webcrypto, clock: () => 100000,
    authorizeAdmin: async (action, workerId, subjectCtx) =>
      action === "pair" && workerId === "worker-b" && subjectCtx === ctx
        ? "f".repeat(64) : null,
  });
  const issued = await tickets.issue({
    action: "pair", worker_id: "worker-b", admin_context: ctx,
  });
  assert.equal(issued.state, "ISSUED_FOR_CONFIRMATION");
  const f = fixture();
  f.input.ticketManager = tickets;
  f.input.ticket = {
    challenge_id: issued.challenge_id, one_time_nonce: issued.one_time_nonce,
  };
  assert.equal((await inspectDecisionTimePairingPreflight(f.input)).state,
    "CHECKED_NOT_RESERVED");
  blocked(await inspectDecisionTimePairingPreflight(f.input),
    "DECISION_PREFLIGHT_TICKET_REJECTED");
});
