import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { createPairingAtomicStore } from "../src/worker-pairing-durable-store.js";
import { createWorkerPairingCeremony } from "../src/worker-pairing-ceremony.js";
import { createAdminOneTimeActionTickets } from "../src/admin-one-time-action-tickets.js";
import { createProtectedInactivePairing } from "../src/protected-inactive-pairing.js";

const HUMAN = "f".repeat(64);
const ctx = { access: { aud: "0123456789abcdef0123456789abcdef",
  async getIdentity() { return { email: "admin@example.test" }; } } };
const env = {
  BKE_PREPRODUCTION: "true", BKE_ACCESS_POLICY_VERIFIED: "true",
  BKE_ADMIN_PR_INVENTORY_ENABLED: "true",
  BKE_ADMIN_PAIRING_ACTIONS_ENABLED: "true",
  BKE_ADMIN_PROTECTED_PAIRING_ENABLED: "true",
  BKE_ADMIN_DISCOVERY_ENABLED: "true",
  BKE_ADMIN_ACCESS_ISSUER: "https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD: ctx.access.aud,
  BKE_ADMIN_EMAILS: "admin@example.test",
};
const observed = (overrides = {}) => ({
  state: "OBSERVED_ONLY", source: "GITHUB_APP_INSTALLATION",
  consistency: "NON_ATOMIC_ENUMERATION", dispatch_authority: "NONE",
  trusted_installation_id: "51", approved_repository_count: 76,
  enumerated_open_pr_count: 0, worker_claims: [], ...overrides,
});
const resources = (i = 0) => ({
  chatgpt_target_sha256: "123456789abcdef0"[i].repeat(64),
  browser_profile_sha256: "123456789abcdef0"[i + 4].repeat(64),
  bridge_identity_sha256: "123456789abcdef0"[i + 8].repeat(64),
});
const blocked = (output, code) => {
  assert.deepEqual(output, { state: "BLOCKED", code });
  assert.doesNotMatch(JSON.stringify(output), /ghs_|Bearer|privateKey|admin@example/u);
};

function fakeStorage() {
  let state = new Map(), gate = Promise.resolve();
  return {
    failOnWrite: null,
    async transaction(fn) {
      let release;
      const next = new Promise(resolve => { release = resolve; });
      const last = gate; gate = next;
      await last;
      const shadow = new Map(structuredClone([...state]));
      let writes = 0;
      try {
        const outcome = await fn({
          get: async key => structuredClone(shadow.get(key)),
          put: async (key, value) => {
            if (++writes === this.failOnWrite) throw Error("private provider exception");
            shadow.set(key, structuredClone(value));
          },
        });
        state = shadow;
        return outcome;
      } finally { release(); }
    },
    get: name => structuredClone(state.get("bke:pairing:v1:" + name)),
  };
}

function setup({ snapshot = observed(), now = 100000, installationId = "51",
  subject = HUMAN, readFail = false } = {}) {
  const storage = fakeStorage(), store = createPairingAtomicStore(storage);
  let time = now, currentSnapshot = snapshot, failRead = readFail;
  const authorize = async (_action, _worker, actualCtx) =>
    actualCtx === ctx ? subject : null;
  const tickets = createAdminOneTimeActionTickets({
    store, installationId, cryptoImpl: webcrypto, clock: () => time,
    authorizeAdmin: authorize,
  });
  const challenge = createWorkerPairingCeremony({
    store, installationId, cryptoImpl: webcrypto, clock: () => time,
    authorizeAdmin: async (_action, _worker, c) => c === ctx,
    readLiveAssignments: async () => ({ verified: true, openPullRequests: [] }),
  });
  const finalize = createProtectedInactivePairing({
    store, installationId, cryptoImpl: webcrypto, clock: () => time,
    authorizeHumanSubject: authorize,
    readAssignments: async () => {
      if (failRead) throw Error("private provider credentials");
      return structuredClone(currentSnapshot);
    },
  });
  return { storage, tickets, challenge, finalize,
    setTime: v => { time = v; },
    setSnapshot: v => { currentSnapshot = v; },
    setReadFail: v => { failRead = v; },
  };
}
async function issued(f, worker_id = "worker-a", i = 0) {
  const key = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await webcrypto.subtle.exportKey("jwk", key.publicKey);
  const device = await f.challenge.issueChallenge({
    worker_id, public_key: { crv: "P-256", kty: "EC", x: jwk.x, y: jwk.y },
    resources: resources(i), admin_context: ctx,
  });
  assert.equal(device.state, "CHALLENGE_ISSUED");
  const signed = new Uint8Array(await webcrypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, key.privateKey,
    new TextEncoder().encode(device.message)));
  const admin = await f.tickets.issue({
    action: "pair", worker_id, admin_context: ctx,
  });
  assert.equal(admin.state, "ISSUED_FOR_CONFIRMATION");
  return {
    worker_id, device_challenge_id: device.challenge_id,
    device_signature: Buffer.from(signed).toString("base64url"),
    admin_challenge_id: admin.challenge_id,
    admin_one_time_nonce: admin.one_time_nonce,
    env, executionCtx: ctx,
  };
}

test("real signed device + human ticket commit all three records atomically", async () => {
  const f = setup();
  const req = await issued(f);
  const output = await f.finalize.finalize(req);
  assert.deepEqual(output, {
    state: "PAIRED_INACTIVE", code: "PROTECTED_PAIRING_INACTIVE_ONLY",
  });
  const paired = f.storage.get("paired");
  const tickets = f.storage.get("admin_actions");
  assert.equal(paired.length, 1);
  assert.equal(paired[0].status, "PAIRED_INACTIVE");
  assert.equal(f.storage.get("pending").length, 0);
  assert.equal(tickets[0].status, "CONSUMED");
  assert.ok(!JSON.stringify([paired, tickets]).includes(req.admin_one_time_nonce));
  blocked(await f.finalize.finalize(req), "PROTECTED_PAIRING_TICKET_MISSING_OR_USED");
});

test("two simultaneous identical finalizers can commit at most once", async () => {
  const f = setup();
  const req = await issued(f);
  const result = await Promise.all([
    f.finalize.finalize(req), f.finalize.finalize(req),
  ]);
  assert.equal(result.filter(x => x.state === "PAIRED_INACTIVE").length, 1);
  assert.equal(result.filter(x => x.state === "BLOCKED").length, 1);
  assert.equal(f.storage.get("paired").length, 1);
});

test("invalid signed device proof leaves human ticket and challenge pending", async () => {
  const f = setup();
  const req = await issued(f);
  const wrong = { ...req, device_signature: Buffer.alloc(64, 4).toString("base64url") };
  blocked(await f.finalize.finalize(wrong), "PROTECTED_PAIRING_DEVICE_PROOF_INVALID");
  assert.equal(f.storage.get("paired"), undefined);
  assert.equal(f.storage.get("admin_actions")[0].status, "PENDING");
  assert.equal(f.storage.get("pending").length, 1);
  assert.equal((await f.finalize.finalize(req)).state, "PAIRED_INACTIVE");
});

test("third-write failure rolls back paired, challenge and ticket together", async () => {
  const f = setup();
  const req = await issued(f);
  f.storage.failOnWrite = 3;
  blocked(await f.finalize.finalize(req), "PROTECTED_PAIRING_STORAGE_UNAVAILABLE");
  assert.equal(f.storage.get("paired"), undefined);
  assert.equal(f.storage.get("pending").length, 1);
  assert.equal(f.storage.get("admin_actions")[0].status, "PENDING");
  f.storage.failOnWrite = null;
  assert.equal((await f.finalize.finalize(req)).state, "PAIRED_INACTIVE");
});

test("mismatched human ticket worker/action and installation are denied", async () => {
  const f = setup();
  const req = await issued(f);
  blocked(await f.finalize.finalize({
    ...req, worker_id: "worker-b",
  }), "PROTECTED_PAIRING_TICKET_MISSING_OR_USED");
  const other = createProtectedInactivePairing({
    store: createPairingAtomicStore(f.storage), installationId: "52",
    authorizeHumanSubject: async () => HUMAN,
    readAssignments: async () => observed({ trusted_installation_id: "52" }),
    cryptoImpl: webcrypto, clock: () => 100000,
  });
  blocked(await other.finalize(req), "PROTECTED_PAIRING_TICKET_MISSING_OR_USED");
  assert.equal(f.storage.get("admin_actions")[0].status, "PENDING");
});

test("claimed worker or malformed GitHub evidence blocks before storage write", async () => {
  const f = setup();
  const req = await issued(f);
  f.setSnapshot(observed({ enumerated_open_pr_count: 1, worker_claims: [{
    repository: "jan2xo/bke-worker", repository_id: 1354026486,
    pr_number: 104, head_sha: "a".repeat(40), worker_id: "worker-a",
  }] }));
  blocked(await f.finalize.finalize(req), "PROTECTED_PAIRING_GITHUB_AMBIGUOUS");
  f.setSnapshot(observed({ consistency: "ATOMIC" }));
  blocked(await f.finalize.finalize(req), "PROTECTED_PAIRING_GITHUB_AMBIGUOUS");
  assert.equal(f.storage.get("paired"), undefined);
  assert.equal(f.storage.get("admin_actions")[0].status, "PENDING");
});

test("GitHub outage and missing Access identity fail closed", async () => {
  const f = setup();
  const req = await issued(f);
  f.setReadFail(true);
  blocked(await f.finalize.finalize(req), "PROTECTED_PAIRING_GITHUB_UNAVAILABLE");
  f.setReadFail(false);
  blocked(await f.finalize.finalize({ ...req, executionCtx: undefined }),
    "PROTECTED_PAIRING_ADMIN_DENIED");
  assert.equal(f.storage.get("admin_actions")[0].status, "PENDING");
});

test("missing opt-in flag blocks before human authorization and storage I/O", async () => {
  const f = setup();
  const req = await issued(f);
  blocked(await f.finalize.finalize({ ...req,
    env: { ...env, BKE_ADMIN_PROTECTED_PAIRING_ENABLED: undefined },
  }), "PROTECTED_PAIRING_LOCKED");
  assert.equal(f.storage.get("admin_actions")[0].status, "PENDING");
});

test("expired 90-second human ticket and expired device challenge block", async () => {
  const human = setup();
  const r1 = await issued(human);
  human.setTime(190000);
  blocked(await human.finalize.finalize(r1), "PROTECTED_PAIRING_TICKET_MISSING_OR_USED");
  const device = setup();
  const r2 = await issued(device);
  device.setTime(220000);
  blocked(await device.finalize.finalize(r2), "PROTECTED_PAIRING_TICKET_MISSING_OR_USED");
});

test("different isolated workers can register independently without shared profiles", async () => {
  const f = setup();
  const [a, b] = await Promise.all([issued(f, "worker-a", 0), issued(f, "worker-b", 1)]);
  const outcomes = await Promise.all([
    f.finalize.finalize(a), f.finalize.finalize(b),
  ]);
  assert.deepEqual(outcomes.map(x => x.state), ["PAIRED_INACTIVE", "PAIRED_INACTIVE"]);
  assert.equal(f.storage.get("paired").length, 2);
});

test("corrupted pending registry blocks without burning an admin ticket", async () => {
  const f = setup();
  const req = await issued(f);
  await f.storage.transaction(async tx => {
    const entries = await tx.get("bke:pairing:v1:pending");
    await tx.put("bke:pairing:v1:pending", [...entries, { ...entries[0] }]);
  });
  blocked(await f.finalize.finalize(req), "PROTECTED_PAIRING_REGISTRY_AMBIGUOUS");
  assert.equal(f.storage.get("admin_actions")[0].status, "PENDING");
});

test("human identity denied, malformed proof, or malformed context fail safely", async () => {
  const f = setup();
  const req = await issued(f);
  blocked(await f.finalize.finalize({ ...req, device_signature: "invalid" }),
    "PROTECTED_PAIRING_PROOF_INVALID");
  blocked(await f.finalize.finalize({ ...req,
    executionCtx: { access: { ...ctx.access,
      async getIdentity() { return { email: "unlisted@example.test" }; } } },
  }), "PROTECTED_PAIRING_ADMIN_DENIED");
  assert.equal(f.storage.get("paired"), undefined);
});

test("no HTTP route, active lease, credential grant or Cloudflare activation", () => {
  const index = readFileSync(new URL("../src/index.js", import.meta.url), "utf8");
  const wr = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.doesNotMatch(index, /protected-inactive-pairing/u);
  assert.doesNotMatch(wr, /BKE_ADMIN_PROTECTED_PAIRING_ENABLED/u);
});

test("stored challenge changing to BUSY blocks without fabricating IDLE", async () => {
  const f = setup();
  const req = await issued(f);
  await f.storage.transaction(async tx => {
    const pending = await tx.get("bke:pairing:v1:pending");
    await tx.put("bke:pairing:v1:pending",
      pending.map(row => ({ ...row, dispatch_state: "BUSY" })));
  });
  blocked(await f.finalize.finalize(req), "PROTECTED_PAIRING_ELIGIBILITY_DENIED");
  assert.equal(f.storage.get("paired"), undefined);
  assert.equal(f.storage.get("admin_actions")[0].status, "PENDING");
});

test("expired device proof fails even with a freshly issued human ticket", async () => {
  const f = setup();
  const req = await issued(f);
  f.setTime(220000);
  const refreshed = await f.tickets.issue({
    action: "pair", worker_id: "worker-a", admin_context: ctx,
  });
  assert.equal(refreshed.state, "ISSUED_FOR_CONFIRMATION");
  blocked(await f.finalize.finalize({ ...req,
    admin_challenge_id: refreshed.challenge_id,
    admin_one_time_nonce: refreshed.one_time_nonce,
  }), "PROTECTED_PAIRING_DEVICE_PROOF_INVALID");
  assert.equal(f.storage.get("paired"), undefined);
  assert.equal(f.storage.get("admin_actions")[0].status, "PENDING");
});
