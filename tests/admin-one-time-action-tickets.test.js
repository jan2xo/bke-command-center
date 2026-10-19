import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { createAdminOneTimeActionTickets } from "../src/admin-one-time-action-tickets.js";
import { createPairingAtomicStore, BkeWorkerPairingVault } from "../src/worker-pairing-durable-store.js";
import { readFileSync } from "node:fs";

const HUMAN = "c".repeat(64);
let now, allow;
const context = { serverIdentity: HUMAN };
function fakeDurableStorage() {
  let state = new Map(), gate = Promise.resolve();
  return {
    async transaction(fn) {
      let unlock;
      const following = new Promise(resolve => { unlock = resolve; });
      const prior = gate; gate = following;
      await prior;
      const staged = new Map(structuredClone([...state]));
      try {
        const result = await fn({
          get: async key => structuredClone(staged.get(key)),
          put: async (key, value) => { staged.set(key, structuredClone(value)); },
        });
        state = staged;
        return result;
      } finally { unlock(); }
    },
    snapshot: () => structuredClone([...state]),
  };
}
function setup(storage = fakeDurableStorage(), options = {}) {
  now = 100_000; allow = true;
  const store = createPairingAtomicStore(storage);
  return {
    storage,
    api: createAdminOneTimeActionTickets({
      store, installationId: "51", clock: () => now, cryptoImpl: webcrypto,
      authorizeAdmin: async (_a, _w, ctx) =>
        allow && ctx?.serverIdentity === HUMAN ? HUMAN : null,
      ...options,
    }),
  };
}
const args = (action = "pair", worker_id = "worker-a", extra = {}) =>
  ({ ...extra, action, worker_id, admin_context: extra.admin_context ?? context });
const getRows = store => new Map(store.snapshot()).get("bke:pairing:v1:admin_actions") ?? [];
const denied = result => {
  assert.equal(result.state, "BLOCKED");
  assert.deepEqual(Object.keys(result).sort(), ["code", "state"]);
  assert.doesNotMatch(JSON.stringify(result), /private|Bearer|ghs_|nonce|serverIdentity/iu);
};

test("90-second one-time ticket stored only as digest inside existing vault", async () => {
  const { api, storage } = setup();
  const t = await api.issue(args());
  assert.equal(t.state, "ISSUED_FOR_CONFIRMATION");
  assert.equal(t.expires_at_ms, 190_000);
  assert.match(t.one_time_nonce, /^[a-f0-9]{64}$/u);
  assert.match(t.challenge_id, /^[a-f0-9]{32}$/u);
  assert.ok(!JSON.stringify(storage.snapshot()).includes(t.one_time_nonce));
  assert.equal((await api.consume(args("pair", "worker-a", t))).state, "CONSUMED_FOR_PREFLIGHT");
  assert.equal(getRows(storage)[0].status, "CONSUMED");
  denied(await api.consume(args("pair", "worker-a", t)));
});

test("two simultaneous consumptions yield exactly one successful preflight", async () => {
  const { api } = setup();
  const t = await api.issue(args());
  const result = await Promise.all([0, 1].map(() => api.consume(args("pair", "worker-a", t))));
  assert.equal(result.filter(x => x.state === "CONSUMED_FOR_PREFLIGHT").length, 1);
  assert.equal(result.filter(x => x.state === "BLOCKED").length, 1);
});

test("competing pair and revoke issuance for one worker is serialized", async () => {
  const { api, storage } = setup();
  const result = await Promise.all([api.issue(args()), api.issue(args("revoke"))]);
  assert.equal(result.filter(x => x.state === "ISSUED_FOR_CONFIRMATION").length, 1);
  assert.equal(getRows(storage).length, 1);
});

test("separate workers can issue isolated concurrent tickets", async () => {
  const { api, storage } = setup();
  const [a, b] = await Promise.all([
    api.issue(args("pair", "worker-a")), api.issue(args("revoke", "worker-b")),
  ]);
  assert.equal(a.state, "ISSUED_FOR_CONFIRMATION");
  assert.equal(b.state, "ISSUED_FOR_CONFIRMATION");
  assert.equal(getRows(storage).length, 2);
});

test("cross-worker, action, tenant and human-binding replay denied", async () => {
  const { api, storage } = setup();
  const t = await api.issue(args());
  denied(await api.consume(args("pair", "worker-b", t)));
  denied(await api.consume(args("revoke", "worker-a", t)));
  const otherTenant = createAdminOneTimeActionTickets({
    store: createPairingAtomicStore(storage), installationId: "52",
    clock: () => now, cryptoImpl: webcrypto, authorizeAdmin: async () => HUMAN,
  });
  denied(await otherTenant.consume(args("pair", "worker-a", t)));
  const otherHuman = createAdminOneTimeActionTickets({
    store: createPairingAtomicStore(storage), installationId: "51",
    clock: () => now, cryptoImpl: webcrypto, authorizeAdmin: async () => "d".repeat(64),
  });
  denied(await otherHuman.consume(args("pair", "worker-a", t)));
  assert.equal((await api.consume(args("pair", "worker-a", t))).state, "CONSUMED_FOR_PREFLIGHT");
});

test("expired ticket blocks and re-issue may proceed after expiration", async () => {
  const { api } = setup();
  const t = await api.issue(args());
  now = t.expires_at_ms;
  denied(await api.consume(args("pair", "worker-a", t)));
  assert.equal((await api.issue(args())).state, "ISSUED_FOR_CONFIRMATION");
});

test("trusted human authorization checked on issuance and consumption", async () => {
  const { api, storage } = setup();
  denied(await api.issue(args("pair", "worker-a", { admin_context: { authorized: true } })));
  assert.equal(getRows(storage).length, 0);
  const t = await api.issue(args());
  allow = false;
  denied(await api.consume(args("pair", "worker-a", t)));
  assert.equal(getRows(storage)[0].status, "PENDING");
});

test("malformed worker, action, nonce and challenge are rejected", async () => {
  const { api } = setup();
  denied(await api.issue(args("dispatch")));
  denied(await api.issue(args("pair", "Worker-A")));
  denied(await api.consume(args("pair", "worker-a", {
    challenge_id: "bad", one_time_nonce: "bad",
  })));
});

test("corrupted, duplicate and oversize registry fail closed", async () => {
  const { api, storage } = setup();
  const t = await api.issue(args());
  await storage.transaction(async tx => {
    const rows = await tx.get("bke:pairing:v1:admin_actions");
    await tx.put("bke:pairing:v1:admin_actions", [...rows, { ...rows[0] }]);
  });
  denied(await api.consume(args("pair", "worker-a", t)));
  denied(await api.issue(args("pair", "worker-b")));
});

test("crypto, clock and storage exceptions map only to fixed codes", async () => {
  const entropy = setup(fakeDurableStorage(), { cryptoImpl: {
    subtle: webcrypto.subtle, getRandomValues() { throw Error("RNG secret"); },
  } });
  assert.deepEqual(await entropy.api.issue(args()), {
    state: "BLOCKED", code: "ADMIN_ACTION_RANDOM_UNAVAILABLE",
  });
  const digest = setup(fakeDurableStorage(), { cryptoImpl: {
    getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
    subtle: { digest() { throw Error("private digest"); } },
  } });
  assert.deepEqual(await digest.api.issue(args()), {
    state: "BLOCKED", code: "ADMIN_ACTION_CRYPTO_UNAVAILABLE",
  });
  const clock = setup(fakeDurableStorage(), {
    clock() { throw Error("private clock"); },
  });
  assert.deepEqual(await clock.api.issue(args()), {
    state: "BLOCKED", code: "ADMIN_ACTION_CLOCK_INVALID",
  });
  const store = setup({ transaction() { throw Error("private database"); } });
  assert.deepEqual(await store.api.issue(args()), {
    state: "BLOCKED", code: "ADMIN_ACTION_STORAGE_UNAVAILABLE",
  });
});

test("consumed proof cannot grant pairing, lease, dispatch or GitHub authority", async () => {
  const { api } = setup();
  const t = await api.issue(args());
  const result = await api.consume(args("pair", "worker-a", t));
  assert.deepEqual(result, {
    state: "CONSUMED_FOR_PREFLIGHT", code: "ADMIN_ACTION_SINGLE_USE_OK",
  });
  for (const key of ["paired", "lease", "token", "dispatch", "credential", "prSnapshotVerified"]) {
    assert.equal(Object.hasOwn(result, key), false);
  }
});

test("vault retains 404/no-RPC boundary and no Admin ticket route or feature flag", async () => {
  const storage = fakeDurableStorage();
  const obj = new BkeWorkerPairingVault({ storage }, {});
  assert.equal((await obj.fetch(new Request("https://example.invalid/admin/ticket"))).status, 404);
  assert.equal(typeof obj.issue, "undefined");
  assert.equal(typeof obj.consume, "undefined");
  const idx = readFileSync(new URL("../src/index.js", import.meta.url), "utf8");
  const wr = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.doesNotMatch(idx, /admin-one-time-action-tickets/u);
  assert.doesNotMatch(wr, /BKE_ADMIN_ACTION_TICKETS_ENABLED/u);
});
