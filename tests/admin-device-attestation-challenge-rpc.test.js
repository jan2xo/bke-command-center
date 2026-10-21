import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { createPairingAtomicStore, BkeWorkerPairingVault } from "../src/worker-pairing-durable-store.js";
import { receiveDeviceAttestationChallenge } from "../src/admin-device-attestation-challenge-rpc.js";

const NOW = 1_800_000_000_000;
const INSTALLATION = "123456";
const WORKER = "android-worker-a";
const AUDIENCE = "bke-command-center/preproduction/android-key-attestation/v1";
const PURPOSE = "android_key_attestation";
const STORAGE_KEY = "bke:pairing:v1:attestation_challenges";
const secret = new Uint8Array(32).fill(0x5a);
const secretB64 = Buffer.from(secret).toString("base64url");
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");

class FakeDurableStorage {
  data = new Map();
  gate = Promise.resolve();
  transactions = 0;
  failTransactions = false;

  async transaction(fn) {
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    const previous = this.gate;
    this.gate = gate;
    await previous;
    this.transactions += 1;
    const copy = new Map(structuredClone([...this.data]));
    const tx = {
      get: async key => structuredClone(copy.get(key)),
      put: async (key, value) => {
        if (this.failTransactions) throw new Error("simulated unavailable storage");
        copy.set(key, structuredClone(value));
      },
    };
    try {
      const result = await fn(tx);
      this.data = copy;
      return result;
    } finally {
      release();
    }
  }
}

function setup({ enabled = true, installationId = INSTALLATION, storage = new FakeDurableStorage() } = {}) {
  const env = {
    BKE_PREPRODUCTION: "true",
    BKE_DEVICE_ATTESTATION_CHALLENGE_RPC_ENABLED: enabled ? "true" : "false",
    BKE_DEVICE_ATTESTATION_CHALLENGE_RPC_KEY_B64: secretB64,
    BKE_WORKER_PAIRING_VAULT: {
      idFromName: name => ({ toString: () => name }),
    },
  };
  const objectId = { toString: () => "installation:" + installationId };
  return {
    env,
    objectId,
    storage,
    store: createPairingAtomicStore(storage),
    run: (request, clock = () => NOW) => receiveDeviceAttestationChallenge({
      request, env, objectId, store: createPairingAtomicStore(storage),
      cryptoImpl: webcrypto, clock,
    }),
  };
}

function fields(request) {
  if (request.action === "issue") {
    return [AUDIENCE, 1, "issue", request.installation_id, request.worker_id,
      PURPOSE, request.operation_id, request.issued_at_ms, request.expires_at_ms];
  }
  return [AUDIENCE, 1, "consume", request.installation_id, request.worker_id,
    PURPOSE, request.challenge_id, request.challenge, request.operation_id,
    request.issued_at_ms, request.expires_at_ms];
}

async function signed(action, options = {}) {
  const request = {
    action,
    installation_id: options.installation_id ?? INSTALLATION,
    worker_id: options.worker_id ?? WORKER,
    operation_id: options.operation_id ?? (action === "issue" ? "1" : "2").repeat(64),
    issued_at_ms: options.issued_at_ms ?? NOW,
    expires_at_ms: options.expires_at_ms ?? NOW + 30_000,
  };
  if (action === "consume") {
    request.challenge_id = options.challenge_id;
    request.challenge = options.challenge;
  }
  const key = await webcrypto.subtle.importKey(
    "raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  request.signature = hex(new Uint8Array(await webcrypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(JSON.stringify(fields(request))),
  )));
  return request;
}

async function issue(api, options = {}) {
  const request = await signed("issue", options);
  return { request, result: await api.run(request, options.clock ?? (() => NOW)) };
}

async function consumeRequest(challenge, options = {}) {
  return signed("consume", {
    ...options,
    challenge_id: challenge.challenge_id,
    challenge: options.challenge ?? challenge.challenge,
    operation_id: options.operation_id ?? "3".repeat(64),
    issued_at_ms: options.issued_at_ms ?? NOW,
    expires_at_ms: options.expires_at_ms ?? NOW + 30_000,
  });
}

test("issues a server-generated 256-bit challenge and persists only its SHA-256 digest", async () => {
  const api = setup();
  const issued = await issue(api);
  assert.equal(issued.result.state, "CHALLENGE_ISSUED");
  assert.equal(issued.result.authority, "NONE");
  assert.match(issued.result.challenge_id, /^[a-f0-9]{32}$/u);
  assert.match(issued.result.challenge, /^[a-f0-9]{64}$/u);
  assert.equal(issued.result.audience, AUDIENCE);
  assert.equal(issued.result.purpose, PURPOSE);

  const rows = api.storage.data.get(STORAGE_KEY);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].challenge_sha256,
    hex(new Uint8Array(await webcrypto.subtle.digest(
      "SHA-256", new TextEncoder().encode(issued.result.challenge),
    ))));
  assert.equal(JSON.stringify(rows).includes(issued.result.challenge), false);
  assert.equal(rows[0].installation_id, INSTALLATION);
  assert.equal(rows[0].worker_id, WORKER);
});

test("same issue operation cannot mint a second challenge", async () => {
  const api = setup();
  const issued = await issue(api);
  assert.equal(issued.result.state, "CHALLENGE_ISSUED");
  const replay = await api.run(issued.request);
  assert.deepEqual(replay, {
    state: "BLOCKED", code: "ATTESTATION_CHALLENGE_ISSUE_REPLAY", authority: "NONE",
  });
  assert.equal(api.storage.data.get(STORAGE_KEY).length, 1);
});

test("concurrent consume attempts atomically produce exactly one success; replay has no authority", async () => {
  const api = setup();
  const { result: issued } = await issue(api);
  const req = await consumeRequest(issued);
  const [first, second] = await Promise.all([api.run(req), api.run(req)]);
  assert.equal([first, second].filter(x => x.state === "CHALLENGE_CONSUMED").length, 1);
  assert.equal([first, second].filter(x => x.code === "ATTESTATION_CHALLENGE_REPLAY").length, 1);
  const success = [first, second].find(x => x.state === "CHALLENGE_CONSUMED");
  assert.equal(success.authority, "NONE");
  const row = api.storage.data.get(STORAGE_KEY)[0];
  assert.equal(Number.isSafeInteger(row.consumed_at_ms), true);
  assert.equal(row.consume_operation_id, req.operation_id);
});

test("rejects wrong worker, installation and challenge value without consuming the valid row", async () => {
  const api = setup();
  const { result: issued } = await issue(api);

  const wrongWorker = await consumeRequest(issued, { worker_id: "android-worker-b", operation_id: "4".repeat(64) });
  assert.equal((await api.run(wrongWorker)).code, "ATTESTATION_CHALLENGE_SCOPE_MISMATCH");

  const wrongInstallation = await consumeRequest(issued, {
    installation_id: "999999", operation_id: "5".repeat(64),
  });
  assert.equal((await api.run(wrongInstallation)).code, "ATTESTATION_CHALLENGE_INSTALLATION_MISMATCH");

  const wrongChallenge = await consumeRequest(issued, {
    challenge: "f".repeat(64), operation_id: "6".repeat(64),
  });
  assert.equal((await api.run(wrongChallenge)).code, "ATTESTATION_CHALLENGE_VALUE_MISMATCH");

  const valid = await api.run(await consumeRequest(issued, { operation_id: "7".repeat(64) }));
  assert.equal(valid.state, "CHALLENGE_CONSUMED");
  assert.equal(valid.authority, "NONE");
});

test("rejects stale command, expired challenge and altered MAC", async () => {
  const api = setup();
  const stale = await signed("issue", {
    operation_id: "8".repeat(64),
    issued_at_ms: NOW - 31_000,
    expires_at_ms: NOW - 1,
  });
  assert.equal((await api.run(stale)).code, "ATTESTATION_CHALLENGE_COMMAND_STALE");

  const { result: issued } = await issue(api, {
    operation_id: "9".repeat(64),
    expires_at_ms: NOW + 1_000,
  });
  assert.equal(issued.state, "CHALLENGE_ISSUED");
  const lateConsume = await consumeRequest(issued, {
    operation_id: "a".repeat(64),
    issued_at_ms: NOW + 1_001,
    expires_at_ms: NOW + 20_000,
  });
  const expiredResult = await api.run(lateConsume, () => NOW + 1_001);
  assert.equal(expiredResult.code, "ATTESTATION_CHALLENGE_EXPIRED");

  const freshIssue = await signed("issue", {
    operation_id: "b".repeat(64),
  });
  freshIssue.signature = "0".repeat(64);
  assert.equal((await api.run(freshIssue)).code, "ATTESTATION_CHALLENGE_COMMAND_INVALID");
});

test("wrong Durable Object and unconfigured/default-off runtime fail closed; fetch stays 404", async () => {
  const api = setup({ installationId: "123456" });
  const { request } = await issue(api);
  const wrongObject = {
    request,
    env: api.env,
    objectId: { toString: () => "installation:999999" },
    store: api.store,
    cryptoImpl: webcrypto,
    clock: () => NOW,
  };
  assert.equal((await receiveDeviceAttestationChallenge(wrongObject)).code,
    "ATTESTATION_CHALLENGE_INSTALLATION_MISMATCH");

  const off = setup({ enabled: false });
  assert.equal((await off.run(await signed("issue"))).code, "ATTESTATION_CHALLENGE_RPC_LOCKED");

  const durable = new FakeDurableStorage();
  const vault = new BkeWorkerPairingVault({ id: { toString: () => "installation:123456" }, storage: durable }, {});
  assert.equal((await vault.manageDeviceAttestationChallenge({ action: "issue" })).code,
    "ATTESTATION_CHALLENGE_RPC_LOCKED");
  assert.equal((await vault.fetch(new Request("https://example.invalid/attestation"))).status, 404);
  assert.equal(durable.transactions, 0);

  const wrangler = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.doesNotMatch(wrangler, /BKE_DEVICE_ATTESTATION_CHALLENGE_RPC_ENABLED\s*=\s*"true"/u);
});

test("storage failures and a full live ledger return blocked states without granting authority", async () => {
  const failedStorage = new FakeDurableStorage();
  failedStorage.failTransactions = true;
  const failed = setup({ storage: failedStorage });
  assert.equal((await issue(failed)).result.code,
    "ATTESTATION_CHALLENGE_ISSUE_OUTCOME_UNCERTAIN");

  const fullStorage = new FakeDurableStorage();
  fullStorage.data.set(STORAGE_KEY, Array.from({ length: 100 }, (_, index) => ({
    challenge_id: index.toString(16).padStart(32, "0"),
    challenge_sha256: "a".repeat(64),
    installation_id: INSTALLATION,
    worker_id: WORKER,
    audience: AUDIENCE,
    purpose: PURPOSE,
    issued_at_ms: NOW - 1,
    expires_at_ms: NOW + 10_000,
    issue_operation_id: (index + 1).toString(16).padStart(64, "0"),
    consumed_at_ms: null,
    consume_operation_id: null,
  })));
  const full = setup({ storage: fullStorage });
  assert.equal((await issue(full, { operation_id: "c".repeat(64) })).result.code,
    "ATTESTATION_CHALLENGE_LEDGER_FULL");
  assert.equal(fullStorage.data.get(STORAGE_KEY).length, 100);
});


test("corrupt duplicate ledger rows and out-of-range consumed timestamps fail closed", async () => {
  const seeded = new FakeDurableStorage();
  const api = setup({ storage: seeded });
  const { result: issued } = await issue(api);
  const existing = seeded.data.get(STORAGE_KEY)[0];

  // Duplicate IDs/issue operation IDs must not be interpreted heuristically.
  seeded.data.set(STORAGE_KEY, [structuredClone(existing), structuredClone(existing)]);
  const dupConsume = await api.run(await consumeRequest(issued, { operation_id: "d".repeat(64) }));
  assert.equal(dupConsume.code, "ATTESTATION_CHALLENGE_CONSUME_OUTCOME_UNCERTAIN");
  assert.equal(seeded.data.get(STORAGE_KEY).length, 2);

  // Restore one row, then tamper with its durable state to a time impossible
  // for this server-owned protocol. Reads must fail closed before mutation.
  seeded.data.set(STORAGE_KEY, [{
    ...existing,
    consumed_at_ms: existing.expires_at_ms + 1,
    consume_operation_id: "e".repeat(64),
  }]);
  const invalidConsume = await api.run(await consumeRequest(issued, { operation_id: "f".repeat(64) }));
  assert.equal(invalidConsume.code, "ATTESTATION_CHALLENGE_CONSUME_OUTCOME_UNCERTAIN");
});


test("server clock rollback cannot consume a challenge before its issue timestamp", async () => {
  const api = setup();
  const { result: issued } = await issue(api);
  const rollbackNow = NOW - 1;
  const req = await consumeRequest(issued, {
    operation_id: "a".repeat(64),
    issued_at_ms: rollbackNow,
    expires_at_ms: rollbackNow + 20_000,
  });
  const result = await api.run(req, () => rollbackNow);
  assert.equal(result.code, "ATTESTATION_CHALLENGE_CLOCK_BEFORE_ISSUE");
  assert.equal(api.storage.data.get(STORAGE_KEY)[0].consumed_at_ms, null);
});

test("operation IDs cannot be reused across issue and consume actions", async () => {
  const api = setup();
  const issueOperation = "b".repeat(64);
  const { result: issued } = await issue(api, { operation_id: issueOperation });

  // Same operation identifier is not valid for consuming the issued challenge.
  const reusedForConsume = await consumeRequest(issued, {
    operation_id: issueOperation,
  });
  assert.equal((await api.run(reusedForConsume)).code,
    "ATTESTATION_CHALLENGE_CONSUME_OPERATION_REPLAY");
  assert.equal(api.storage.data.get(STORAGE_KEY)[0].consumed_at_ms, null);

  const validConsumeOp = "c".repeat(64);
  const validConsume = await api.run(await consumeRequest(issued, {
    operation_id: validConsumeOp,
  }));
  assert.equal(validConsume.state, "CHALLENGE_CONSUMED");

  // Nor may that consume operation be reused to issue a different challenge.
  const reusedForIssue = await signed("issue", {
    operation_id: validConsumeOp,
    issued_at_ms: NOW + 1,
    expires_at_ms: NOW + 20_000,
  });
  assert.equal((await api.run(reusedForIssue, () => NOW + 1)).code,
    "ATTESTATION_CHALLENGE_ISSUE_REPLAY");
  assert.equal(api.storage.data.get(STORAGE_KEY).length, 1);
});


test("uncertain post-commit outcomes fail closed and a retry cannot mint or consume twice", async () => {
  const api = setup();
  const baseStore = createPairingAtomicStore(api.storage);
  const uncertainAfterCommit = {
    async atomic(operation) {
      await baseStore.atomic(operation);
      throw new Error("simulated lost response after commit");
    },
  };

  const issueRequest = await signed("issue", { operation_id: "d".repeat(64) });
  const issueResult = await receiveDeviceAttestationChallenge({
    request: issueRequest, env: api.env, objectId: api.objectId,
    store: uncertainAfterCommit, cryptoImpl: webcrypto, clock: () => NOW,
  });
  assert.equal(issueResult.code, "ATTESTATION_CHALLENGE_ISSUE_OUTCOME_UNCERTAIN");
  assert.equal(api.storage.data.get(STORAGE_KEY).length, 1);
  const issueRetry = await api.run(issueRequest);
  assert.equal(issueRetry.code, "ATTESTATION_CHALLENGE_ISSUE_REPLAY");
  assert.equal(api.storage.data.get(STORAGE_KEY).length, 1);

  const persisted = api.storage.data.get(STORAGE_KEY)[0];
  // The plaintext challenge was intentionally never persisted. The test's
  // issue response was lost, so do not try to reconstruct/use it.
  assert.equal(persisted.consumed_at_ms, null);

  // Separately exercise consume's unknown response: it commits once, returns
  // BLOCKED to the caller, and any replay sees the already-consumed state.
  const second = setup();
  const { result: issued } = await issue(second, { operation_id: "e".repeat(64) });
  const consumeRequestValue = await consumeRequest(issued, { operation_id: "f".repeat(64) });
  const consumeStore = createPairingAtomicStore(second.storage);
  const consumeResult = await receiveDeviceAttestationChallenge({
    request: consumeRequestValue, env: second.env, objectId: second.objectId,
    store: {
      async atomic(operation) {
        await consumeStore.atomic(operation);
        throw new Error("simulated lost consume response after commit");
      },
    },
    cryptoImpl: webcrypto, clock: () => NOW,
  });
  assert.equal(consumeResult.code, "ATTESTATION_CHALLENGE_CONSUME_OUTCOME_UNCERTAIN");
  assert.equal(second.storage.data.get(STORAGE_KEY)[0].consumed_at_ms, NOW);
  assert.equal((await second.run(consumeRequestValue)).code, "ATTESTATION_CHALLENGE_REPLAY");
});
