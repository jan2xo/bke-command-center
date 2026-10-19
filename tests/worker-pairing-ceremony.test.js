import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { createWorkerPairingCeremony } from "../src/worker-pairing-ceremony.js";

const hex = char => char.repeat(64);
const resources = (i = 0) => ({
  chatgpt_target_sha256: hex("a".charCodeAt(0) + i <= "f".charCodeAt(0) ? String.fromCharCode(97 + i) : "1"),
  browser_profile_sha256: hex(String.fromCharCode(103 + i)),
  bridge_identity_sha256: hex(String.fromCharCode(107 + i)),
});
// Digests must use lowercase hexadecimal, not arbitrary placeholders.
const validResources = (i = 0) => ({
  chatgpt_target_sha256: hex("123456789abcdef0"[i]),
  browser_profile_sha256: hex("123456789abcdef0"[i + 4]),
  bridge_identity_sha256: hex("123456789abcdef0"[i + 8]),
});

function fakeStore() {
  let data = {};
  let gate = Promise.resolve();
  return {
    async atomic(fn) {
      let unlock;
      const next = new Promise(resolve => { unlock = resolve; });
      const previous = gate; gate = next;
      await previous;
      const working = structuredClone(data);
      try {
        const outcome = await fn({
          get: async key => structuredClone(working[key]),
          put: async (key, value) => { working[key] = structuredClone(value); },
        });
        data = working;
        return outcome;
      } finally { unlock(); }
    },
    snapshot() { return structuredClone(data); },
  };
}
let now = 100_000;
let openPrs = [];
let healthy = true;
let allowed = true;
const reset = () => { now = 100_000; openPrs = []; healthy = true; allowed = true; };
const make = (store = fakeStore(), options = {}) => ({
  store,
  api: createWorkerPairingCeremony({
    store, cryptoImpl: webcrypto, clock: () => now,
    installationId: "123456",
    authorizeAdmin: async (action, _worker, context) => {
      assert.ok(["pair", "revoke"].includes(action));
      return allowed && context?.trusted === "operator";
    },
    readLiveAssignments: async () => {
      if (!healthy) throw Error("sensitive upstream token");
      return { verified: true, openPullRequests: openPrs };
    },
    ...options,
  }),
});
async function keypair() {
  const pair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  return { privateKey: pair.privateKey,
    public_key: { crv: "P-256", kty: "EC", x: jwk.x, y: jwk.y } };
}
function b64url(bytes) { return Buffer.from(bytes).toString("base64url"); }
async function signed(pair, challenge) {
  return b64url(new Uint8Array(await webcrypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, pair.privateKey,
    new TextEncoder().encode(challenge.message))));
}
const request = (pair, worker_id = "worker-b", i = 0) => ({
  worker_id, public_key: pair.public_key, resources: validResources(i),
  admin_context: { trusted: "operator" },
});
const denied = result => {
  assert.equal(result.state, "BLOCKED");
  assert.match(result.code, /^[A-Z0-9_]+$/u);
  assert.deepEqual(Object.keys(result).sort(), ["code", "state"]);
  assert.doesNotMatch(JSON.stringify(result), /sensitive|ghs_|operator|https|privateKey/iu);
};

test("P-256 key-possession registers inactive pair with atomic nonce consumption; replay denied", async () => {
  reset();
  const { api, store } = make();
  const key = await keypair();
  const challenge = await api.issueChallenge(request(key));
  assert.equal(challenge.state, "CHALLENGE_ISSUED");
  assert.equal(challenge.expires_at_ms, 220_000);
  assert.match(challenge.message, /bke-command-center\/preproduction\/worker-pairing\/v1/u);
  assert.ok(!("token" in challenge || "lease_token" in challenge));
  const proof = await signed(key, challenge);
  const accepted = await api.completePairing({
    worker_id: "worker-b", challenge_id: challenge.challenge_id, signature: proof });
  assert.deepEqual(accepted, { state: "PAIRED_INACTIVE", code: "PAIRING_PROOF_ACCEPTED" });
  denied(await api.completePairing({
    worker_id: "worker-b", challenge_id: challenge.challenge_id, signature: proof }));
  const db = store.snapshot();
  assert.equal(db.paired.length, 1);
  assert.equal(db.paired[0].status, "PAIRED_INACTIVE");
  assert.equal(db.pending.length, 0);
  assert.equal(db.paired[0].enrollment_expires_at_ms, 3_700_000);
  assert.doesNotMatch(JSON.stringify(db.paired), /privateKey|signature|message|Bearer|token/u);
});

test("proof from different key or tampered signature is rejected without consuming challenge", async () => {
  reset();
  const { api, store } = make();
  const [owner, other] = await Promise.all([keypair(), keypair()]);
  const challenge = await api.issueChallenge(request(owner));
  denied(await api.completePairing({
    worker_id: "worker-b", challenge_id: challenge.challenge_id,
    signature: await signed(other, challenge) }));
  assert.equal((store.snapshot().pending || []).length, 1);
  const proof = await signed(owner, challenge);
  denied(await api.completePairing({
    worker_id: "worker-b", challenge_id: challenge.challenge_id,
    signature: proof.slice(0, -1) + "!" }));
  assert.equal((await api.completePairing({
    worker_id: "worker-b", challenge_id: challenge.challenge_id, signature: proof })).state,
    "PAIRED_INACTIVE");
});

test("expired challenge cannot be completed or replaced through a stale proof", async () => {
  reset();
  const { api, store } = make();
  const pair = await keypair();
  const challenge = await api.issueChallenge(request(pair));
  now = 220_000;
  denied(await api.completePairing({ worker_id: "worker-b",
    challenge_id: challenge.challenge_id, signature: await signed(pair, challenge) }));
  assert.equal((store.snapshot().paired || []).length, 0);
});

test("Admin authorization is mandatory for issuance and revocation", async () => {
  reset();
  const { api, store } = make();
  const pair = await keypair();
  allowed = false;
  denied(await api.issueChallenge(request(pair)));
  assert.equal(Object.keys(store.snapshot()).length, 0);
  allowed = true;
  denied(await api.issueChallenge({ ...request(pair), admin_context: { trusted: "browser" } }));
  assert.equal(Object.keys(store.snapshot()).length, 0);
  denied(await api.revokePairing({ worker_id: "worker-b", admin_context: null }));
});

test("missing GitHub inventory blocks both challenge and completion", async () => {
  reset();
  const { api, store } = make();
  const pair = await keypair();
  healthy = false;
  denied(await api.issueChallenge(request(pair)));
  healthy = true;
  const challenge = await api.issueChallenge(request(pair));
  healthy = false;
  denied(await api.completePairing({ worker_id: "worker-b",
    challenge_id: challenge.challenge_id, signature: await signed(pair, challenge) }));
  assert.equal((store.snapshot().paired || []).length, 0);
});

test("active PR assignment prevents enrollment even if label appears after challenge issuance", async () => {
  reset();
  const { api, store } = make();
  const pair = await keypair();
  const challenge = await api.issueChallenge(request(pair));
  openPrs = [{ repository: "jan2xo/bke-worker", number: 225, state: "open",
    labels: ["bke-worker:worker-b"] }];
  denied(await api.completePairing({ worker_id: "worker-b",
    challenge_id: challenge.challenge_id, signature: await signed(pair, challenge) }));
  assert.equal((store.snapshot().paired || []).length, 0);
});

test("unrelated existing PR assignment allows pairing", async () => {
  reset();
  openPrs = [{ repository: "jan2xo/bke-worker", number: 225, state: "open",
    labels: ["bke-worker:worker-a"] }];
  const { api } = make();
  const pair = await keypair();
  const challenge = await api.issueChallenge(request(pair));
  assert.equal(challenge.state, "CHALLENGE_ISSUED");
});

test("same worker concurrent challenges are serialized with exactly one winner", async () => {
  reset();
  const { api, store } = make();
  const pair = await keypair();
  const [a, b] = await Promise.all([
    api.issueChallenge(request(pair)), api.issueChallenge(request(pair)) ]);
  assert.equal([a, b].filter(x => x.state === "CHALLENGE_ISSUED").length, 1);
  assert.equal([a, b].filter(x => x.state === "BLOCKED").length, 1);
  assert.equal(store.snapshot().pending.length, 1);
});

test("same valid proof raced twice cannot create duplicate worker identities", async () => {
  reset();
  const { api, store } = make();
  const pair = await keypair();
  const challenge = await api.issueChallenge(request(pair));
  const proof = await signed(pair, challenge);
  const [a, b] = await Promise.all([0, 1].map(() =>
    api.completePairing({ worker_id: "worker-b", challenge_id: challenge.challenge_id,
      signature: proof })));
  assert.equal([a, b].filter(x => x.state === "PAIRED_INACTIVE").length, 1);
  assert.equal(store.snapshot().paired.length, 1);
});

test("two isolated workers can pair, but shared target and shared key block", async () => {
  reset();
  const { api, store } = make();
  const [a, b] = await Promise.all([keypair(), keypair()]);
  const ca = await api.issueChallenge(request(a, "worker-a", 0));
  assert.equal(ca.state, "CHALLENGE_ISSUED");
  const cb = await api.issueChallenge(request(b, "worker-b", 1));
  assert.equal(cb.state, "CHALLENGE_ISSUED");
  const sharedTarget = { ...request(b, "worker-c", 0).resources,
    browser_profile_sha256: validResources(2).browser_profile_sha256,
    bridge_identity_sha256: validResources(2).bridge_identity_sha256 };
  denied(await api.issueChallenge({
    ...request(b, "worker-c", 2), resources: sharedTarget }));
  assert.equal((await api.completePairing({ worker_id: "worker-a",
    challenge_id: ca.challenge_id, signature: await signed(a, ca) })).state,
    "PAIRED_INACTIVE");
  assert.equal((await api.completePairing({ worker_id: "worker-b",
    challenge_id: cb.challenge_id, signature: await signed(b, cb) })).state,
    "PAIRED_INACTIVE");
  assert.equal(store.snapshot().paired.length, 2);
  denied(await api.issueChallenge(request(a, "worker-c", 2)));
});

test("revoke invalidates enrollment and leaves tombstone preventing silent identity reuse", async () => {
  reset();
  const { api, store } = make();
  const pair = await keypair();
  const challenge = await api.issueChallenge(request(pair));
  const signature = await signed(pair, challenge);
  assert.equal((await api.completePairing({ worker_id: "worker-b",
    challenge_id: challenge.challenge_id, signature })).state, "PAIRED_INACTIVE");
  assert.deepEqual(await api.revokePairing({ worker_id: "worker-b",
    admin_context: { trusted: "operator" } }),
  { state: "REVOKED", code: "PAIRING_REVOKED" });
  assert.equal(store.snapshot().paired[0].status, "REVOKED");
  denied(await api.revokePairing({ worker_id: "worker-b",
    admin_context: { trusted: "operator" } }));
  denied(await api.issueChallenge(request(pair)));
});

test("invalid public keys/worker IDs and malformed proof are rejected", async () => {
  reset();
  const { api } = make();
  const pair = await keypair();
  for (const patch of [{ worker_id: "Worker-B" },
    { public_key: { ...pair.public_key, crv: "P-384" } },
    { public_key: { ...pair.public_key, d: "private-key" } },
    { resources: { ...validResources(), chatgpt_target_sha256: "raw-target" } }]) {
    denied(await api.issueChallenge({ ...request(pair), ...patch }));
  }
  denied(await api.completePairing({ worker_id: "worker-b", challenge_id: "notanid", signature: "bad" }));
});

test("storage exceptions become fixed redacted errors", async () => {
  reset();
  const broken = { atomic: async () => { throw Error("do not leak private PEM"); } };
  const { api } = make(broken);
  const pair = await keypair();
  assert.deepEqual(await api.issueChallenge(request(pair)),
    { state: "BLOCKED", code: "PAIRING_STORAGE_UNAVAILABLE" });
});
