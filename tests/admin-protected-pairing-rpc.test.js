import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { sendProtectedInactivePairing } from "../src/admin-protected-pairing-rpc.js";
import { parseTrustedWorkerAssignmentPayload } from "../src/admin-worker-assignments.js";
import { BkeWorkerPairingVault, createPairingAtomicStore } from "../src/worker-pairing-durable-store.js";
import { createWorkerPairingCeremony } from "../src/worker-pairing-ceremony.js";
import { createAdminOneTimeActionTickets } from "../src/admin-one-time-action-tickets.js";

const KEY_BYTES = Buffer.alloc(32, 29);
const KEY = KEY_BYTES.toString("base64url"); // TEST ONLY, never deploy.
const AUD = "bke-command-center/preproduction/execute-protected-inactive-pairing/v1";
const ADMIN = { access: { aud: "0123456789abcdef0123456789abcdef",
  async getIdentity() { return { email: "admin@example.test" }; } } };
const flags = {
  BKE_PREPRODUCTION: "true", BKE_ACCESS_POLICY_VERIFIED: "true",
  BKE_ADMIN_DISCOVERY_ENABLED: "true",
  BKE_ADMIN_PR_INVENTORY_ENABLED: "true",
  BKE_ADMIN_PAIRING_ACTIONS_ENABLED: "true",
  BKE_ADMIN_DO_ROUTING_ENABLED: "true",
  BKE_ADMIN_PROTECTED_PAIRING_ENABLED: "true",
  BKE_ADMIN_PROTECTED_RPC_ENABLED: "true",
  BKE_ADMIN_ACCESS_ISSUER: "https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD: ADMIN.access.aud,
  BKE_ADMIN_EMAILS: "admin@example.test",
  BKE_PAIRING_RPC_KEY_B64: KEY,
};
const inventory = () => ({
  principal: "github_app_installation",
  authority: "EXISTING_GITHUB_APP_INSTALLATION",
  repository_scope: "INSTALLATION_APPROVED_ONLY",
  consistency: "NON_ATOMIC_ENUMERATION",
  installation_id: "51", total_visible_repositories: 76,
  enumerated_open_pull_requests: 0, worker_assignments: [],
});
const RES = {
  chatgpt_target_sha256: "1".repeat(64),
  browser_profile_sha256: "2".repeat(64),
  bridge_identity_sha256: "3".repeat(64),
};
const blocked = (out) => {
  assert.equal(out.state, "BLOCKED");
  assert.deepEqual(Object.keys(out).sort(), ["code","state"]);
  assert.doesNotMatch(JSON.stringify(out), /ghs_|secret|nonce|Bearer|admin@example/u);
};
async function subject() {
  const signing = await webcrypto.subtle.importKey("raw", KEY_BYTES,
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const msg = JSON.stringify([AUD, "human-subject", ADMIN.access.aud, "admin@example.test"]);
  const data = new Uint8Array(await webcrypto.subtle.sign("HMAC", signing,
    new TextEncoder().encode(msg)));
  return Buffer.from(data).toString("hex");
}
function database() {
  let state = new Map(), gate = Promise.resolve();
  const data = {
    failOnWrite: 0, transactions: 0,
    async transaction(cb) {
      let resume;
      const next = new Promise(r => { resume = r; });
      const previous = gate; gate = next;
      await previous;
      const copy = new Map(structuredClone([...state]));
      this.transactions++;
      let writes = 0;
      try {
        const out = await cb({
          get: async key => structuredClone(copy.get(key)),
          put: async (key, value) => {
            if (this.failOnWrite && ++writes === this.failOnWrite) throw Error("private storage");
            copy.set(key, structuredClone(value));
          },
        });
        state = copy;
        return out;
      } finally { resume(); }
    },
    get: name => structuredClone(state.get("bke:pairing:v1:" + name)),
  };
  return data;
}
async function setup() {
  const storage = database();
  let raw = inventory(), brokerCalls = 0;
  let alternateStub = null;
  const ns = {
    idFromName: name => ({ toString: () => "DO:" + name }),
    get: id => alternateStub ?? new BkeWorkerPairingVault({ id, storage }, env),
  };
  const env = { ...flags, BKE_WORKER_PAIRING_VAULT: ns,
    BKE_GITHUB_READ_BROKER: {
      async listVerifiedWorkerAssignments(purpose) {
        assert.deepEqual(purpose, { purpose: "admin_worker_assignment_inventory" });
        brokerCalls++;
        return structuredClone(raw);
      },
    },
  };
  const human = await subject();
  const store = createPairingAtomicStore(storage);
  const issueDevice = createWorkerPairingCeremony({
    store, installationId: "51", cryptoImpl: webcrypto,
    authorizeAdmin: async (_, __, who) => who === ADMIN,
    readLiveAssignments: async () => ({verified:true,openPullRequests:[]}),
  });
  const issueHuman = createAdminOneTimeActionTickets({
    store, installationId: "51", cryptoImpl: webcrypto,
    authorizeAdmin: async (_, __, who) => who === ADMIN ? human : null,
  });
  const key = await webcrypto.subtle.generateKey(
    {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const jwk = await webcrypto.subtle.exportKey("jwk", key.publicKey);
  const device = await issueDevice.issueChallenge({
    worker_id: "worker-a", public_key: {crv:"P-256",kty:"EC",x:jwk.x,y:jwk.y},
    resources:RES, admin_context:ADMIN,
  });
  assert.equal(device.state, "CHALLENGE_ISSUED");
  const sig = Buffer.from(new Uint8Array(await webcrypto.subtle.sign(
    {name:"ECDSA",hash:"SHA-256"},key.privateKey,
    new TextEncoder().encode(device.message)))).toString("base64url");
  const ticket = await issueHuman.issue({
    action:"pair", worker_id:"worker-a", admin_context:ADMIN,
  });
  assert.equal(ticket.state, "ISSUED_FOR_CONFIRMATION");
  const proof = {
    worker_id:"worker-a", device_challenge_id:device.challenge_id,
    device_signature:sig, admin_challenge_id:ticket.challenge_id,
    admin_one_time_nonce:ticket.one_time_nonce,
  };
  const request = (opt = {}) => sendProtectedInactivePairing({
    env, executionCtx: ADMIN, proof,
    readAssignments: async () => parseTrustedWorkerAssignmentPayload(structuredClone(raw)),
    cryptoImpl:webcrypto,
    ...opt,
  });
  return {env,ns,storage,request,proof,brokerCalls:()=>brokerCalls,
    setRaw:x=>{raw=x;}, setStub:x=>{alternateStub=x;}};
}

test("real Access+GitHub+HMAC RPC atomically registers only inactive device", async () => {
  const f = await setup();
  const out = await f.request();
  assert.deepEqual(out, {
    state:"PAIRED_INACTIVE", code:"PROTECTED_PAIRING_INACTIVE_ONLY",
  });
  assert.equal(f.storage.get("paired").length,1);
  assert.equal(f.storage.get("paired")[0].status,"PAIRED_INACTIVE");
  assert.equal(f.storage.get("pending").length,0);
  assert.equal(f.storage.get("admin_actions")[0].status,"CONSUMED");
  assert.equal(f.brokerCalls(),1);
  assert.ok(!JSON.stringify(f.storage.get("paired")).includes(f.proof.admin_one_time_nonce));
});

test("two racing signed RPC deliveries can register at most once", async () => {
  const f = await setup();
  const [a,b] = await Promise.all([f.request(),f.request()]);
  assert.equal([a,b].filter(x=>x.state==="PAIRED_INACTIVE").length,1);
  assert.equal(f.storage.get("paired").length,1);
  assert.equal(f.storage.get("admin_actions")[0].status,"CONSUMED");
});

test("replay after completed pairing cannot register again", async () => {
  const f = await setup();
  assert.equal((await f.request()).state,"PAIRED_INACTIVE");
  blocked(await f.request());
  assert.equal(f.storage.get("paired").length,1);
});

test("third storage write failure rolls back all three registry changes", async () => {
  const f = await setup();
  f.storage.failOnWrite = 3;
  blocked(await f.request());
  assert.equal(f.storage.get("paired"),undefined);
  assert.equal(f.storage.get("pending").length,1);
  assert.equal(f.storage.get("admin_actions")[0].status,"PENDING");
  f.storage.failOnWrite = 0;
  assert.equal((await f.request()).state,"PAIRED_INACTIVE");
});

test("wrong tenant DO cannot be used as the target of a signed command", async () => {
  const f = await setup();
  f.setStub(new BkeWorkerPairingVault({
    id:f.ns.idFromName("installation:52"),storage:f.storage,
  },f.env));
  blocked(await f.request());
  assert.equal(f.storage.get("paired"),undefined);
});

test("unauthorized Admin denies before private broker or DO mutation", async () => {
  const f = await setup();
  const bad = {access:{aud:ADMIN.access.aud,
    async getIdentity(){return {email:"intruder@example.test"};}}};
  blocked(await f.request({executionCtx:bad}));
  assert.equal(f.brokerCalls(),0);
  assert.equal(f.storage.get("paired"),undefined);
});

test("missing separate feature flag or HMAC key denies before provider reads", async () => {
  const f = await setup();
  for (const key of ["BKE_ADMIN_PROTECTED_RPC_ENABLED","BKE_ADMIN_DO_ROUTING_ENABLED"]) {
    blocked(await f.request({env:{...f.env,[key]:undefined}}));
  }
  blocked(await f.request({env:{...f.env,BKE_PAIRING_RPC_KEY_B64:undefined}}));
  assert.equal(f.brokerCalls(),0);
});

test("untrusted repo claims or changed installation deny without pairing", async () => {
  const f = await setup();
  f.setRaw({...inventory(),installation_id:"52"});
  blocked(await f.request());
  f.setRaw({...inventory(),worker_assignments:[{
    repository:"jan2xo/bke-worker",repository_id:1354026486,
    number:104,state:"open",head_sha:"a".repeat(40),
    labels:["bke-worker:worker-a"],
  }],enumerated_open_pull_requests:1,installation_id:"51"});
  blocked(await f.request());
  assert.equal(f.storage.get("paired"),undefined);
});

test("forged signed-response, wrong broker grant and missing RPC fail closed", async () => {
  const f = await setup();
  f.setStub({finalizeProtectedInactivePairing:async()=>({state:"PAIRED",token:"ghs_fake"})});
  blocked(await f.request());
  f.setStub({});
  blocked(await f.request());
  f.setStub(null);
  f.setRaw({...inventory(),permissions:{contents:"write"}});
  blocked(await f.request());
  assert.equal(f.storage.get("paired"),undefined);
});

test("public HTTP still refuses pairing and neither secret nor flag is configured", async () => {
  const index = readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
  const wr = readFileSync(new URL("../wrangler.toml",import.meta.url),"utf8");
  const cloud = readFileSync(new URL("../src/cloudflare-worker-entry.js",import.meta.url),"utf8");
  assert.doesNotMatch(index,/admin-protected-pairing-rpc/u);
  assert.doesNotMatch(wr,/BKE_ADMIN_PROTECTED_RPC_ENABLED/u);
  assert.doesNotMatch(wr,/BKE_PAIRING_RPC_KEY_B64/u);
  assert.match(cloud,/async finalizeProtectedInactivePairing\(request\)/u);
  assert.match(cloud,/extends DurableObject/u);
});
