import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { createPairingAtomicStore, BkeWorkerPairingVault } from "../src/worker-pairing-durable-store.js";
import { createWorkerPairingCeremony } from "../src/worker-pairing-ceremony.js";

class FakeDurableStorage {
  data = new Map();
  gate = Promise.resolve();
  transactions = 0;
  failSecondWrite = false;

  async transaction(fn) {
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    const prev = this.gate;
    this.gate = gate;
    await prev;
    this.transactions += 1;
    const copy = new Map(structuredClone([...this.data]));
    let writes = 0;
    const tx = {
      get: async key => structuredClone(copy.get(key)),
      put: async (key, value) => {
        writes += 1;
        if (this.failSecondWrite && writes === 2) throw new Error("sensitive backend failure");
        copy.set(key, structuredClone(value));
      },
    };
    try {
      const result = await fn(tx);
      this.data = copy;
      return result;
    } finally { release(); }
  }
  get(key) { return structuredClone(this.data.get("bke:pairing:v1:" + key)); }
}
const hx = x => x.repeat(64);
function resources(n = 0) {
  const alphabet = "0123456789abcdef";
  return {
    chatgpt_target_sha256: hx(alphabet[n]),
    browser_profile_sha256: hx(alphabet[n+4]),
    bridge_identity_sha256: hx(alphabet[n+8]),
  };
}
async function pairKey() {
  const keys = await webcrypto.subtle.generateKey({ name:"ECDSA",namedCurve:"P-256" }, true, ["sign","verify"]);
  const jwk = await webcrypto.subtle.exportKey("jwk", keys.publicKey);
  return { secret:keys.privateKey, public_key:{crv:"P-256",kty:"EC",x:jwk.x,y:jwk.y} };
}
async function signature(key,message) {
  return Buffer.from(new Uint8Array(await webcrypto.subtle.sign(
    {name:"ECDSA",hash:"SHA-256"},key.secret,new TextEncoder().encode(message)))).toString("base64url");
}
function ceremony(storage) {
  return createWorkerPairingCeremony({
    store:createPairingAtomicStore(storage),
    authorizeAdmin:async(action,workerId,token)=>["pair","revoke"].includes(action)&&
      /^worker-[ab]$/.test(workerId)&&token?.verifiedByPlatform===true,
    readLiveAssignments:async()=>({verified:true,openPullRequests:[]}),
    installationId:"123456",
    cryptoImpl:webcrypto,
    clock:()=>1_000_000,
  });
}
const approve={verifiedByPlatform:true};

test("Cloudflare transaction adapter scopes only paired/pending keys",async()=>{
  const durable=new FakeDurableStorage(), vault=createPairingAtomicStore(durable);
  const r=await vault.atomic(async tx=>{
    assert.equal(await tx.get("paired"),undefined);
    await tx.put("paired",[]);
    await tx.put("pending",[]);
    return "PASS";
  });
  assert.equal(r,"PASS");
  assert.deepEqual(durable.get("paired"),[]);
  assert.deepEqual([...durable.data.keys()].sort(),
    ["bke:pairing:v1:paired","bke:pairing:v1:pending"]);
});

test("atomic rollback if the second write fails (never half-register)",async()=>{
  const durable=new FakeDurableStorage();
  const vault=createPairingAtomicStore(durable);
  durable.failSecondWrite=true;
  await assert.rejects(()=>vault.atomic(async tx=>{
    await tx.put("paired",[{x:1}]);
    await tx.put("pending",[]);
  }),/PAIRING_STORAGE_UNAVAILABLE/);
  assert.equal(durable.get("paired"),undefined);
  assert.equal(durable.get("pending"),undefined);
});

test("two independent adapter instances serialize through the same Durable Object",async()=>{
  const durable=new FakeDurableStorage();
  const a=createPairingAtomicStore(durable),b=createPairingAtomicStore(durable);
  const write=store=>store.atomic(async tx=>{
    const rows=(await tx.get("paired"))||[];
    await Promise.resolve();
    await tx.put("paired",[...rows,{n:rows.length+1}]);
  });
  await Promise.all([write(a),write(b)]);
  assert.deepEqual(durable.get("paired"),[{n:1},{n:2}]);
  assert.equal(durable.transactions,2);
});

test("complete cryptographic pairing through real transaction adapter; replay blocked",async()=>{
  const durable=new FakeDurableStorage(),api=ceremony(durable),key=await pairKey();
  const issued=await api.issueChallenge({
    worker_id:"worker-a",public_key:key.public_key,resources:resources(0),
    admin_context:approve,
  });
  assert.equal(issued.state,"CHALLENGE_ISSUED");
  const sig=await signature(key,issued.message);
  const attempts=await Promise.all([0,1].map(()=>api.completePairing({
    worker_id:"worker-a",challenge_id:issued.challenge_id,signature:sig,
  })));
  assert.equal(attempts.filter(x=>x.state==="PAIRED_INACTIVE").length,1);
  assert.equal(attempts.filter(x=>x.state==="BLOCKED").length,1);
  assert.equal(durable.get("paired").length,1);
  assert.equal(durable.get("pending").length,0);
  assert.deepEqual(await api.revokePairing({worker_id:"worker-a",admin_context:approve}),
    {state:"REVOKED",code:"PAIRING_REVOKED"});
  assert.equal(durable.get("paired")[0].status,"REVOKED");
});

test("two isolated workers share the installation-wide serialized vault",async()=>{
  const durable=new FakeDurableStorage(),a=ceremony(durable),b=ceremony(durable);
  const [k1,k2]=await Promise.all([pairKey(),pairKey()]);
  const [c1,c2]=await Promise.all([
    a.issueChallenge({worker_id:"worker-a",public_key:k1.public_key,resources:resources(0),admin_context:approve}),
    b.issueChallenge({worker_id:"worker-b",public_key:k2.public_key,resources:resources(1),admin_context:approve}),
  ]);
  assert.equal(c1.state,"CHALLENGE_ISSUED");
  assert.equal(c2.state,"CHALLENGE_ISSUED");
  const outcomes=await Promise.all([
    a.completePairing({worker_id:"worker-a",challenge_id:c1.challenge_id,signature:await signature(k1,c1.message)}),
    b.completePairing({worker_id:"worker-b",challenge_id:c2.challenge_id,signature:await signature(k2,c2.message)}),
  ]);
  assert.deepEqual(outcomes.map(x=>x.state),["PAIRED_INACTIVE","PAIRED_INACTIVE"]);
  assert.equal(durable.get("paired").length,2);
});

test("out-of-scope storage access, bad transaction or non-json values fail closed",async()=>{
  const durable=new FakeDurableStorage(),vault=createPairingAtomicStore(durable);
  for(const operation of [
    tx=>tx.get("secrets"),
    tx=>tx.put("other",[]),
    tx=>tx.put("paired",[{secret:()=>{}}]),
    tx=>tx.put("pending",{foo:true}),
  ])await assert.rejects(()=>vault.atomic(operation),/PAIRING_STORAGE_UNAVAILABLE/);
  assert.equal(durable.data.size,0);
  assert.throws(()=>createPairingAtomicStore({}),/PAIRING_STORAGE_CONTRACT_INVALID/);
});

test("vault class remains inert: no RPC operation, no public fetch, no side effects",async()=>{
  const durable=new FakeDurableStorage();
  const instance=new BkeWorkerPairingVault({storage:durable},{});
  assert.equal((await instance.fetch(new Request("https://example.invalid/pair"))).status,404);
  assert.equal(durable.transactions,0);
  assert.equal(typeof instance.issueChallenge,"undefined");
  assert.equal(typeof instance.completePairing,"undefined");
  assert.equal(typeof instance.revokePairing,"undefined");
});

test("PREPRODUCTION-only migration is staged but runtime pairing flag/route is absent",()=>{
  const config=readFileSync(new URL("../wrangler.toml",import.meta.url),"utf8");
  const index=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
  assert.match(config,/\[\[env\.preproduction\.durable_objects\.bindings\]\]/u);
  assert.match(config,/new_sqlite_classes\s*=\s*\["BkeWorkerPairingVault"\]/u);
  assert.doesNotMatch(config,/BKE_PAIRING_ENABLED\s*=\s*"true"/u);
  // The new source-only review route requires an injected trusted adapter,
  // with its feature latch deliberately absent from the deployed configuration.
  assert.match(index,/server: pairingReviewServer/u);
  assert.doesNotMatch(config,/BKE_ADMIN_PAIRING_REVIEW_ENABLED/u);
});
