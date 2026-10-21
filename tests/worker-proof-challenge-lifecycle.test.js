import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { createPairingAtomicStore, createAndroidProofChallengeLifecycle, BkeWorkerPairingVault } from "../src/worker-pairing-durable-store.js";

class FakeDurableStorage {
  data = new Map(); gate = Promise.resolve(); transactions = 0; failCommit = false;
  async transaction(fn) {
    let release; const gate = new Promise(resolve=>{release=resolve;});
    const prev=this.gate; this.gate=gate; await prev; this.transactions++;
    const copy=new Map(structuredClone([...this.data]));
    const tx={get:async key=>structuredClone(copy.get(key)),put:async(key,value)=>copy.set(key,structuredClone(value))};
    try { const result=await fn(tx); if(this.failCommit){this.failCommit=false;throw Error("uncertain commit");} this.data=copy; return result; }
    finally { release(); }
  }
}
const hex=c=>c.repeat(64);
const AUD="bke-command-center/android-attestation-proof/v1";
const PURPOSE="android-attestation-proof-v1";
const binding=(installationId="123456",workerId="worker-a",s="a")=>({
 installation_id:installationId,worker_id:workerId,session_sha256:hex(s),
 profile_sha256:hex(s==="a"?"b":"c"),bridge_sha256:hex(s==="a"?"d":"e"),target_sha256:hex(s==="a"?"f":"1"),
 audience:AUD,purpose:PURPOSE
});
function lifecycle(storage,ctx=binding(),now=2_000_000_000_000) {
 return createAndroidProofChallengeLifecycle({
   store:createPairingAtomicStore(storage),installationId:ctx.installation_id,
   resolveTrustedContext:async reference=>reference?.trusted===true?structuredClone(reference.overrideContext||ctx):null,
   cryptoImpl:webcrypto,clock:()=>now
 });
}
const trusted={trusted:true};

test("proof challenge lifecycle uses a scoped namespace and atomically commits one-use state",async()=>{
 const d=new FakeDurableStorage(),api=lifecycle(d);
 const issued=await api.issue({serverReference:trusted});
 assert.equal(issued.state,"ISSUED"); assert.equal(issued.expiresAtMs,2_000_000_120_000); // bounded 120-second TTL from injected clock
 assert.match(issued.challengeId,/^[a-f0-9]{64}$/u);
 assert.deepEqual([...d.data.keys()],["bke:proof-challenge:v1:rows"]);
 const claimed=await api.claim({challengeId:issued.challengeId,serverReference:trusted});
 assert.equal(claimed.state,"CLAIMED"); assert.equal(claimed.proofChallenge.challengeBase64Url.length,43);
 assert.equal(Buffer.from(claimed.proofChallenge.challengeBase64Url,"base64url").length,32);
 assert.deepEqual(Object.keys(claimed.proofChallenge).sort(),["challengeBase64Url","expiresAtMs","issuedAtMs","state","workerId"]);
 assert.deepEqual(await api.finalize({challengeId:issued.challengeId,serverReference:trusted,outcome:"CONSUMED"}),{state:"CONSUMED"});
 assert.deepEqual(await api.claim({challengeId:issued.challengeId,serverReference:trusted}),{state:"BLOCKED",code:"PROOF_CHALLENGE_NOT_ISSUED"});
 assert.equal((await api.inspectForTest(issued.challengeId)).state,"CONSUMED");
});

test("two simultaneous claims against two lifecycle clients yield exactly one winner",async()=>{
 const d=new FakeDurableStorage(),a=lifecycle(d),b=lifecycle(d);
 const issued=await a.issue({serverReference:trusted});
 const results=await Promise.all([a.claim({challengeId:issued.challengeId,serverReference:trusted}),b.claim({challengeId:issued.challengeId,serverReference:trusted})]);
 assert.equal(results.filter(x=>x.state==="CLAIMED").length,1);
 assert.equal(results.filter(x=>x.state==="BLOCKED").length,1);
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"CLAIMED");
});

test("binding mismatches cannot claim or finalize someone else's challenge",async()=>{
 const d=new FakeDurableStorage(),a=lifecycle(d),other=lifecycle(d,binding("123456","worker-b","z"));
 const issued=await a.issue({serverReference:trusted});
 assert.deepEqual(await other.claim({challengeId:issued.challengeId,serverReference:trusted}),{state:"BLOCKED",code:"PROOF_CHALLENGE_BINDING_MISMATCH"});
 assert.equal((await a.inspectForTest(issued.challengeId)).state,"ISSUED");
 const claim=await a.claim({challengeId:issued.challengeId,serverReference:trusted}); assert.equal(claim.state,"CLAIMED");
 assert.deepEqual(await other.finalize({challengeId:issued.challengeId,serverReference:trusted,outcome:"CONSUMED"}),{state:"BLOCKED",code:"PROOF_CHALLENGE_BINDING_MISMATCH"});
 assert.equal((await a.inspectForTest(issued.challengeId)).state,"CLAIMED");
});

test("untrusted server context, malformed id, unsupported terminal state fail closed",async()=>{
 const d=new FakeDurableStorage(),api=lifecycle(d);
 assert.deepEqual(await api.issue({serverReference:{trusted:false,workerId:"forged"}}),{state:"BLOCKED",code:"PROOF_CHALLENGE_TRUST_CONTEXT_UNAVAILABLE"});
 assert.deepEqual(await api.claim({challengeId:"a",serverReference:trusted}),{state:"BLOCKED",code:"PROOF_CHALLENGE_ID_INVALID"});
 const issued=await api.issue({serverReference:trusted});
 assert.deepEqual(await api.finalize({challengeId:issued.challengeId,serverReference:trusted,outcome:"ISSUED"}),{state:"BLOCKED",code:"PROOF_CHALLENGE_FINALIZE_INPUT_INVALID"});
});

test("expiry is terminal rejection; backwards clock cannot revive issue",async()=>{
 const d=new FakeDurableStorage();let now=2_000_000_000_000;
 const api=createAndroidProofChallengeLifecycle({store:createPairingAtomicStore(d),installationId:"123456",resolveTrustedContext:async r=>r?.trusted?binding():null,cryptoImpl:webcrypto,clock:()=>now});
 const issued=await api.issue({serverReference:trusted}); now=issued.expiresAtMs;
 assert.deepEqual(await api.claim({challengeId:issued.challengeId,serverReference:trusted}),{state:"BLOCKED",code:"PROOF_CHALLENGE_EXPIRED"});
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"REJECTED");
 now=issued.issuedAtMs;
 assert.deepEqual(await api.claim({challengeId:issued.challengeId,serverReference:trusted}),{state:"BLOCKED",code:"PROOF_CHALLENGE_NOT_ISSUED"});
});

test("storage commit uncertainty returns BLOCKED and never exposes a challenge",async()=>{
 const d=new FakeDurableStorage(),api=lifecycle(d);
 d.failCommit=true;
 assert.deepEqual(await api.issue({serverReference:trusted}),{state:"BLOCKED",code:"PROOF_CHALLENGE_STORAGE_UNAVAILABLE"});
 assert.equal(d.data.has("bke:proof-challenge:v1:rows"),false);
 const issued=await api.issue({serverReference:trusted}); d.failCommit=true;
 assert.deepEqual(await api.claim({challengeId:issued.challengeId,serverReference:trusted}),{state:"BLOCKED",code:"PROOF_CHALLENGE_STORAGE_UNAVAILABLE"});
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"ISSUED");
});

test("vault HTTP fetch remains 404 and has no public lifecycle methods",async()=>{
 const d=new FakeDurableStorage(),vault=new BkeWorkerPairingVault({storage:d,id:{toString:()=>"installation:123456"}},{});
 assert.equal((await vault.fetch(new Request("https://example.invalid/proof-challenge"))).status,404);
 assert.equal(typeof vault.issueProofChallenge,"function");
 assert.equal(typeof vault.claimProofChallenge,"function");
 assert.equal(typeof vault.finalizeProofChallenge,"function");
 assert.deepEqual(await vault.issueProofChallenge({serverReference:trusted}),{state:"BLOCKED",code:"PROOF_CHALLENGE_LOCKED"});
 assert.equal(d.transactions,0);
});

test("state persists across reconstructed lifecycle client and installation is isolated",async()=>{
 const d=new FakeDurableStorage(),api=lifecycle(d);
 const issued=await api.issue({serverReference:trusted});
 const apiAfterRestart=lifecycle(d);
 const claim=await apiAfterRestart.claim({challengeId:issued.challengeId,serverReference:trusted});
 assert.equal(claim.state,"CLAIMED");
 const isolated=lifecycle(new FakeDurableStorage(),binding("654321","worker-a","a"));
 assert.deepEqual(await isolated.claim({challengeId:issued.challengeId,serverReference:trusted}),{state:"BLOCKED",code:"PROOF_CHALLENGE_MISSING_OR_USED"});
});
