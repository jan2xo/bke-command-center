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
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"CONSUMED");
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
 assert.equal((await other.claim({challengeId:issued.challengeId,serverReference:{trusted:true,overrideContext:binding("123456","worker-b","z")}})).state,"BLOCKED");
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"ISSUED");
 const claim=await a.claim({challengeId:issued.challengeId,serverReference:trusted}); assert.equal(claim.state,"CLAIMED");
 assert.equal((await other.finalize({challengeId:issued.challengeId,serverReference:{trusted:true,overrideContext:binding("123456","worker-b","z")},outcome:"CONSUMED"})).state,"BLOCKED");
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"CLAIMED");
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
 now=issued.issuedAtMs+1;
 assert.equal((await api.claim({challengeId:issued.challengeId,serverReference:trusted})).state,"BLOCKED");
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"REJECTED");
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


test("expiry is rechecked after stalled trusted-context resolution before claim mutation",async()=>{
 const d=new FakeDurableStorage();
 let now=2_000_000_000_000;
 let release;
 const gate=new Promise(resolve=>{release=resolve;});
 let stalled=false;
 const api=createAndroidProofChallengeLifecycle({
   store:createPairingAtomicStore(d),installationId:"123456",
   resolveTrustedContext:async reference=>{
     if(reference?.stall===true){stalled=true;await gate;}
     return reference?.trusted===true?binding():null;
   },
   cryptoImpl:webcrypto,clock:()=>now
 });
 const issued=await api.issue({serverReference:trusted});
 const pending=api.claim({challengeId:issued.challengeId,serverReference:{trusted:true,stall:true}});
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(stalled,true);
 now=issued.expiresAtMs;
 release();
 assert.deepEqual(await pending,{state:"BLOCKED",code:"PROOF_CHALLENGE_EXPIRED"});
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"REJECTED");
});

test("expiry is rechecked after stalled trusted-context resolution before terminal finalize",async()=>{
 const d=new FakeDurableStorage();
 let now=2_000_000_000_000;
 let release;
 const gate=new Promise(resolve=>{release=resolve;});
 let stalled=false;
 const api=createAndroidProofChallengeLifecycle({
   store:createPairingAtomicStore(d),installationId:"123456",
   resolveTrustedContext:async reference=>{
     if(reference?.stall===true){stalled=true;await gate;}
     return reference?.trusted===true?binding():null;
   },
   cryptoImpl:webcrypto,clock:()=>now
 });
 const issued=await api.issue({serverReference:trusted});
 assert.equal((await api.claim({challengeId:issued.challengeId,serverReference:trusted})).state,"CLAIMED");
 const pending=api.finalize({challengeId:issued.challengeId,serverReference:{trusted:true,stall:true},outcome:"CONSUMED"});
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(stalled,true);
 now=issued.expiresAtMs;
 release();
 assert.deepEqual(await pending,{state:"BLOCKED",code:"PROOF_CHALLENGE_EXPIRED"});
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"REJECTED");
});

test("enabled vault with missing resolver and wrong Durable Object identity return typed BLOCKED",async()=>{
 const storage=new FakeDurableStorage();
 const idFromName=name=>({toString:()=>name==="installation:123456"?"right-object":"wrong-object"});
 const baseEnv={
  BKE_PREPRODUCTION:"true",BKE_ANDROID_PROOF_CHALLENGE_ENABLED:"true",
  BKE_PAIRING_INSTALLATION_ID:"123456",
  BKE_WORKER_PAIRING_VAULT:{idFromName},
 };
 const noResolver=new BkeWorkerPairingVault({storage,id:{toString:()=>"right-object"}},baseEnv);
 assert.deepEqual(await noResolver.issueProofChallenge({serverReference:trusted}),
  {state:"BLOCKED",code:"PROOF_CHALLENGE_TRUST_CONTEXT_UNAVAILABLE"});
 const resolver=async reference=>reference?.trusted===true?binding():null;
 const validEnv={...baseEnv,BKE_PROOF_CHALLENGE_CONTEXT_RESOLVER:resolver};
 const wrongObject=new BkeWorkerPairingVault({storage,id:{toString:()=>"wrong-object"}},validEnv);
 assert.deepEqual(await wrongObject.issueProofChallenge({serverReference:trusted}),
  {state:"BLOCKED",code:"PROOF_CHALLENGE_OBJECT_MISMATCH"});
 assert.deepEqual(await wrongObject.claimProofChallenge({challengeId:"a",serverReference:trusted}),
  {state:"BLOCKED",code:"PROOF_CHALLENGE_OBJECT_MISMATCH"});
 assert.deepEqual(await wrongObject.finalizeProofChallenge({challengeId:"a",serverReference:trusted,outcome:"CONSUMED"}),
  {state:"BLOCKED",code:"PROOF_CHALLENGE_OBJECT_MISMATCH"});
});


test("queued transaction crossing expiry cannot claim or finalize",async()=>{
 const d=new FakeDurableStorage();
 let now=2_000_000_000_000;
 let release;
 const gate=new Promise(resolve=>{release=resolve;});
 const api=createAndroidProofChallengeLifecycle({
  store:createPairingAtomicStore(d),installationId:"123456",
  resolveTrustedContext:async reference=>reference?.trusted?binding():null,
  cryptoImpl:webcrypto,clock:()=>now
 });
 const issued=await api.issue({serverReference:trusted});
 assert.equal((await api.claim({challengeId:issued.challengeId,serverReference:trusted})).state,"CLAIMED");
 let entered;
 const inQueue=new Promise(resolve=>{entered=resolve;});
 const blocker=d.transaction(async tx=>{entered();await gate;return tx.get("unused");});
 await inQueue;
 const pending=api.finalize({challengeId:issued.challengeId,serverReference:trusted,outcome:"CONSUMED"});
 await new Promise(resolve=>setImmediate(resolve));
 now=issued.expiresAtMs;
 release();
 await blocker;
 assert.deepEqual(await pending,{state:"BLOCKED",code:"PROOF_CHALLENGE_EXPIRED"});
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"REJECTED");
});

test("storage read stalled after transaction entry cannot claim after expiry",async()=>{
 const d=new FakeDurableStorage();let now=2_000_000_000_000;
 const api=createAndroidProofChallengeLifecycle({
  store:createPairingAtomicStore(d),installationId:"123456",
  resolveTrustedContext:async r=>r?.trusted?binding():null,
  cryptoImpl:webcrypto,clock:()=>now
 });
 const issued=await api.issue({serverReference:trusted});
 let releaseRead, markReadEntered;
 const readGate=new Promise(resolve=>{releaseRead=resolve;});
 const readEntered=new Promise(resolve=>{markReadEntered=resolve;});
 const originalTransaction=d.transaction.bind(d);
 let intercept=true;
 d.transaction=fn=>originalTransaction(tx=>{
  const wrapped={
   get:async key=>{
    if(intercept && key==="bke:proof-challenge:v1:rows"){
     intercept=false;markReadEntered();await readGate;
    }
    return tx.get(key);
   },
   put:(key,value)=>tx.put(key,value)
  };
  return fn(wrapped);
 });
 const pending=api.claim({challengeId:issued.challengeId,serverReference:trusted});
 await readEntered;
 now=issued.expiresAtMs;
 releaseRead();
 assert.deepEqual(await pending,{state:"BLOCKED",code:"PROOF_CHALLENGE_EXPIRED"});
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"REJECTED");
});

test("storage read stalled after transaction entry cannot finalize after expiry",async()=>{
 const d=new FakeDurableStorage();let now=2_000_000_000_000;
 const api=createAndroidProofChallengeLifecycle({
  store:createPairingAtomicStore(d),installationId:"123456",
  resolveTrustedContext:async r=>r?.trusted?binding():null,
  cryptoImpl:webcrypto,clock:()=>now
 });
 const issued=await api.issue({serverReference:trusted});
 assert.equal((await api.claim({challengeId:issued.challengeId,serverReference:trusted})).state,"CLAIMED");
 let releaseRead, markReadEntered;
 const readGate=new Promise(resolve=>{releaseRead=resolve;});
 const readEntered=new Promise(resolve=>{markReadEntered=resolve;});
 const originalTransaction=d.transaction.bind(d);
 let intercept=true;
 d.transaction=fn=>originalTransaction(tx=>{
  const wrapped={
   get:async key=>{
    if(intercept && key==="bke:proof-challenge:v1:rows"){
     intercept=false;markReadEntered();await readGate;
    }
    return tx.get(key);
   },
   put:(key,value)=>tx.put(key,value)
  };
  return fn(wrapped);
 });
 const pending=api.finalize({challengeId:issued.challengeId,serverReference:trusted,outcome:"CONSUMED"});
 await readEntered;
 now=issued.expiresAtMs;
 releaseRead();
 assert.deepEqual(await pending,{state:"BLOCKED",code:"PROOF_CHALLENGE_EXPIRED"});
 assert.equal(d.data.get("bke:proof-challenge:v1:rows")[0].state,"REJECTED");
});

test("issuance starts its TTL after a stalled storage read completes",async()=>{
 const d=new FakeDurableStorage();let now=2_000_000_000_000;
 const api=createAndroidProofChallengeLifecycle({
  store:createPairingAtomicStore(d),installationId:"123456",
  resolveTrustedContext:async r=>r?.trusted?binding():null,
  cryptoImpl:webcrypto,clock:()=>now
 });
 let releaseRead, markReadEntered;
 const readGate=new Promise(resolve=>{releaseRead=resolve;});
 const readEntered=new Promise(resolve=>{markReadEntered=resolve;});
 const originalTransaction=d.transaction.bind(d);
 let intercept=true;
 d.transaction=fn=>originalTransaction(tx=>{
  const wrapped={
   get:async key=>{
    if(intercept && key==="bke:proof-challenge:v1:rows"){
     intercept=false;markReadEntered();await readGate;
    }
    return tx.get(key);
   },
   put:(key,value)=>tx.put(key,value)
  };
  return fn(wrapped);
 });
 const pending=api.issue({serverReference:trusted});
 await readEntered;
 now+=75_000;
 releaseRead();
 const issued=await pending;
 assert.equal(issued.state,"ISSUED");
 assert.equal(issued.issuedAtMs,now);
 assert.equal(issued.expiresAtMs,now+120_000);
});
