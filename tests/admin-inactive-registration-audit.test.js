import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {createPairingAtomicStore,BkeWorkerPairingVault} from "../src/worker-pairing-durable-store.js";
import {observeInactivePairingRegistrations} from "../src/admin-inactive-registration-audit.js";

const AT=1_000_000;
const H=x=>x.repeat(64);
const hashes=n=>({
  identity_public_key_sha256:H(n===0?"1":"6"),
  chatgpt_target_sha256:H(n===0?"2":"7"),
  browser_profile_sha256:H(n===0?"3":"8"),
  bridge_identity_sha256:H(n===0?"4":"9"),
  nonce_sha256:H(n===0?"5":"a"),
});
const row=(name="worker-a",n=0)=>({
  worker_id:name,...hashes(n),status:"PAIRED_INACTIVE",
  registered_at_ms:AT-100,enrollment_expires_at_ms:AT+2000,
});
class FakeDurableStorage {
  data=new Map();
  gate=Promise.resolve();
  reads=0; writes=0; transactions=0;
  throwOnRead=false;
  async transaction(fn){
    let release;
    const next=new Promise(resolve=>{release=resolve;});
    const previous=this.gate;this.gate=next;await previous;
    this.transactions++;
    const copy=new Map(structuredClone([...this.data]));
    const tx={
      get:async key=>{
        this.reads++;
        if(this.throwOnRead)throw Error("Sensitive storage exception");
        return structuredClone(copy.get(key));
      },
      put:async(key,value)=>{this.writes++;copy.set(key,structuredClone(value));},
    };
    try{const result=await fn(tx);this.data=copy;return result;}
    finally{release();}
  }
}
function context(rows=[],clock=()=>AT){
  const db=new FakeDurableStorage();
  db.data.set("bke:pairing:v1:paired",structuredClone(rows));
  const store=createPairingAtomicStore(db);
  return {db,store,call:(opts={})=>observeInactivePairingRegistrations({
    store,trustedInstallationId:"123456789",clock,...opts,
  })};
}
const denied=(call)=>assert.rejects(call,/INACTIVE_REGISTRATION_SNAPSHOT_UNAVAILABLE/);

test("real vault transaction projects only unexpired inactive IDs and FOUR immutable fingerprints",async()=>{
 const x=context([row("worker-b",1),row()]);
 const observation=await x.call();
 assert.deepEqual(Object.keys(observation).sort(),[
   "dispatch_authority","inactive_unexpired_workers","observed_at_ms",
   "pairing_activation","registrations","registry_rows","session_binding_authority",
   "state","trusted_installation_id","wake_authority",
 ]);
 assert.equal(observation.state,"PAIRED_INACTIVE_OBSERVED");
 assert.equal(observation.trusted_installation_id,"123456789");
 assert.equal(observation.registry_rows,2);
 assert.equal(observation.inactive_unexpired_workers,2);
 assert.deepEqual(observation.registrations.map(x=>x.worker_id),["worker-a","worker-b"]);
 assert.equal(Object.isFrozen(observation),true);
 assert.equal(Object.isFrozen(observation.registrations),true);
 assert.equal(Object.isFrozen(observation.registrations[0]),true);
 assert.deepEqual(Object.keys(observation.registrations[0]).sort(),[
  "bridge_identity_sha256","browser_profile_sha256","chatgpt_target_sha256",
  "identity_public_key_sha256","worker_id",
 ]);
 assert.equal(observation.dispatch_authority,"NONE");
 assert.equal(observation.wake_authority,"NONE");
 assert.equal(observation.session_binding_authority,"NONE");
 assert.equal(observation.pairing_activation,"NONE");
 assert.equal(x.db.transactions,1);
 assert.equal(x.db.reads,1);
 assert.equal(x.db.writes,0);
 assert.doesNotMatch(JSON.stringify(observation),/nonce_sha256|session_binding_sha256|private_key|token|secret/);
});

test("empty vault is observed only; no invented worker, token or live session",async()=>{
 const x=context();
 const r=await x.call();
 assert.equal(r.inactive_unexpired_workers,0);
 assert.deepEqual(r.registrations,[]);
 assert.equal(x.db.writes,0);
});

test("revoked and expired registrations never appear as eligible inactive rows",async()=>{
 const revoked={...row(),status:"REVOKED",enrollment_expires_at_ms:AT-1};
 const expired={...row("worker-b",1),enrollment_expires_at_ms:AT-1};
 const x=context([revoked,expired]);
 const result=await x.call();
 assert.equal(result.registry_rows,2);
 assert.equal(result.inactive_unexpired_workers,0);
 assert.deepEqual(result.registrations,[]);
});

test("duplicate IDs, reused target, profile, bridge, identity or nonce block whole registry",async()=>{
 const a=row(),b=row("worker-b",1);
 for(const bad of [
  {...b,worker_id:"worker-a"},
  ...["identity_public_key_sha256","chatgpt_target_sha256","browser_profile_sha256","bridge_identity_sha256","nonce_sha256"].map(field=>({...b,[field]:a[field]})),
 ])await denied(context([a,bad]).call);
});

test("a malformed or revoked unrelated row invalidates ALL registry evidence",async()=>{
 const a=row(),b=row("worker-b",1);
 const corruptions=[
  {...b,untrusted:true},
  {...b,status:"PAIRED_ACTIVE"},
  {...b,worker_id:"Worker-B"},
  {...b,identity_public_key_sha256:"INVALID"},
  {...b,nonce_sha256:"ab"},
  {...b,registered_at_ms:AT+1},
  {...b,registered_at_ms:0},
  {...b,enrollment_expires_at_ms:AT-200},
  {...b,enrollment_expires_at_ms:AT+3_600_001},
  {...b,status:"REVOKED",registered_at_ms:AT+1},
 ];
 for(const modified of corruptions)await denied(context([a,modified]).call);
});

test("refuse untrusted installation IDs, missing store and unexpected clock types",async()=>{
 const x=context([row()]);
 for(const id of ["0","-1","012","browser-chosen",123,undefined]){
   await denied(()=>x.call({trustedInstallationId:id}));
 }
 await denied(()=>x.call({store:{}}));
 for(const now of [0,NaN,"1000",Number.MAX_SAFE_INTEGER]){
   await denied(()=>x.call({clock:()=>now}));
 }
});

test("storage rejection and invalid paired storage shape are not exposed",async()=>{
 const x=context([row()]);
 x.db.throwOnRead=true;
 await denied(x.call);
 assert.equal(x.db.writes,0);
 const y=context();
 y.db.data.set("bke:pairing:v1:paired",{fake:true});
 await denied(y.call);
 const z=context();
 z.db.data.set("bke:pairing:v1:paired",Array.from({length:101},(_,i)=>row("worker-"+i)));
 await denied(z.call);
});

test("one serializable transaction sees prior committed revocation, not partial state",async()=>{
 const x=context([row()]);
 let release;
 const delay=new Promise(resolve=>{release=resolve;});
 let entered;
 const started=new Promise(resolve=>{entered=resolve;});
 const mutation=x.store.atomic(async tx=>{
   const data=await tx.get("paired");
   entered();
   await delay;
   await tx.put("paired",data.map(r=>({...r,status:"REVOKED",enrollment_expires_at_ms:AT})));
 });
 await started;
 const observation=x.call();
 release();
 await mutation;
 const result=await observation;
 assert.equal(result.registry_rows,1);
 assert.equal(result.inactive_unexpired_workers,0);
 assert.equal(x.db.writes,1); // explicit test mutation ONLY
});

test("clock regression, excessive delay and transition-to-expired all fail closed",async()=>{
 for(const sequence of [[AT,AT-1],[AT,AT+30_001],[AT,AT+2_001]]){
   const x=context([row()],()=>sequence.shift());
   await denied(x.call);
 }
});

test("the new projection is unwired from deployable routes and no public RPC is exposed",()=>{
 const entry=readFileSync(new URL("../src/cloudflare-worker-entry.js",import.meta.url),"utf8");
 const index=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
 const vault=readFileSync(new URL("../src/worker-pairing-durable-store.js",import.meta.url),"utf8");
 const config=readFileSync(new URL("../wrangler.toml",import.meta.url),"utf8");
 for(const source of [entry,index,vault,config])assert.doesNotMatch(source,/observeInactivePairingRegistrations|admin-inactive-registration-audit/u);
 assert.doesNotMatch(config,/BKE_MULTIWORKER_ACTIVE|BKE_INACTIVE_REGISTRY_AUDIT_ENABLED/u);
 const fake=new FakeDurableStorage();
 const instance=new BkeWorkerPairingVault({storage:fake},{});
 assert.equal(typeof instance.observeInactivePairingRegistrations,"undefined");
});
