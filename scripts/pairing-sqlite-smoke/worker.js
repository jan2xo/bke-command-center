// LOCAL-ONLY Workerd SQLite fixture, never imported by deployable configuration.
import { DurableObject } from "cloudflare:workers";
import { createPairingAtomicStore, createAndroidProofChallengeLifecycle } from "../../src/worker-pairing-durable-store.js";
const fixed=(status,data)=>Response.json(data,{status,headers:{"cache-control":"no-store"}});
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const requireCondition=(condition,code)=>{if(!condition)throw Error(code);};
let fakeNow=2_000_000_000_000;
const AUD="bke-command-center/android-attestation-proof/v1";
const context=(installationId,workerId="worker-a",suffix="a")=>({
 installation_id:installationId,worker_id:workerId,
 session_sha256:(suffix==="a"?"a":"b").repeat(64),
 profile_sha256:(suffix==="a"?"c":"d").repeat(64),
 bridge_sha256:(suffix==="a"?"e":"f").repeat(64),
 target_sha256:(suffix==="a"?"1":"2").repeat(64),
 audience:AUD,purpose:"android-attestation-proof-v1"
});
export class SmokeVault extends DurableObject {
 #store;
 constructor(ctx,env){super(ctx,env);this.#store=createPairingAtomicStore(ctx.storage);}
 async reset(){return this.#store.atomic(async tx=>{for(const k of ["paired","pending","admin_actions","consents","prepared","proof_challenges"])await tx.put(k,[]);return "RESET";});}
 #challengeApi(installationId, suffix="a"){return createAndroidProofChallengeLifecycle({
  store:this.#store,installationId,
  resolveTrustedContext:async ref=>ref?.trusted===true?context(installationId,ref.workerId||"worker-a",ref.suffix||suffix):null,
  clock:()=>fakeNow,
 });}
 async issueTest(ref){return this.#challengeApi("123456",ref?.suffix||"a").issue({serverReference:ref});}
 async claimTest(id,ref){return this.#challengeApi("123456",ref?.suffix||"a").claim({challengeId:id,serverReference:ref});}
 async finalizeTest(id,ref,outcome){return this.#challengeApi("123456",ref?.suffix||"a").finalize({challengeId:id,serverReference:ref,outcome});}
 async record(label){if(!["a","b","c","d"].includes(label))throw Error("SMOKE_INPUT");return this.#store.atomic(async tx=>{const before=(await tx.get("paired"))??[];await tx.put("paired",[...before,{id:label}]);return before.length+1;});}
 async commitAll(){return this.#store.atomic(async tx=>{const existing=(await tx.get("paired"))??[];await tx.put("paired",existing);await tx.put("pending",[{id:"challenge"}]);await tx.put("admin_actions",[{id:"ticket"}]);await tx.put("consents",[{id:"human-proposal"}]);await tx.put("prepared",[{id:"signed-device-offer"}]);return "COMMITTED";});}
 async failAll(){try{await this.#store.atomic(async tx=>{for(const k of ["paired","pending","admin_actions","consents","prepared"])await tx.put(k,[{id:"CORRUPT"}]);throw Error("INTENTIONAL_ROLLBACK");});}catch(e){return e.message==="PAIRING_STORAGE_UNAVAILABLE"?"ROLLED_BACK":"BAD_ERROR_CODE";}return "PARTIAL_COMMIT";}
 async inspect(){return this.#store.atomic(async tx=>({paired:(await tx.get("paired"))??[],pending:(await tx.get("pending"))??[],admin_actions:(await tx.get("admin_actions"))??[],consents:(await tx.get("consents"))??[],prepared:(await tx.get("prepared"))??[],proof_challenges:(await tx.get("proof_challenges"))??[]}));}
}
export default {async fetch(request,env){
 const url=new URL(request.url);
 if(request.method!=="GET"||env?.BKE_SQLITE_SMOKE_FIXTURE!=="true"||!["127.0.0.1","localhost"].includes(url.hostname))return fixed(404,{state:"LOCKED"});
 const a=env.SMOKE_VAULT.get(env.SMOKE_VAULT.idFromName("installation:local-test-a"));
 const b=env.SMOKE_VAULT.get(env.SMOKE_VAULT.idFromName("installation:local-test-b"));
 if(url.pathname==="/health")return fixed(200,{state:"READY",fixture:"LOCAL_SQLITE_DO_ONLY"});
 if(url.pathname==="/verify"){const [one,other]=await Promise.all([a.inspect(),b.inspect()]);return fixed(200,{state:"OBSERVED",a_paired_count:one.paired.length,b_paired_count:other.paired.length,pending_count:one.pending.length,admin_actions_count:one.admin_actions.length,consent_count:one.consents.length,prepared_count:one.prepared.length,proof_challenge_count:one.proof_challenges.length});}
 if(url.pathname!=="/smoke")return fixed(404,{state:"LOCKED"});
 try {
  await a.reset();await b.reset();
  requireCondition(await a.record("a")===1&&await a.record("b")===2,"SEQUENTIAL_PERSIST");
  requireCondition((await b.inspect()).paired.length===0,"INSTALLATION_ISOLATION");
  requireCondition(await a.commitAll()==="COMMITTED","FIVE_KEY_COMMIT");
  const before=await a.inspect();requireCondition(before.paired.length===2&&before.pending.length===1&&before.admin_actions.length===1&&before.consents.length===1&&before.prepared.length===1,"FIVE_KEY_VISIBILITY");
  requireCondition(await a.failAll()==="ROLLED_BACK","ROLLBACK");requireCondition(same(before,await a.inspect()),"ATOMIC_NO_PARTIAL_WRITE");
  await Promise.all([a.record("c"),a.record("d")]);requireCondition((await a.inspect()).paired.length===4,"PAIRING_CONCURRENCY");
  const owner={trusted:true,workerId:"worker-a",suffix:"a"};
  const issued=await a.issueTest(owner);requireCondition(issued.state==="ISSUED","PROOF_ISSUE");
  const contests=await Promise.all([a.claimTest(issued.challengeId,owner),a.claimTest(issued.challengeId,owner)]);
  requireCondition(contests.filter(x=>x.state==="CLAIMED").length===1&&contests.filter(x=>x.state==="BLOCKED").length===1,"PROOF_EXCLUSIVE_CLAIM");
  const result=contests.find(x=>x.state==="CLAIMED");
  requireCondition(Buffer.from(result.proofChallenge.challengeBase64Url,"base64url").length===32,"PROOF_NONCE_BYTES");
  requireCondition((await a.finalizeTest(issued.challengeId,owner,"CONSUMED")).state==="CONSUMED","PROOF_CONSUME");
  requireCondition((await a.claimTest(issued.challengeId,owner)).state==="BLOCKED","PROOF_REPLAY");
  const durable=await a.inspect();requireCondition(durable.proof_challenges[0].state==="CONSUMED","PROOF_TERMINAL_PERSISTENCE");
  const blocked=await a.issueTest({trusted:false,workerId:"forged"});requireCondition(blocked.state==="BLOCKED","PROOF_TRUST_REQUIRED");
  return fixed(200,{state:"PASS",checks:["installation_isolation","sequential_sqlite_persistence","five_key_rollback","pairing_concurrency","proof_issue","concurrent_exclusive_claim","canonical_32_byte_nonce","terminal_consumption","replay_denial","terminal_persistence","trusted_context_required"]});
 }catch{return fixed(500,{state:"FAIL",code:"LOCAL_SQLITE_SMOKE_FAILURE"});}
}};
