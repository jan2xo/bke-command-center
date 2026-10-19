import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { sendAdminPairingInvitation, receiveAdminPairingInvitation } from "../src/admin-invitation-rpc.js";
import { computePairingProposalSha256 } from "../src/admin-atomic-pairing-invitation.js";
import { createAdminProposalConsent } from "../src/admin-pairing-proposal-consent.js";
import { createPairingAtomicStore, BkeWorkerPairingVault } from "../src/worker-pairing-durable-store.js";
import { parseTrustedWorkerAssignmentPayload } from "../src/admin-worker-assignments.js";

const KEY_BYTES=Buffer.alloc(32,47), KEY=KEY_BYTES.toString("base64url");
const AUD="bke-command-center/preproduction/execute-protected-inactive-pairing/v1";
const ADMIN={access:{aud:"0123456789abcdef0123456789abcdef",
  async getIdentity(){return {email:"admin@example.test"};}}};
const ENV={
  BKE_PREPRODUCTION:"true",BKE_ACCESS_POLICY_VERIFIED:"true",
  BKE_ADMIN_DISCOVERY_ENABLED:"true",
  BKE_ADMIN_ACCESS_ISSUER:"https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD:ADMIN.access.aud,BKE_ADMIN_EMAILS:"admin@example.test",
  BKE_ADMIN_PR_INVENTORY_ENABLED:"true",BKE_ADMIN_PAIRING_ACTIONS_ENABLED:"true",
  BKE_ADMIN_PROTECTED_PAIRING_ENABLED:"true",BKE_ADMIN_PAIRING_ISSUANCE_ENABLED:"true",
  BKE_ADMIN_PROPOSAL_CONSENT_ENABLED:"true",BKE_ADMIN_DO_ROUTING_ENABLED:"true",
  BKE_ADMIN_INVITATION_RPC_ENABLED:"true",BKE_PAIRING_RPC_KEY_B64:KEY,
};
const resources=(n=0)=>({
  chatgpt_target_sha256:"123456789abcdef0"[n].repeat(64),
  browser_profile_sha256:"123456789abcdef0"[n+4].repeat(64),
  bridge_identity_sha256:"123456789abcdef0"[n+8].repeat(64),
});
const raw=(id="51")=>({
  authority:"EXISTING_GITHUB_APP_INSTALLATION",principal:"github_app_installation",
  repository_scope:"INSTALLATION_APPROVED_ONLY",consistency:"NON_ATOMIC_ENUMERATION",
  installation_id:id,total_visible_repositories:2,
  enumerated_open_pull_requests:0,worker_assignments:[],
});
const denied=(result)=> {
  assert.equal(result.state,"BLOCKED");
  assert.deepEqual(Object.keys(result).sort(),["code","state"]);
  assert.doesNotMatch(JSON.stringify(result),/one_time_nonce|ghs_|Bearer|admin@example.test|private backend/u);
};
function storage(){
  let state=new Map(),lock=Promise.resolve();
  return {
    failAt:0,
    async transaction(run){
      let done;const next=new Promise(r=>done=r);
      const prev=lock;lock=next;await prev;
      const draft=new Map(structuredClone([...state]));
      let writes=0;
      try{
        const reply=await run({
          get:async key=>structuredClone(draft.get(key)),
          put:async(key,value)=>{
            if(++writes===this.failAt)throw Error("private backend token");
            draft.set(key,structuredClone(value));
          },
        });
        state=draft;return reply;
      }finally{done();}
    },
    read:name=>structuredClone(state.get("bke:pairing:v1:"+name)),
  };
}
async function subject(){
  const key=await webcrypto.subtle.importKey("raw",KEY_BYTES,
    {name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const raw=await webcrypto.subtle.sign("HMAC",key,new TextEncoder().encode(
    JSON.stringify([AUD,"human-subject",ADMIN.access.aud,"admin@example.test"])));
  return Buffer.from(raw).toString("hex");
}
async function keypair(){
  const keys=await webcrypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,
    ["sign","verify"]);
  const key=await webcrypto.subtle.exportKey("jwk",keys.publicKey);
  return {crv:"P-256",kty:"EC",x:key.x,y:key.y};
}
function confirmRequest(challenge){
  return new Request("https://cc.jl-bke.com/api/admin/pairing/confirm-proposal",{
    method:"POST",headers:{
      origin:"https://cc.jl-bke.com","sec-fetch-site":"same-origin",
      "sec-fetch-mode":"cors","content-type":"application/json",
      "x-bke-admin-action":"pair",
    },body:JSON.stringify({
      action:"pair",challenge_id:challenge.challenge_id,
      confirm_worker_id:challenge.worker_id,worker_id:challenge.worker_id,
      proposal_sha256:challenge.proposal_sha256,
    }),
  });
}
async function harness(id="51"){
  const stores=new Map(),issued=[];
  const db=(install)=>{
    if(!stores.has(install))stores.set(install,storage());
    return stores.get(install);
  };
  const state={raw:raw(id),receiverRaw:null,unavailable:false,
    stub:null,request:null,readCount:0};
  let env;
  const ns={
    idFromName:name=>({toString:()=>"DO:"+name}),
    get:obj=>{
      if(state.stub)return state.stub(obj);
      const name=obj.toString().replace("DO:installation:","");
      return new BkeWorkerPairingVault({id:obj,storage:db(name)},env);
    },
  };
  env={...ENV,BKE_WORKER_PAIRING_VAULT:ns,BKE_GITHUB_READ_BROKER:{
    async listVerifiedWorkerAssignments(purpose) {
      assert.deepEqual(purpose,{purpose:"admin_worker_assignment_inventory"});
      state.readCount++;
      if(state.unavailable)throw Error("private broker token");
      return structuredClone(state.receiverRaw??state.raw);
    },
  }};
  const person=await subject();
  const consent=createAdminProposalConsent({
    store:createPairingAtomicStore(db(id)),cryptoImpl:webcrypto,
    authorizeSubject:async(action,worker,proposal,ctx)=>
      action==="pair" && ctx===ADMIN && /^[a-z0-9-]+$/u.test(worker) &&
      /^[a-f0-9]{64}$/u.test(proposal) ? person:null,
  });
  const prepare=async(worker="worker-a",key=null,res=resources())=>{
    const public_key=key??await keypair();
    const digest=await computePairingProposalSha256({
      installationId:id,workerId:worker,publicKey:public_key,
      resources:res,cryptoImpl:webcrypto,
    });
    assert.ok(digest);
    const challenge=await consent.present({
      worker_id:worker,proposal_sha256:digest.proposalHash,env,executionCtx:ADMIN,
    });
    assert.equal(challenge.state,"AWAITING_EXPLICIT_HUMAN_CONFIRMATION");
    assert.equal((await consent.confirm({
      request:confirmRequest(challenge),env,executionCtx:ADMIN,
    })).state,"CONFIRMED_FOR_ATOMIC_ISSUANCE");
    return {worker_id:worker,public_key,resources:res,
      consent_challenge_id:challenge.challenge_id};
  };
  const send=(proposal,options={})=>sendAdminPairingInvitation({
    env,executionCtx:ADMIN,proposal,cryptoImpl:webcrypto,
    onPrivateIssued:async invitation=>issued.push(invitation),
    readAssignments:async()=>parseTrustedWorkerAssignmentPayload(structuredClone(state.raw)),
    ...options,
  });
  return {id,env,db,ns,state,issued,consent,prepare,send,person};
}

test("platform Access + two independent broker reads + signed DO issues consent/ticket/challenge atomically",async()=>{
  const f=await harness(),proposal=await f.prepare();
  const receipt=await f.send(proposal);
  assert.equal(receipt.state,"ISSUED_FOR_PRIVATE_DELIVERY");
  assert.equal(receipt.pairing_authority,"NONE");
  assert.equal(receipt.dispatch_authority,"NONE");
  assert.equal(f.state.readCount,1);
  assert.equal(f.issued.length,1);
  assert.match(f.issued[0].human_ticket.one_time_nonce,/^[a-f0-9]{64}$/u);
  assert.ok(!JSON.stringify(receipt).includes(f.issued[0].human_ticket.one_time_nonce));
  assert.equal(f.db("51").read("consents")[0].status,"CONSUMED");
  assert.equal(f.db("51").read("pending").length,1);
  assert.equal(f.db("51").read("admin_actions")[0].status,"PENDING");
  assert.equal(f.db("51").read("paired"),undefined);
  assert.ok(!JSON.stringify([...f.db("51").read("admin_actions"),
    ...f.db("51").read("pending")]).includes(f.issued[0].human_ticket.one_time_nonce));
});

test("successful command replay cannot create second invitation",async()=>{
  const f=await harness(),p=await f.prepare();
  assert.equal((await f.send(p)).state,"ISSUED_FOR_PRIVATE_DELIVERY");
  denied(await f.send(p));
  assert.equal(f.issued.length,1);
  assert.equal(f.db("51").read("pending").length,1);
});

test("racing signed requests consume one consent and produce one invitation",async()=>{
  const f=await harness(),p=await f.prepare();
  const results=await Promise.all([f.send(p),f.send(p)]);
  assert.equal(results.filter(r=>r.state==="ISSUED_FOR_PRIVATE_DELIVERY").length,1);
  assert.equal(f.db("51").read("pending").length,1);
  assert.equal(f.db("51").read("consents")[0].status,"CONSUMED");
});

test("wrong installation object fails closed without consuming consent",async()=>{
  const f=await harness(),p=await f.prepare();
  f.state.stub=()=>new BkeWorkerPairingVault({
    id:f.ns.idFromName("installation:52"),storage:f.db("52"),
  },f.env);
  denied(await f.send(p));
  assert.equal(f.db("51").read("consents")[0].status,"CONFIRMED");
  assert.equal(f.db("52").read("pending"),undefined);
});

test("recipient independently rejects changed broker installation",async()=>{
  const f=await harness(),p=await f.prepare();
  f.state.receiverRaw=raw("52");
  denied(await f.send(p));
  assert.equal(f.db("51").read("consents")[0].status,"CONFIRMED");
});

test("recipient rejects broker outage, duplicate/ambiguous assignment",async()=>{
  const f=await harness(),p=await f.prepare();
  f.state.unavailable=true;
  denied(await f.send(p));
  f.state.unavailable=false;
  f.state.receiverRaw={...raw("51"),enumerated_open_pull_requests:1,
    worker_assignments:[{
      repository:"jan2xo/bke-worker",repository_id:12345,number:9,
      state:"open",head_sha:"a".repeat(40),labels:["bke-worker:worker-a"],
    }]};
  denied(await f.send(p));
  assert.equal(f.db("51").read("consents")[0].status,"CONFIRMED");
});

test("changed public key, worker and target/profile/bridge digests cannot use approval",async()=>{
  const f=await harness(),p=await f.prepare();
  const differentKey=await keypair();
  for(const changes of [
    {public_key:differentKey},{worker_id:"worker-b"},
    {resources:{...p.resources,chatgpt_target_sha256:"e".repeat(64)}},
    {resources:{...p.resources,browser_profile_sha256:"e".repeat(64)}},
    {resources:{...p.resources,bridge_identity_sha256:"e".repeat(64)}},
  ]){
    denied(await f.send({...p,...changes}));
  }
  assert.equal(f.db("51").read("consents")[0].status,"CONFIRMED");
  assert.equal(f.db("51").read("pending"),undefined);
});

test("third write failure rolls back confirmed consent and both proofs",async()=>{
  const f=await harness(),p=await f.prepare();
  f.db("51").failAt=3;
  denied(await f.send(p));
  assert.equal(f.db("51").read("consents")[0].status,"CONFIRMED");
  assert.equal(f.db("51").read("pending"),undefined);
  assert.equal(f.db("51").read("admin_actions"),undefined);
  f.db("51").failAt=0;
  assert.equal((await f.send(p)).state,"ISSUED_FOR_PRIVATE_DELIVERY");
});

test("private sink failure is uncertain; no nonce returned and retry cannot reissue",async()=>{
  const f=await harness(),p=await f.prepare();
  const out=await f.send(p,{onPrivateIssued:async()=>{throw Error("private sink failed");}});
  denied(out);
  assert.equal(out.code,"INVITE_RPC_OUTCOME_UNCERTAIN");
  assert.equal(f.db("51").read("consents")[0].status,"CONSUMED");
  denied(await f.send(p));
});

test("no verified Cloudflare platform Access / denylisted human blocks before broker",async()=>{
  const f=await harness(),p=await f.prepare();
  for(const executionCtx of [
    {},{access:{aud:ADMIN.access.aud,async getIdentity(){return {email:"attacker@example.test"};}}},
    {access:{aud:"other-audience",async getIdentity(){return {email:"admin@example.test"};}}},
  ])denied(await f.send(p,{executionCtx}));
  assert.equal(f.state.readCount,0);
  assert.equal(f.db("51").read("consents")[0].status,"CONFIRMED");
});

test("separate feature gate and missing HMAC secret deny all mutation",async()=>{
  const f=await harness(),p=await f.prepare();
  for(const name of [
    "BKE_ADMIN_INVITATION_RPC_ENABLED","BKE_ADMIN_DO_ROUTING_ENABLED",
    "BKE_ADMIN_PROPOSAL_CONSENT_ENABLED","BKE_ADMIN_PAIRING_ISSUANCE_ENABLED",
  ])denied(await f.send(p,{env:{...f.env,[name]:undefined}}));
  denied(await f.send(p,{env:{...f.env,BKE_PAIRING_RPC_KEY_B64:undefined}}));
  assert.equal(f.state.readCount,0);
});

test("tightly shaped signed command rejects tamper, wrong purpose, expired and wrong subject",async()=>{
  const f=await harness(),p=await f.prepare();
  let signed;
  f.state.stub=()=>({async issueAtomicPairingInvitation(req){signed=structuredClone(req);
    return {state:"BLOCKED",code:"INVITE_RPC_REQUEST_REJECTED"};}});
  denied(await f.send(p));
  assert.ok(signed);
  const read=async request=>receiveAdminPairingInvitation({
    request,env:f.env,objectId:f.ns.idFromName("installation:51"),
    store:createPairingAtomicStore(f.db("51")),cryptoImpl:webcrypto,
  });
  for(const change of [
    {purpose:"other"},
    {nonce:"a".repeat(64)},
    {subject_sha256:"b".repeat(64)},
    {signature:"a".repeat(64)},
    {installation_id:"52"},
    {proof:{...signed.proof,worker_id:"worker-b"}},
    {extra:"true"},
    {expires_at_ms:1},
  ]){
    denied(await read({...signed,...change}));
  }
  assert.equal(f.db("51").read("consents")[0].status,"CONFIRMED");
});

test("malformed, unconfirmed and expired human consents cannot issue invitation",async()=>{
  const f=await harness(),p=await f.prepare();
  for(const changes of [
    {consent_challenge_id:"a".repeat(64)},
    {consent_challenge_id:"short"},
    {resources:{...p.resources,evil:"1"}},
    {public_key:{...p.public_key,evil:"1"}},
  ])denied(await f.send({...p,...changes}));
  assert.equal(f.db("51").read("consents")[0].status,"CONFIRMED");
});

test("separate installations can independently invite same worker with separate DO state",async()=>{
  const [a,b]=await Promise.all([harness("51"),harness("52")]);
  const pa=await a.prepare(),pb=await b.prepare();
  assert.equal((await a.send(pa)).state,"ISSUED_FOR_PRIVATE_DELIVERY");
  assert.equal((await b.send(pb)).state,"ISSUED_FOR_PRIVATE_DELIVERY");
  assert.equal(a.db("51").read("pending").length,1);
  assert.equal(b.db("52").read("pending").length,1);
  assert.equal(a.db("52").read("pending"),undefined);
  assert.equal(b.db("51").read("pending"),undefined);
});

test("malformed private return is never forwarded to the sink",async()=>{
  const f=await harness(),p=await f.prepare();
  f.state.stub=()=>({async issueAtomicPairingInvitation(){
    return {state:"ISSUED_FOR_SECURE_DELIVERY",human_ticket:{one_time_nonce:"a".repeat(64)}};
  }});
  denied(await f.send(p));
  assert.equal(f.issued.length,0);
});

test("no public HTTP invitation endpoint and runtime methods remain private",async()=>{
  const entry=readFileSync(new URL("../src/cloudflare-worker-entry.js",import.meta.url),"utf8");
  const bridge=readFileSync(new URL("../src/worker-pairing-durable-store.js",import.meta.url),"utf8");
  const api=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
  const wrangler=readFileSync(new URL("../wrangler.toml",import.meta.url),"utf8");
  assert.match(entry,/issueAtomicPairingInvitation/u);
  assert.match(bridge,/receiveAdminPairingInvitation/u);
  assert.doesNotMatch(api,/sendAdminPairingInvitation|issueAtomicPairingInvitation/u);
  assert.doesNotMatch(wrangler,/BKE_ADMIN_INVITATION_RPC_ENABLED/u);
  const f=await harness();
  const vault=new BkeWorkerPairingVault({id:f.ns.idFromName("installation:51"),
    storage:f.db("51")},f.env);
  assert.equal((await vault.fetch(new Request("https://cc.jl-bke.com/api/admin/pairing/invite"))).status,404);
});
