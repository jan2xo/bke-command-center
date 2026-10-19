import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { stageDeviceOriginProposal,loadPreparedDeviceProposal,createAdminPreparedProposalServer,
  receivePreparedDeviceProposal } from "../src/admin-device-proposal-preparation.js";
import { createPairingAtomicStore,BkeWorkerPairingVault } from "../src/worker-pairing-durable-store.js";
import { parseTrustedWorkerAssignmentPayload } from "../src/admin-worker-assignments.js";
import { handleRequest } from "../src/index.js";

const KEY_BYTES=Buffer.alloc(32,83),KEY=KEY_BYTES.toString("base64url");
const ADMIN={access:{aud:"0123456789abcdef0123456789abcdef",
  async getIdentity(){return {email:"admin@example.test"};}}};
const FLAGS={
  BKE_PREPRODUCTION:"true",BKE_ACCESS_POLICY_VERIFIED:"true",
  BKE_ADMIN_DISCOVERY_ENABLED:"true",
  BKE_ADMIN_ACCESS_ISSUER:"https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD:ADMIN.access.aud,BKE_ADMIN_EMAILS:"admin@example.test",
  BKE_ADMIN_PR_INVENTORY_ENABLED:"true",
  BKE_ADMIN_PAIRING_ACTIONS_ENABLED:"true",
  BKE_ADMIN_PAIRING_REVIEW_ENABLED:"true",
  BKE_ADMIN_PROPOSAL_CONSENT_ENABLED:"true",
  BKE_ADMIN_DEVICE_PREPARATION_ENABLED:"true",
  BKE_PAIRING_RPC_KEY_B64:KEY,
};
const raw=(id="51",workerAssignments=[])=>({
  principal:"github_app_installation",authority:"EXISTING_GITHUB_APP_INSTALLATION",
  repository_scope:"INSTALLATION_APPROVED_ONLY",consistency:"NON_ATOMIC_ENUMERATION",
  installation_id:id,total_visible_repositories:4,
  enumerated_open_pull_requests:workerAssignments.length,
  worker_assignments:workerAssignments,
});
const resources=(n=0)=>({
  chatgpt_target_sha256:"123456789abcdef0"[n].repeat(64),
  browser_profile_sha256:"123456789abcdef0"[n+4].repeat(64),
  bridge_identity_sha256:"123456789abcdef0"[n+8].repeat(64),
});
const blocked=x=>{
  assert.equal(x.state,"BLOCKED");
  assert.deepEqual(Object.keys(x).sort(),["code","state"]);
  assert.doesNotMatch(JSON.stringify(x),/ghs_|Bearer|email|one_time_nonce|secret/u);
};
const matrix=()=> {
  let content=new Map(),gate=Promise.resolve();
  return {
    failAt:0,
    async transaction(fn){
      let unlock;
      const next=new Promise(r=>{unlock=r;});
      const previous=gate;gate=next;await previous;
      const draft=new Map(structuredClone([...content]));let writes=0;
      try{
        const result=await fn({
          get:async key=>structuredClone(draft.get(key)),
          put:async(key,value)=>{
            if(++writes===this.failAt)throw Error("storage secret");
            draft.set(key,structuredClone(value));
          },
        });
        content=draft;return result;
      }finally{unlock();}
    },
    get:k=>structuredClone(content.get("bke:pairing:v1:"+k)),
  };
};
async function device(worker_id="worker-a",r=resources()){
  const key=await webcrypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const jwk=await webcrypto.subtle.exportKey("jwk",key.publicKey);
  return {
    worker_id,public_key:{crv:"P-256",kty:"EC",x:jwk.x,y:jwk.y},resources:r,
    display:{chatgpt_target:"Dedicated ChatGPT target",
      browser_profile:"Exclusive browser profile",
      bridge_identity:"Private GeckoView/extension channel"},
    async signChallenge(msg){
      const signature=new Uint8Array(await webcrypto.subtle.sign(
        {name:"ECDSA",hash:"SHA-256"},key.privateKey,new TextEncoder().encode(msg)));
      return Buffer.from(signature).toString("base64url");
    },
  };
}
async function fixture(id="51"){
  const dbs=new Map(),meta={raw:raw(id),receiverRaw:null,blockBroker:false,
    override:null,reads:0,bridgeCalls:0,now:Date.now()};
  const db=x=>{
    if(!dbs.has(x))dbs.set(x,matrix());
    return dbs.get(x);
  };
  let env;
  const ns={
    idFromName:name=>({toString:()=>name}),
    get:objectId=>{
      if(meta.override)return meta.override(objectId);
      const install=objectId.toString().slice("installation:".length);
      return new BkeWorkerPairingVault({id:objectId,storage:db(install)},env);
    },
  };
  env={...FLAGS,BKE_WORKER_PAIRING_VAULT:ns,
    BKE_GITHUB_READ_BROKER:{
      async listVerifiedWorkerAssignments(purpose){
        assert.deepEqual(purpose,{purpose:"admin_worker_assignment_inventory"});
        meta.reads++;
        if(meta.blockBroker)throw Error("private broker credential");
        return structuredClone(meta.receiverRaw??meta.raw);
      },
    },
  };
  let activeDevice=await device();
  const bridge={
    async readCandidate(){meta.bridgeCalls++;return {...activeDevice};},
  };
  const readAssignments=async()=>parseTrustedWorkerAssignmentPayload(structuredClone(meta.raw));
  const sender=(opts={})=>stageDeviceOriginProposal({
    env,executionCtx:ADMIN,deviceBridge:bridge,readAssignments,
    cryptoImpl:webcrypto,clock:()=>meta.now,...opts,
  });
  const loader=(opts={})=>loadPreparedDeviceProposal({
    env,executionCtx:ADMIN,readAssignments,
    cryptoImpl:webcrypto,clock:()=>meta.now,...opts,
  });
  return {id,db,ns,meta,env,bridge,sender,loader,readAssignments,
    setDevice:async(worker,r)=>{activeDevice=await device(worker,r);},
    device:()=>activeDevice};
}

test("fresh P-256 signed device origin stages one private tenant proposal, not pairing or active worker",async()=>{
  const f=await fixture();
  const result=await f.sender();
  assert.equal(result.state,"PREPARED_FOR_HUMAN_REVIEW");
  assert.equal(result.worker_id,"worker-a");
  assert.equal(result.dispatch_authority,"NONE");
  assert.equal(result.pairing_authority,"NONE");
  assert.match(result.proposal_sha256,/^[a-f0-9]{64}$/u);
  assert.equal(f.db("51").get("prepared").length,1);
  assert.equal(f.db("51").get("paired"),undefined);
  assert.equal(f.db("51").get("pending"),undefined);
  assert.equal(f.db("51").get("admin_actions"),undefined);
  const prepared=await f.loader();
  assert.equal(prepared.worker_id,"worker-a");
  assert.deepEqual(prepared.resources,resources());
  assert.equal(prepared.display.chatgpt_target,"Dedicated ChatGPT target");
  assert.ok(!JSON.stringify(prepared).includes("device_signature"));
  assert.equal(f.meta.reads,2);
});

test("existing Admin review consumes only SERVER-owned prepared proposal via injected adapter",async()=>{
  const f=await fixture();
  assert.equal((await f.sender()).state,"PREPARED_FOR_HUMAN_REVIEW");
  const server=createAdminPreparedProposalServer({
    readAssignments:f.readAssignments,cryptoImpl:webcrypto,clock:()=>f.meta.now,
  });
  const html=await handleRequest(new Request("https://cc.jl-bke.com/admin/pairing/review"),
    f.env,()=>({}),ADMIN,server);
  assert.equal(html.status,200);
  const page=await html.text();
  assert.match(page,/worker-a/u);
  assert.match(page,/Dedicated ChatGPT target/u);
  assert.match(page,/Private GeckoView\/extension channel/u);
  assert.doesNotMatch(page,/installation:51|one_time_nonce|BEGIN PRIVATE KEY/u);
  assert.equal(f.db("51").get("consents")[0].status,"PENDING");
  // Protected final pairing is not invoked by staging or mere presentation.
  assert.equal(f.db("51").get("paired"),undefined);
  assert.equal(f.db("51").get("admin_actions"),undefined);
});

test("no bridge and invalid platform human deny BEFORE soliciting device-origin proof",async()=>{
  const f=await fixture();
  blocked(await f.sender({deviceBridge:null}));
  assert.equal(f.meta.bridgeCalls,0);
  for(const ctx of [
    {},{access:{aud:ADMIN.access.aud,async getIdentity(){return {email:"bad@example.test"};}}},
    {access:{aud:"wrong",async getIdentity(){return {email:"admin@example.test"};}}},
  ])blocked(await f.sender({executionCtx:ctx}));
  assert.equal(f.meta.bridgeCalls,0);
  assert.equal(f.db("51").get("prepared"),undefined);
});

test("invalid device signatures, wrong key, bad resources and fabricated approval are denied",async()=>{
  const f=await fixture();
  const valid=f.device();
  for(const tamper of [
    {...valid,async signChallenge(){return "A".repeat(86);}},
    {...valid,async signChallenge(){return "bad";}},
    {...valid,public_key:{...valid.public_key,x:"wrong"}},
    {...valid,resources:{...valid.resources,chatgpt_target_sha256:"bad"}},
    {...valid,authorized:true},
    {...valid,display:{...valid.display,chatgpt_target:""}},
  ]){
    blocked(await f.sender({deviceBridge:{async readCandidate(){return tamper;}}}));
  }
  assert.equal(f.db("51").get("prepared"),undefined);
});

test("two racing preparations allow at most one active proposal per installation",async()=>{
  const f=await fixture();
  const [a,b]=await Promise.all([f.sender(),f.sender()]);
  assert.equal([a,b].filter(x=>x.state==="PREPARED_FOR_HUMAN_REVIEW").length,1);
  assert.equal(f.db("51").get("prepared").length,1);
  blocked(await f.sender());
});

test("wrong installation object fails closed; storage remains isolated",async()=>{
  const f=await fixture();
  f.meta.override=()=>new BkeWorkerPairingVault({
    id:f.ns.idFromName("installation:52"),storage:f.db("52"),
  },f.env);
  blocked(await f.sender());
  assert.equal(f.db("51").get("prepared"),undefined);
  assert.equal(f.db("52").get("prepared"),undefined);
});

test("fresh receiver broker scope and conflicting GitHub worker labels deny preparation",async()=>{
  const f=await fixture();
  f.meta.receiverRaw=raw("52");
  blocked(await f.sender());
  f.meta.receiverRaw=raw("51",[{
    repository:"jan2xo/bke-worker",repository_id:22222,
    number:10,head_sha:"a".repeat(40),state:"open",
    labels:["bke-worker:worker-a"],
  }]);
  blocked(await f.sender());
  assert.equal(f.db("51").get("prepared"),undefined);
  f.meta.receiverRaw=null;f.meta.blockBroker=true;
  blocked(await f.sender());
});

test("conflicting paired resource fingerprint refuses staging even with a valid P-256 proof",async()=>{
  const f=await fixture();
  const row={
    worker_id:"other-worker",status:"PAIRED_INACTIVE",
    identity_public_key_sha256:"a".repeat(64),
    chatgpt_target_sha256:resources().chatgpt_target_sha256,
    browser_profile_sha256:"b".repeat(64),bridge_identity_sha256:"c".repeat(64),
    nonce_sha256:"d".repeat(64),registered_at_ms:f.meta.now-500,
    enrollment_expires_at_ms:f.meta.now+100000,
  };
  await f.db("51").transaction(tx=>tx.put("bke:pairing:v1:paired",[row]));
  blocked(await f.sender());
  assert.equal(f.db("51").get("prepared"),undefined);
});

test("third-party tampering of short-lived signed DO command rejected before state write",async()=>{
  const f=await fixture();
  let command;
  f.meta.override=()=>({async managePreparedDeviceProposal(x){
    command=structuredClone(x);
    return {state:"BLOCKED",code:"PREPARATION_REQUEST_REJECTED"};
  }});
  blocked(await f.sender());
  assert.ok(command);
  const receive=c=>receivePreparedDeviceProposal({
    command:c,env:f.env,objectId:f.ns.idFromName("installation:51"),
    store:createPairingAtomicStore(f.db("51")),cryptoImpl:webcrypto,
    clock:()=>f.meta.now,
  });
  for(const change of [
    {installation_id:"52"},{kind:"read"},{nonce:"b".repeat(64)},
    {subject_sha256:"c".repeat(64)},{signature:"a".repeat(64)},
    {expires_at_ms:1},{purpose:"attacker"}, {extra:1},
    {payload:{...command.payload,offer:{...command.payload.offer,worker_id:"worker-b"}}},
    {payload:{...command.payload,device_signature:"A".repeat(86)}},
  ])blocked(await receive({...command,...change}));
  assert.equal(f.db("51").get("prepared"),undefined);
});

test("replayed authentic signed command cannot stage again, even within 30s",async()=>{
  const f=await fixture();
  let captured;
  const get=f.ns.get.bind(f.ns);
  f.meta.override=obj=>({async managePreparedDeviceProposal(cmd){
    captured=structuredClone(cmd);
    return new BkeWorkerPairingVault({id:obj,storage:f.db("51")},f.env)
      .managePreparedDeviceProposal(cmd);
  }});
  assert.equal((await f.sender()).state,"PREPARED_FOR_HUMAN_REVIEW");
  assert.ok(captured);
  const again=await receivePreparedDeviceProposal({
    command:captured,env:f.env,objectId:f.ns.idFromName("installation:51"),
    store:createPairingAtomicStore(f.db("51")),cryptoImpl:webcrypto,
    clock:()=>f.meta.now,
  });
  blocked(again);
  assert.equal(f.db("51").get("prepared").length,1);
});

test("partial storage failure rolls back prepared proposal, safe retry requires fresh signed proof",async()=>{
  const f=await fixture();
  f.db("51").failAt=1;
  blocked(await f.sender());
  assert.equal(f.db("51").get("prepared"),undefined);
  f.db("51").failAt=0;
  assert.equal((await f.sender()).state,"PREPARED_FOR_HUMAN_REVIEW");
});

test("missing feature latch or HMAC secret leaves proposal ingress inert",async()=>{
  const f=await fixture();
  for(const name of [
    "BKE_ADMIN_DEVICE_PREPARATION_ENABLED",
    "BKE_ADMIN_PAIRING_REVIEW_ENABLED",
    "BKE_ADMIN_PROPOSAL_CONSENT_ENABLED",
  ])blocked(await f.sender({env:{...f.env,[name]:undefined}}));
  blocked(await f.sender({env:{...f.env,BKE_PAIRING_RPC_KEY_B64:undefined}}));
  assert.equal(f.meta.bridgeCalls,0);
});

test("expired proposal cannot be read and no secret is exposed from returned offer",async()=>{
  const f=await fixture();
  assert.equal((await f.sender()).state,"PREPARED_FOR_HUMAN_REVIEW");
  f.meta.now+=90000;
  assert.equal(await f.loader(),null);
  assert.equal(f.db("51").get("prepared").length,1);
});

test("independent installations retain isolated signed prepared proposals",async()=>{
  const [a,b]=await Promise.all([fixture("51"),fixture("52")]);
  assert.equal((await a.sender()).state,"PREPARED_FOR_HUMAN_REVIEW");
  assert.equal((await b.sender()).state,"PREPARED_FOR_HUMAN_REVIEW");
  assert.equal(a.db("52").get("prepared"),undefined);
  assert.equal(b.db("51").get("prepared"),undefined);
});

test("runtime remains locked with no device ingress HTTP endpoint or configured flag",()=>{
  const index=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
  const config=readFileSync(new URL("../wrangler.toml",import.meta.url),"utf8");
  const entry=readFileSync(new URL("../src/cloudflare-worker-entry.js",import.meta.url),"utf8");
  assert.doesNotMatch(index,/stageDeviceOriginProposal|\/api\/admin\/device-proposal/u);
  assert.doesNotMatch(config,/BKE_ADMIN_DEVICE_PREPARATION_ENABLED/u);
  assert.match(entry,/async managePreparedDeviceProposal\(command\)/u);
});
