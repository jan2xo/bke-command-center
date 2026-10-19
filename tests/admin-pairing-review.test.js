import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { handleRequest } from "../src/index.js";
import { sendAdminPairingConsent, receiveAdminPairingConsent } from "../src/admin-pairing-review-rpc.js";
import { createPairingAtomicStore, BkeWorkerPairingVault } from "../src/worker-pairing-durable-store.js";
import { parseTrustedWorkerAssignmentPayload } from "../src/admin-worker-assignments.js";

const KEY_BYTES=Buffer.alloc(32,71);
const KEY=KEY_BYTES.toString("base64url");
const CONTEXT={access:{aud:"0123456789abcdef0123456789abcdef",
  async getIdentity(){return {email:"admin@example.test"};}}};
const flags={
  BKE_PREPRODUCTION:"true",BKE_ACCESS_POLICY_VERIFIED:"true",
  BKE_ADMIN_DISCOVERY_ENABLED:"true",
  BKE_ADMIN_ACCESS_ISSUER:"https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD:CONTEXT.access.aud,BKE_ADMIN_EMAILS:"admin@example.test",
  BKE_ADMIN_PR_INVENTORY_ENABLED:"true",BKE_ADMIN_PAIRING_ACTIONS_ENABLED:"true",
  BKE_ADMIN_PROPOSAL_CONSENT_ENABLED:"true",
  BKE_ADMIN_PAIRING_REVIEW_ENABLED:"true",
  BKE_PAIRING_RPC_KEY_B64:KEY,
};
const raw=(id="51",assignments=[])=>({
  authority:"EXISTING_GITHUB_APP_INSTALLATION",principal:"github_app_installation",
  repository_scope:"INSTALLATION_APPROVED_ONLY",
  consistency:"NON_ATOMIC_ENUMERATION",installation_id:id,
  total_visible_repositories:2,enumerated_open_pull_requests:assignments.length,
  worker_assignments:assignments,
});
function database(){
  let state=new Map(),chain=Promise.resolve();
  return {
    failAt:0,
    async transaction(fn){
      let release;
      const next=new Promise(resolve=>release=resolve);
      const previous=chain;chain=next;await previous;
      const copy=new Map(structuredClone([...state]));let writes=0;
      try{
        const out=await fn({
          get:async key=>structuredClone(copy.get(key)),
          put:async(key,value)=>{
            if(++writes===this.failAt)throw Error("private storage error");
            copy.set(key,structuredClone(value));
          },
        });
        state=copy;return out;
      }finally{release();}
    },
    rows:k=>structuredClone(state.get("bke:pairing:v1:"+k)),
  };
}
function proposal(key){
  return {
    worker_id:"worker-a",
    public_key:key,
    resources:{
      chatgpt_target_sha256:"1".repeat(64),
      browser_profile_sha256:"2".repeat(64),
      bridge_identity_sha256:"3".repeat(64),
    },
    display:{
      chatgpt_target:"Personal worker ChatGPT · exclusive",
      browser_profile:"Dedicated human-authenticated browser profile",
      bridge_identity:"Dedicated extension/native messaging bridge",
    },
  };
}
async function keypair(){
  const key=await webcrypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,
    ["sign","verify"]);
  const publicKey=await webcrypto.subtle.exportKey("jwk",key.publicKey);
  return {kty:"EC",crv:"P-256",x:publicKey.x,y:publicKey.y};
}
function request(data,overrides={}){
  return new Request(overrides.url??"https://cc.jl-bke.com/api/admin/pairing/confirm-proposal",{
    method:overrides.method??"POST",
    headers:{
      origin:"https://cc.jl-bke.com","sec-fetch-site":"same-origin",
      "sec-fetch-mode":"cors","content-type":"application/json",
      "x-bke-admin-action":"pair",...overrides.headers,
    },
    body:JSON.stringify(data),
  });
}
const denial=r=>assert.equal(r.state,"BLOCKED");
async function fixture(id="51"){
  const stores=new Map(),meta={raw:raw(id),receiverRaw:null,failBroker:false,
    override:null,reads:0};
  const db=x=>{
    if(!stores.has(x))stores.set(x,database());
    return stores.get(x);
  };
  let env;
  const ns={
    idFromName:name=>({toString:()=>"DO:"+name}),
    get:which=>{
      if(meta.override)return meta.override(which);
      const name=which.toString().slice("DO:installation:".length);
      return new BkeWorkerPairingVault({id:which,storage:db(name)},env);
    },
  };
  env={...flags,BKE_WORKER_PAIRING_VAULT:ns,BKE_GITHUB_READ_BROKER:{
    async listVerifiedWorkerAssignments(purpose){
      assert.deepEqual(purpose,{purpose:"admin_worker_assignment_inventory"});
      meta.reads++;
      if(meta.failBroker)throw Error("private provider secret");
      return structuredClone(meta.receiverRaw??meta.raw);
    },
  }};
  const prepared=proposal(await keypair());
  const server={
    async loadPreparedProposal(){return structuredClone(prepared);},
    rpcOverrides:{
      cryptoImpl:webcrypto,
      readAssignments:async()=>parseTrustedWorkerAssignmentPayload(
        structuredClone(meta.raw)),
    },
  };
  const handle=(req,options={})=>handleRequest(req,options.env??env,()=>({}),
    options.ctx??CONTEXT,options.server===undefined?server:options.server);
  const show=()=>handle(new Request("https://cc.jl-bke.com/admin/pairing/review"));
  const pending=()=>db(id).rows("consents")?.[0];
  const data=(changes={})=>{
    const a=pending();
    return {action:"pair",challenge_id:a.challenge_id,
      confirm_worker_id:a.worker_id,proposal_sha256:a.proposal_sha256,
      worker_id:a.worker_id,...changes};
  };
  const confirm=(changes={},overrides={},ctx=CONTEXT)=>
    handle(request(data(changes),overrides),{ctx});
  return {id,db,meta,ns,env,prepared,server,handle,show,pending,confirm,data};
}

test("human GET presents real server-selected worker,key,resources and POST confirms one DO record",async()=>{
  const f=await fixture();
  const page=await f.show();
  assert.equal(page.status,200);
  const html=await page.text();
  assert.match(html,/Review one worker pairing proposal/u);
  assert.match(html,/worker-a/u);
  assert.match(html,/P-256 public key SHA-256/u);
  assert.match(html,/Dedicated human-authenticated browser profile/u);
  assert.match(html,/1{64}/u);
  assert.match(html,/2{64}/u);
  assert.match(html,/3{64}/u);
  assert.match(html,/NOT yet proved possession/u);
  assert.match(html,/Confirm exact proposal/u);
  assert.equal(page.headers.get("cache-control"),"no-store");
  assert.match(page.headers.get("content-security-policy"),/script-src 'nonce-[A-Za-z0-9_-]+'/u);
  assert.doesNotMatch(html,/admin@example.test|installation:51|one_time_nonce/u);
  assert.equal(f.pending().status,"PENDING");
  const response=await f.confirm();
  assert.equal(response.status,200);
  const outcome=await response.json();
  assert.equal(outcome.state,"CONFIRMED_FOR_ATOMIC_ISSUANCE");
  assert.equal(outcome.pairing_authority,"NONE");
  assert.equal(outcome.dispatch_authority,"NONE");
  assert.equal(f.pending().status,"CONFIRMED");
  assert.equal(f.db("51").rows("pending"),undefined);
  assert.equal(f.db("51").rows("paired"),undefined);
  assert.equal(f.meta.reads,2);
});

test("confirmation POST replays and races allow precisely one human approval",async()=>{
  const f=await fixture();await f.show();
  const [a,b]=await Promise.all([f.confirm(),f.confirm()]);
  assert.equal([a.status,b.status].filter(s=>s===200).length,1);
  assert.equal(f.pending().status,"CONFIRMED");
  const replay=await f.confirm();
  assert.equal(replay.status,403);
});

test("no server-only prepared-proposal adapter or feature OFF leaves HTTP inert",async()=>{
  const f=await fixture();
  assert.equal((await f.handle(new Request("https://cc.jl-bke.com/admin/pairing/review"),
    {server:null})).status,404);
  assert.equal((await f.handle(new Request("https://cc.jl-bke.com/admin/pairing/review"),
    {env:{...f.env,BKE_ADMIN_PAIRING_REVIEW_ENABLED:undefined}})).status,404);
  assert.equal((await f.handle(new Request("https://cc.jl-bke.com/admin/pairing/review?evil=1"))).status,400);
  assert.equal(f.pending(),undefined);
  const config=readFileSync(new URL("../wrangler.toml",import.meta.url),"utf8");
  assert.doesNotMatch(config,/BKE_ADMIN_PAIRING_REVIEW_ENABLED/u);
  const entry=readFileSync(new URL("../src/cloudflare-worker-entry.js",import.meta.url),"utf8");
  assert.match(entry,/async reviewPairingConsent\(command\)/u);
});

test("human-readable descriptions escaped instead of injecting script/HTML",async()=>{
  const f=await fixture();
  f.prepared.display.chatgpt_target="<img src=x onerror=alert(1)>";
  f.prepared.display.browser_profile="</script><script>alert(2)</script>";
  const page=await f.show();
  assert.equal(page.status,200);
  const html=await page.text();
  assert.match(html,/&lt;img src=x onerror=alert\(1\)&gt;/u);
  assert.match(html,/&lt;\/script&gt;&lt;script&gt;/u);
  assert.doesNotMatch(html,/<img src=x onerror=alert/u);
});

test("wrong Access context or caller headers cannot impersonate human",async()=>{
  const f=await fixture();
  for(const ctx of [
    {},{access:{aud:CONTEXT.access.aud,async getIdentity(){return {email:"evil@example.test"};}}},
    {access:{aud:"forged",async getIdentity(){return {email:"admin@example.test"};}}},
  ]){
    assert.equal((await f.handle(new Request("https://cc.jl-bke.com/admin/pairing/review"),
      {ctx})).status,403);
  }
  assert.equal(f.pending(),undefined);
});

test("wrong method, origin, Fetch Metadata, content type and extra fields deny confirmation",async()=>{
  const f=await fixture();await f.show();
  for(const opts of [
    {url:"https://attacker.invalid/api/admin/pairing/confirm-proposal"},
    {url:"https://cc.jl-bke.com/api/admin/pairing/confirm-proposal?query=1"},
    {headers:{origin:"https://evil.test"}},
    {headers:{"sec-fetch-site":"cross-site"}},
    {headers:{"sec-fetch-mode":"navigate"}},
    {headers:{"content-type":"text/plain"}},
    {headers:{"x-bke-admin-action":"revoke"}},
  ])assert.notEqual((await f.confirm({},opts)).status,200);
  assert.equal((await f.confirm({approved:true})).status,403);
  assert.equal((await f.confirm({worker_id:"worker-b",confirm_worker_id:"worker-b"})).status,403);
  assert.equal((await f.confirm({proposal_sha256:"e".repeat(64)})).status,403);
  assert.equal((await f.confirm({confirm_worker_id:"worker-b"})).status,403);
  assert.equal(f.pending().status,"PENDING");
});

test("changed human cannot confirm prior human's PENDING record",async()=>{
  const f=await fixture();await f.show();
  const alt={access:{aud:CONTEXT.access.aud,
    async getIdentity(){return {email:"second@example.test"};}}};
  f.env.BKE_ADMIN_EMAILS="admin@example.test,second@example.test";
  assert.equal((await f.confirm({}, {},alt)).status,403);
  assert.equal(f.pending().status,"PENDING");
});

test("provider broker outage and installation mismatch fail closed",async()=>{
  const f=await fixture();
  f.meta.failBroker=true;
  assert.notEqual((await f.show()).status,200);
  assert.equal(f.pending(),undefined);
  f.meta.failBroker=false;
  f.meta.receiverRaw=raw("52");
  assert.notEqual((await f.show()).status,200);
  assert.equal(f.pending(),undefined);
});

test("wrong DO object and existing GitHub worker assignment deny presentation",async()=>{
  const f=await fixture();
  f.meta.override=()=>new BkeWorkerPairingVault({
    id:f.ns.idFromName("installation:52"),storage:f.db("52"),
  },f.env);
  assert.notEqual((await f.show()).status,200);
  assert.equal(f.db("51").rows("consents"),undefined);
  f.meta.override=null;
  f.meta.receiverRaw=raw("51",[{
    repository:"jan2xo/bke-worker",repository_id:12345,number:90,state:"open",
    head_sha:"a".repeat(40),labels:["bke-worker:worker-a"],
  }]);
  assert.notEqual((await f.show()).status,200);
  assert.equal(f.db("51").rows("consents"),undefined);
});

test("failed durable write rolls back present and confirm",async()=>{
  const f=await fixture();
  f.db("51").failAt=1;
  assert.notEqual((await f.show()).status,200);
  assert.equal(f.db("51").rows("consents"),undefined);
  f.db("51").failAt=0;
  assert.equal((await f.show()).status,200);
  f.db("51").failAt=1;
  assert.equal((await f.confirm()).status,403);
  assert.equal(f.pending().status,"PENDING");
  f.db("51").failAt=0;
  assert.equal((await f.confirm()).status,200);
  assert.equal(f.pending().status,"CONFIRMED");
});

test("wrong tenant and tampered signed command rejected by receiving object",async()=>{
  const f=await fixture();
  let intercepted;
  f.meta.override=()=>({
    async reviewPairingConsent(command){
      intercepted=structuredClone(command);
      return {state:"BLOCKED",code:"REVIEW_RPC_REQUEST_REJECTED"};
    },
  });
  const response=await f.show();
  assert.notEqual(response.status,200);
  assert.ok(intercepted);
  const receive=command=>receiveAdminPairingConsent({
    command,env:f.env,objectId:f.ns.idFromName("installation:51"),
    store:createPairingAtomicStore(f.db("51")),cryptoImpl:webcrypto,
  });
  for(const change of [
    {installation_id:"52"},{nonce:"b".repeat(64)},{signature:"c".repeat(64)},
    {subject_sha256:"d".repeat(64)},{kind:"confirm"},{purpose:"evil"},
    {expires_at_ms:1},
    {payload:{...intercepted.payload,worker_id:"worker-b"}},
    {extra:true},
  ])denial(await receive({...intercepted,...change}));
  assert.equal(f.db("51").rows("consents"),undefined);
});

test("request payload and response exclude raw subject / installation / private ticket",async()=>{
  const f=await fixture();await f.show();
  const receipt=await f.confirm();
  const reply=await receipt.json();
  assert.equal(reply.state,"CONFIRMED_FOR_ATOMIC_ISSUANCE");
  const serialized=JSON.stringify(reply);
  assert.doesNotMatch(serialized,/subject_sha256|installation_id|one_time_nonce|admin@example.test|signature/u);
  assert.equal(f.db("51").rows("admin_actions"),undefined);
});

test("signed presentation replay cannot create another challenge while consumed tombstone is live",async()=>{
  const f=await fixture();
  let original;
  f.meta.override=obj=>({
    async reviewPairingConsent(command){
      original=structuredClone(command);
      return new BkeWorkerPairingVault({id:obj,storage:f.db("51")},f.env)
        .reviewPairingConsent(command);
    },
  });
  assert.equal((await f.show()).status,200);
  assert.ok(original);
  await f.db("51").transaction(async tx=>{
    const path="bke:pairing:v1:consents";
    const rows=await tx.get(path);
    await tx.put(path,rows.map(x=>({...x,status:"CONSUMED"})));
  });
  const again=await receiveAdminPairingConsent({
    command:original,env:f.env,objectId:f.ns.idFromName("installation:51"),
    store:createPairingAtomicStore(f.db("51")),cryptoImpl:webcrypto,
  });
  denial(again);
  assert.equal(f.db("51").rows("consents").length,1);
  assert.equal(f.db("51").rows("consents")[0].status,"CONSUMED");
});

test("server adapter override cannot replace platform Access or chosen operation",async()=>{
  const f=await fixture();
  f.server.rpcOverrides={
    ...f.server.rpcOverrides,
    kind:"confirm",env:{...f.env,BKE_PREPRODUCTION:undefined},
    executionCtx:{},offer:{worker_id:"attacker"},
  };
  assert.equal((await f.show()).status,200);
  assert.equal((await f.confirm()).status,200);
});
test("expired confirmation challenge denies without changing its consent state",async()=>{
  const f=await fixture();await f.show();
  await f.db("51").transaction(async tx=>{
    const path="bke:pairing:v1:consents";
    const rows=await tx.get(path);
    await tx.put(path,rows.map(x=>({...x,expires_at_ms:Date.now()-1})));
  });
  assert.equal((await f.confirm()).status,403);
  assert.equal(f.pending().status,"PENDING");
});
