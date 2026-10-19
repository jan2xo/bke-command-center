import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { stageDeviceFromPrivateTransport } from "../src/admin-private-device-admission.js";
import { BkeWorkerPairingVault } from "../src/worker-pairing-durable-store.js";
import { parseTrustedWorkerAssignmentPayload } from "../src/admin-worker-assignments.js";

const CLOCK=1_786_000_000_000;
const HEX=n=>n.repeat(64);
const KEY=Buffer.alloc(32,59).toString("base64url");
const ACCESS={access:{aud:"0123456789abcdef0123456789abcdef",
  async getIdentity(){return {email:"admin@example.test"};}}};
const FLAGS={
  BKE_PREPRODUCTION:"true",BKE_ACCESS_POLICY_VERIFIED:"true",
  BKE_ADMIN_DISCOVERY_ENABLED:"true",
  BKE_ADMIN_ACCESS_ISSUER:"https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD:ACCESS.access.aud,BKE_ADMIN_EMAILS:"admin@example.test",
  BKE_ADMIN_PR_INVENTORY_ENABLED:"true",BKE_ADMIN_PAIRING_ACTIONS_ENABLED:"true",
  BKE_ADMIN_PAIRING_REVIEW_ENABLED:"true",BKE_ADMIN_PROPOSAL_CONSENT_ENABLED:"true",
  BKE_ADMIN_DEVICE_PREPARATION_ENABLED:"true",
  BKE_NATIVE_DEVICE_ADMISSION_ENABLED:"true",
  BKE_PAIRING_RPC_KEY_B64:KEY,
};
const inventory=id=>({
  principal:"github_app_installation",authority:"EXISTING_GITHUB_APP_INSTALLATION",
  repository_scope:"INSTALLATION_APPROVED_ONLY",consistency:"NON_ATOMIC_ENUMERATION",
  installation_id:id,total_visible_repositories:2,
  enumerated_open_pull_requests:0,worker_assignments:[],
});
function fakeStorage(){
  let data=new Map(),queue=Promise.resolve();
  const s={
    fail:false,
    async transaction(fn){
      let release;const next=new Promise(resolve=>release=resolve);
      const prev=queue;queue=next;await prev;
      const draft=new Map(structuredClone([...data]));
      try{
        const out=await fn({
          get:async k=>structuredClone(draft.get(k)),
          put:async(k,v)=>{
            if(s.fail)throw Error("private-provider-storage-failed");
            draft.set(k,structuredClone(v));
          },
        });
        data=draft;return out;
      }finally{release();}
    },
    get:k=>structuredClone(data.get("bke:pairing:v1:"+k)),
  };
  return s;
}
async function device(){
  const keys=await webcrypto.subtle.generateKey({
    name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const public_key=await webcrypto.subtle.exportKey("jwk",keys.publicKey);
  const raw={crv:"P-256",kty:"EC",x:public_key.x,y:public_key.y};
  const resources={
    chatgpt_target_sha256:HEX("1"),
    browser_profile_sha256:HEX("2"),
    bridge_identity_sha256:HEX("3"),
  };
  const digest=await webcrypto.subtle.digest("SHA-256",
    new TextEncoder().encode(JSON.stringify(raw)));
  const keyhash=Buffer.from(digest).toString("hex");
  return {
    raw,resources,keyhash,
    async sign(message){
      const bytes=await webcrypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},
        keys.privateKey,new TextEncoder().encode(message));
      return Buffer.from(bytes).toString("base64url");
    },
  };
}
async function fixture(installation="51"){
  const key=await device(),stores=new Map();
  const events={peerChecks:0,readCalls:0,proofCalls:0,brokerCalls:0,
    labelCalls:0,now:CLOCK,change:false,badProof:false,failBroker:false,
    peerDisabled:false,replaceOffer:null,receiverCode:null};
  const store=id=>{
    if(!stores.has(id))stores.set(id,fakeStorage());
    return stores.get(id);
  };
  let env;
  const ns={
    idFromName:name=>({toString:()=>name}),
    get:obj=>{
      const id=obj.toString().slice("installation:".length);
      const vault=new BkeWorkerPairingVault({id:obj,storage:store(id)},env);
      return {async managePreparedDeviceProposal(command){
        const result=await vault.managePreparedDeviceProposal(command);
        events.receiverCode=result?.state==="BLOCKED"?result.code:null;
        return result;
      }};
    },
  };
  env={...FLAGS,BKE_WORKER_PAIRING_VAULT:ns,
    BKE_GITHUB_READ_BROKER:{
      async listVerifiedWorkerAssignments(purpose){
        assert.deepEqual(purpose,{purpose:"admin_worker_assignment_inventory"});
        events.brokerCalls++;
        if(events.failBroker)throw Error("private GitHub token");
        return inventory(installation);
      },
    },
  };
  let attestation={
    audience:"bke-command-center/preproduction/native-device-admission/v1",
    source:"DESKTOP_EXTENSION_NATIVE",
    worker_id:"worker-a",session_binding_sha256:HEX("4"),
    identity_public_key_sha256:key.keyhash,
    chatgpt_target_sha256:key.resources.chatgpt_target_sha256,
    browser_profile_sha256:key.resources.browser_profile_sha256,
    bridge_identity_sha256:key.resources.bridge_identity_sha256,
    expires_at_ms:CLOCK+30000,
  };
  const link={
    async readCandidate(){
      events.readCalls++;
      return events.replaceOffer??{
        worker_id:"worker-a",public_key:key.raw,
        resources:key.resources,
      };
    },
    async exchangeProof(message){
      events.proofCalls++;
      if(events.badProof)return "A".repeat(86);
      return key.sign(message);
    },
  };
  const authorizePeer=async()=>{
    events.peerChecks++;
    if(events.peerDisabled)throw Error("native host authorization unavailable");
    return events.change?{...attestation,session_binding_sha256:HEX("5")}:structuredClone(attestation);
  };
  const describeResources=async()=>{
    events.labelCalls++;
    return {
      chatgpt_target:"Owner approved isolated ChatGPT target",
      browser_profile:"Owner approved exclusive browser profile",
      bridge_identity:"Authenticated device bridge proof",
    };
  };
  const readAssignments=async()=>parseTrustedWorkerAssignmentPayload(inventory(installation));
  const stage=(override={})=>stageDeviceFromPrivateTransport({
    env,executionCtx:ACCESS,link,authorizePeer,
    describeResources,readAssignments,cryptoImpl:webcrypto,
    clock:()=>events.now,...override,
  });
  return {key,events,ns,store,env,link,authorizePeer,describeResources,
    readAssignments,stage,
    setAttestation:v=>{attestation=v;},
  };
}
const blocked=x=>{
  assert.equal(x.state,"BLOCKED");
  assert.deepEqual(Object.keys(x).sort(),["code","state"]);
  assert.doesNotMatch(JSON.stringify(x),/Bearer|ghs_|private GitHub token|admin@example.test/u);
};

test("trusted session + real P-256 challenge stages ONLY a prepared offer",async()=>{
  const f=await fixture();
  const result=await f.stage();
  assert.equal(result.state,"PREPARED_FOR_HUMAN_REVIEW",JSON.stringify({result,receiverCode:f.events.receiverCode}));
  assert.equal(result.worker_id,"worker-a");
  assert.equal(result.pairing_authority,"NONE");
  assert.equal(result.dispatch_authority,"NONE");
  assert.equal(f.events.readCalls,1);
  assert.equal(f.events.proofCalls,1);
  assert.ok(f.events.peerChecks>=4);
  assert.equal(f.events.brokerCalls,1);
  assert.equal(f.store("51").get("prepared").length,1);
  assert.equal(f.store("51").get("pending"),undefined);
  assert.equal(f.store("51").get("paired"),undefined);
  assert.equal(f.store("51").get("admin_actions"),undefined);
  const row=f.store("51").get("prepared")[0];
  assert.equal(row.worker_id,"worker-a");
  assert.equal(row.identity_public_key_sha256,f.key.keyhash);
  assert.equal(row.display.chatgpt_target,"Owner approved isolated ChatGPT target");
  assert.ok(!JSON.stringify(result).includes("installation_id"));
});

test("missing feature gate or missing trusted callbacks deny before inspecting device",async()=>{
  const f=await fixture();
  for(const name of ["BKE_NATIVE_DEVICE_ADMISSION_ENABLED","BKE_ADMIN_DEVICE_PREPARATION_ENABLED"]){
    blocked(await f.stage({env:{...f.env,[name]:undefined}}));
  }
  blocked(await f.stage({link:null}));
  blocked(await f.stage({authorizePeer:undefined}));
  blocked(await f.stage({describeResources:null}));
  assert.equal(f.events.readCalls,0);
  assert.equal(f.events.proofCalls,0);
});
test("denied or forged Admin Access never reaches transport peer",async()=>{
  const f=await fixture();
  for(const context of [
    {},{access:{aud:ACCESS.access.aud,
      async getIdentity(){return {email:"attacker@example.test"};}}},
    {access:{aud:"wrong",async getIdentity(){return {email:"admin@example.test"};}}},
  ])blocked(await f.stage({executionCtx:context}));
  assert.equal(f.events.peerChecks,0);
  assert.equal(f.events.readCalls,0);
});
test("attestation is exact, fresh, supported and worker-bound; browser JSON cannot assert trust",async()=>{
  const f=await fixture();
  const original=(await f.authorizePeer());
  for(const invalid of [
    {...original,source:"CHATGPT_CONTENT_SCRIPT"},
    {...original,worker_id:"worker-b"},
    {...original,identity_public_key_sha256:HEX("a")},
    {...original,browser_profile_sha256:HEX("a")},
    {...original,bridge_identity_sha256:HEX("a")},
    {...original,chatgpt_target_sha256:HEX("a")},
    {...original,session_binding_sha256:"z"},
    {...original,expires_at_ms:CLOCK},
    {...original,expires_at_ms:CLOCK+30001},
    {...original,audience:"other"},
    {...original,trusted:true},
  ]){
    f.setAttestation(invalid);
    blocked(await f.stage());
  }
  assert.equal(f.store("51").get("prepared"),undefined);
});
test("invalid client offer and proof fail without storing anything",async()=>{
  const f=await fixture();
  const raw={worker_id:"worker-a",public_key:f.key.raw,resources:f.key.resources};
  for(const invalid of [
    {...raw,worker_id:"worker-b"},
    {...raw,resources:{...raw.resources,browser_profile_sha256:HEX("f")}},
    {...raw,public_key:{...raw.public_key,x:"bad"}},
    {...raw,trusted:true},
    {...raw,device_signature:"A".repeat(86)},
  ]){
    f.events.replaceOffer=invalid;
    blocked(await f.stage());
  }
  f.events.replaceOffer=null;
  f.events.badProof=true;
  blocked(await f.stage());
  assert.equal(f.store("51").get("prepared"),undefined);
});
test("changed peer binding during challenge exchange rejects and cannot stage",async()=>{
  const f=await fixture();
  f.link.exchangeProof=async message=>{
    f.events.proofCalls++;
    f.events.change=true;
    return f.key.sign(message);
  };
  blocked(await f.stage());
  assert.equal(f.store("51").get("prepared"),undefined);
});
test("attestor outage mid-handshake rejects despite valid device P-256 proof",async()=>{
  const f=await fixture();
  f.link.exchangeProof=async msg=>{
    f.events.peerDisabled=true;
    return f.key.sign(msg);
  };
  blocked(await f.stage());
  assert.equal(f.store("51").get("prepared"),undefined);
});
test("concurrent same identity stage attempts allow precisely one prepared row",async()=>{
  const f=await fixture();
  const [a,b]=await Promise.all([f.stage(),f.stage()]);
  assert.equal([a,b].filter(x=>x.state==="PREPARED_FOR_HUMAN_REVIEW").length,1);
  assert.equal(f.store("51").get("prepared").length,1);
  blocked(await f.stage());
});
test("real receiver GitHub provider outage fails closed after device proof",async()=>{
  const f=await fixture();
  f.events.failBroker=true;
  blocked(await f.stage());
  assert.equal(f.store("51").get("prepared"),undefined);
});
test("atomic storage write failure prevents prepared authorization",async()=>{
  const f=await fixture();
  f.store("51").fail=true;
  blocked(await f.stage());
  assert.equal(f.store("51").get("prepared"),undefined);
});
test("expired session cannot send or stage a proposal",async()=>{
  const f=await fixture();
  f.events.now=CLOCK+30000;
  blocked(await f.stage());
  assert.equal(f.events.readCalls,0);
});
test("source remains default-off with no enrollment HTTP, WebSocket or shared relay token",()=>{
  const runtime=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
  const entry=readFileSync(new URL("../src/cloudflare-worker-entry.js",import.meta.url),"utf8");
  const config=readFileSync(new URL("../wrangler.toml",import.meta.url),"utf8");
  assert.doesNotMatch(runtime,/stageDeviceFromPrivateTransport/u);
  assert.doesNotMatch(entry,/stageDeviceFromPrivateTransport/u);
  assert.doesNotMatch(config,/BKE_NATIVE_DEVICE_ADMISSION_ENABLED/u);
  assert.doesNotMatch(config,/BKE_DEVICE_ADMISSION_SECRET/u);
  assert.doesNotMatch(runtime,/\/api\/admin\/native-device-admission/u);
});
