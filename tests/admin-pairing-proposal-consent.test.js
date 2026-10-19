import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { createAdminProposalConsent } from "../src/admin-pairing-proposal-consent.js";
import { createPairingAtomicStore } from "../src/worker-pairing-durable-store.js";

const HUMAN="a".repeat(64);
const PROPOSAL="c".repeat(64);
const ADMIN={ access: {
  aud:"0123456789abcdef0123456789abcdef",
  async getIdentity(){return {email:"admin@example.test"};},
}};
const FLAGS={
  BKE_PREPRODUCTION:"true",BKE_ACCESS_POLICY_VERIFIED:"true",
  BKE_ADMIN_PAIRING_ACTIONS_ENABLED:"true",
  BKE_ADMIN_PROPOSAL_CONSENT_ENABLED:"true",
  BKE_ADMIN_DISCOVERY_ENABLED:"true",
  BKE_ADMIN_ACCESS_ISSUER:"https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD:ADMIN.access.aud,
  BKE_ADMIN_EMAILS:"admin@example.test",
};
function backend(){
  let state=new Map(),gate=Promise.resolve();
  return {
    failAt:0,
    async transaction(fn){
      let done;
      const next=new Promise(resolve=>{done=resolve;});
      const prior=gate;gate=next;await prior;
      const draft=new Map(structuredClone([...state]));
      let writes=0;
      try{
        const result=await fn({
          get:async key=>structuredClone(draft.get(key)),
          put:async(key,value)=>{
            if(++writes===this.failAt)throw Error("private store credential");
            draft.set(key,structuredClone(value));
          },
        });
        state=draft;return result;
      }finally{done();}
    },
    rows:key=>structuredClone(state.get("bke:pairing:v1:"+key)),
  };
}
function setup(options={}){
  const database=backend(),store=createPairingAtomicStore(database);
  let now=100_000,allowed=true;
  const api=createAdminProposalConsent({
    store,clock:()=>now,
    authorizeSubject:async(action,worker,proposal,ctx)=>{
      if(!allowed || ctx!==ADMIN || action!=="pair" ||
         !/^[a-z0-9-]+$/.test(worker) || proposal!==PROPOSAL)
         return null;
      return HUMAN;
    },
    cryptoImpl:options.cryptoImpl??webcrypto,
  });
  return {database,store,api,setTime:n=>{now=n;},denyHuman:()=>{allowed=false;}};
}
function request(challenge, overrides={}, bodyOverride=null){
  const body=bodyOverride??{
    action:"pair",challenge_id:challenge.challenge_id,
    worker_id:challenge.worker_id,confirm_worker_id:challenge.worker_id,
    proposal_sha256:challenge.proposal_sha256,
  };
  return new Request(overrides.url??"https://cc.jl-bke.com/api/admin/pairing/confirm-proposal",{
    method:overrides.method??"POST",
    headers:{
      origin:"https://cc.jl-bke.com",
      "sec-fetch-site":"same-origin",
      "sec-fetch-mode":"cors",
      "content-type":"application/json",
      "x-bke-admin-action":"pair",
      ...overrides.headers,
    },
    body:JSON.stringify(body),
  });
}
const args=(worker_id="worker-a")=>({
  worker_id,proposal_sha256:PROPOSAL,env:FLAGS,executionCtx:ADMIN,
});
const blocked=(r,code)=>{
  assert.deepEqual(r,{state:"BLOCKED",code});
  assert.doesNotMatch(JSON.stringify(r),/ghs_|private|admin@example|Bearer|hmac|nonce/u);
};
async function approved(f,worker_id="worker-a"){
  const presented=await f.api.present(args(worker_id));
  assert.equal(presented.state,"AWAITING_EXPLICIT_HUMAN_CONFIRMATION");
  const confirmed=await f.api.confirm({
    request:request(presented),env:FLAGS,executionCtx:ADMIN,
  });
  assert.equal(confirmed.state,"CONFIRMED_FOR_ATOMIC_ISSUANCE");
  return presented;
}
const consume=(f,challenge,extra={})=>f.store.atomic(tx=>
  f.api.consumeInTransaction(tx,{
    challenge_id:challenge.challenge_id,worker_id:challenge.worker_id,
    proposal_sha256:challenge.proposal_sha256,
    subject_sha256:HUMAN,...extra,
  }));

test("human challenge confirms exact proposal; one transactional consumption",async()=>{
  const f=setup();
  const challenge=await f.api.present(args());
  assert.equal(challenge.pairing_authority,"NONE");
  assert.equal(challenge.dispatch_authority,"NONE");
  assert.equal(challenge.expires_at_ms,160_000);
  assert.match(challenge.challenge_id,/^[a-f0-9]{64}$/u);
  assert.equal(f.database.rows("consents").length,1);
  assert.equal(f.database.rows("consents")[0].subject_sha256,HUMAN);
  const confirmed=await f.api.confirm({
    request:request(challenge),env:FLAGS,executionCtx:ADMIN,
  });
  assert.equal(confirmed.state,"CONFIRMED_FOR_ATOMIC_ISSUANCE");
  assert.equal(confirmed.pairing_authority,"NONE");
  assert.equal(confirmed.dispatch_authority,"NONE");
  assert.equal(f.database.rows("consents")[0].status,"CONFIRMED");
  assert.deepEqual(await consume(f,challenge),{state:"CONSENT_CONSUMED_IN_TRANSACTION"});
  assert.equal(f.database.rows("consents")[0].status,"CONSUMED");
  blocked(await consume(f,challenge),"CONSENT_MISSING_OR_USED");
});

test("replayed confirmation cannot reaffirm human approval",async()=>{
  const f=setup(),c=await f.api.present(args());
  assert.equal((await f.api.confirm({
    request:request(c),env:FLAGS,executionCtx:ADMIN,
  })).state,"CONFIRMED_FOR_ATOMIC_ISSUANCE");
  blocked(await f.api.confirm({
    request:request(c),env:FLAGS,executionCtx:ADMIN,
  }),"CONSENT_MISSING_OR_USED");
});

test("two concurrent human confirmations result in one accepted action",async()=>{
  const f=setup(),c=await f.api.present(args());
  const [a,b]=await Promise.all([0,1].map(()=>f.api.confirm({
    request:request(c),env:FLAGS,executionCtx:ADMIN,
  })));
  assert.equal([a,b].filter(x=>x.state==="CONFIRMED_FOR_ATOMIC_ISSUANCE").length,1);
  assert.equal(f.database.rows("consents")[0].status,"CONFIRMED");
});

test("two simultaneous proposals for same worker do not overwrite each other",async()=>{
  const f=setup();
  const [a,b]=await Promise.all([f.api.present(args()),f.api.present(args())]);
  assert.equal([a,b].filter(x=>x.state==="AWAITING_EXPLICIT_HUMAN_CONFIRMATION").length,1);
  assert.equal(f.database.rows("consents").length,1);
});

test("independent workers have unique, isolated consent challenges",async()=>{
  const f=setup();
  const [a,b]=await Promise.all([
    f.api.present(args("worker-a")),f.api.present(args("worker-b")),
  ]);
  assert.equal(a.state,"AWAITING_EXPLICIT_HUMAN_CONFIRMATION");
  assert.equal(b.state,"AWAITING_EXPLICIT_HUMAN_CONFIRMATION");
  assert.notEqual(a.challenge_id,b.challenge_id);
  assert.equal(f.database.rows("consents").length,2);
  blocked(await consume(f,a,{worker_id:"worker-b"}),"CONSENT_MISSING_OR_USED");
});

test("same-origin origin+Fetch Metadata+POST checks reject CSRF and query",async()=>{
  const f=setup(),c=await f.api.present(args());
  const invalid=[
    {url:"https://evil.example/api/admin/pairing/confirm-proposal"},
    {url:"https://cc.jl-bke.com/api/admin/pairing/confirm-proposal?x=1"},
    {headers:{origin:"https://evil.example"}},
    {headers:{"sec-fetch-site":"cross-site"}},
    {headers:{"sec-fetch-mode":"navigate"}},
    {headers:{"content-type":"text/plain"}},
    {headers:{"x-bke-admin-action":"revoke"}},
  ];
  for(const changes of invalid){
    blocked(await f.api.confirm({
      request:request(c,changes),env:FLAGS,executionCtx:ADMIN,
    }),"CONSENT_REQUEST_REJECTED");
  }
  assert.equal(f.database.rows("consents")[0].status,"PENDING");
});

test("unverified platform identity rejected before showing or reading intent",async()=>{
  const f=setup(),c=await f.api.present(args());
  const ctx={access:{
    aud:ADMIN.access.aud,
    async getIdentity(){return {email:"outsider@example.test"};},
  }};
  blocked(await f.api.present({...args(),executionCtx:ctx}),"CONSENT_ADMIN_DENIED");
  blocked(await f.api.confirm({
    request:request(c),env:FLAGS,executionCtx:ctx,
  }),"CONSENT_ADMIN_DENIED");
  assert.equal(f.database.rows("consents")[0].status,"PENDING");
});

test("the trusted human must approve the same worker and proposal digest",async()=>{
  const f=setup(),c=await f.api.present(args());
  for(const changes of [
    {worker_id:"worker-b",confirm_worker_id:"worker-b"},
    {proposal_sha256:"d".repeat(64)},
    {confirm_worker_id:"worker-b"},
    {action:"revoke"},
    {authorized:true},
    {hmac:"b".repeat(64)},
  ]){
    const body={
      action:"pair",challenge_id:c.challenge_id,
      worker_id:c.worker_id,confirm_worker_id:c.worker_id,
      proposal_sha256:c.proposal_sha256,...changes,
    };
    const result=await f.api.confirm({
      request:request(c,{},body),env:FLAGS,executionCtx:ADMIN,
    });
    assert.equal(result.state,"BLOCKED");
  }
  assert.equal(f.database.rows("consents")[0].status,"PENDING");
});

test("expired challenge blocks confirmation and transactional consumption",async()=>{
  const f=setup(),c=await approved(f);
  f.setTime(c.expires_at_ms);
  blocked(await consume(f,c),"CONSENT_MISSING_OR_USED");
  const g=setup(),b=await g.api.present(args());
  g.setTime(b.expires_at_ms);
  blocked(await g.api.confirm({
    request:request(b),env:FLAGS,executionCtx:ADMIN,
  }),"CONSENT_MISSING_OR_USED");
});

test("failed issuance after consent consumption rolls back confirmation tombstone",async()=>{
  const f=setup(),c=await approved(f);
  await assert.rejects(()=>f.store.atomic(async tx=>{
    assert.equal((await f.api.consumeInTransaction(tx,{
      challenge_id:c.challenge_id,worker_id:c.worker_id,
      proposal_sha256:c.proposal_sha256,subject_sha256:HUMAN,
    })).state,"CONSENT_CONSUMED_IN_TRANSACTION");
    await tx.put("pending",[{fixture:"disposable"}]);
    throw Error("simulate second write failure");
  }),/PAIRING_STORAGE_UNAVAILABLE/u);
  assert.equal(f.database.rows("consents")[0].status,"CONFIRMED");
  assert.equal(f.database.rows("pending"),undefined);
  assert.equal((await consume(f,c)).state,"CONSENT_CONSUMED_IN_TRANSACTION");
});

test("forged or missing human subject cannot consume confirmation",async()=>{
  const f=setup(),c=await approved(f);
  blocked(await consume(f,c,{subject_sha256:"e".repeat(64)}),"CONSENT_MISSING_OR_USED");
  blocked(await consume(f,c,{challenge_id:"0".repeat(64)}),"CONSENT_MISSING_OR_USED");
  assert.equal(f.database.rows("consents")[0].status,"CONFIRMED");
});

test("source defaults off before identity callback or database changes",async()=>{
  const f=setup();
  for(const key of ["BKE_PREPRODUCTION","BKE_ACCESS_POLICY_VERIFIED",
    "BKE_ADMIN_PAIRING_ACTIONS_ENABLED","BKE_ADMIN_PROPOSAL_CONSENT_ENABLED"]){
    blocked(await f.api.present({...args(),env:{...FLAGS,[key]:undefined}}),"CONSENT_LOCKED");
  }
  assert.equal(f.database.rows("consents"),undefined);
});

test("overflow/unknown fields and oversized bodies fail without confirmation",async()=>{
  const f=setup(),c=await f.api.present(args());
  blocked(await f.api.confirm({
    request:request(c,{},{
      action:"pair",challenge_id:c.challenge_id,worker_id:c.worker_id,
      confirm_worker_id:c.worker_id,proposal_sha256:c.proposal_sha256,
      extra:"X".repeat(1200),
    }),env:FLAGS,executionCtx:ADMIN,
  }),"CONSENT_INTENT_INVALID");
  assert.equal(f.database.rows("consents")[0].status,"PENDING");
});

test("transaction write error does not issue visible approval",async()=>{
  const f=setup();
  f.database.failAt=1;
  blocked(await f.api.present(args()),"CONSENT_STORAGE_UNAVAILABLE");
  assert.equal(f.database.rows("consents"),undefined);
  f.database.failAt=0;
  assert.equal((await f.api.present(args())).state,
    "AWAITING_EXPLICIT_HUMAN_CONFIRMATION");
});

test("random source errors and corrupt saved consent registries fail closed",async()=>{
  const f=setup({cryptoImpl:{getRandomValues(){throw Error("secret");}}});
  blocked(await f.api.present(args()),"CONSENT_RANDOM_UNAVAILABLE");
  const g=setup(),c=await g.api.present(args());
  await g.store.atomic(async tx=>{
    const rows=await tx.get("consents");
    await tx.put("consents",[...rows,{...rows[0]}]);
  });
  blocked(await g.api.confirm({
    request:request(c),env:FLAGS,executionCtx:ADMIN,
  }),"CONSENT_REGISTRY_AMBIGUOUS");
});

test("no route or DO RPC imports consent; flag absent in deploy config",()=>{
  const idx=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
  const doEntry=readFileSync(new URL("../src/cloudflare-worker-entry.js",import.meta.url),"utf8");
  const wr=readFileSync(new URL("../wrangler.toml",import.meta.url),"utf8");
  assert.doesNotMatch(idx,/admin-pairing-proposal-consent/u);
  assert.doesNotMatch(doEntry,/admin-pairing-proposal-consent/u);
  assert.doesNotMatch(wr,/BKE_ADMIN_PROPOSAL_CONSENT_ENABLED/u);
});
