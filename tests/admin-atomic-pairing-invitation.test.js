import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { createAtomicPairingInvitation, computePairingProposalSha256 } from "../src/admin-atomic-pairing-invitation.js";
import { createAdminProposalConsent } from "../src/admin-pairing-proposal-consent.js";
import { createProtectedInactivePairing } from "../src/protected-inactive-pairing.js";
import { createPairingAtomicStore } from "../src/worker-pairing-durable-store.js";
import { parseTrustedWorkerAssignmentPayload } from "../src/admin-worker-assignments.js";

const SUBJECT="f".repeat(64);
const CONTEXT=Object.freeze({access:{
  aud:"0123456789abcdef0123456789abcdef",
  async getIdentity(){return {email:"admin@example.test"};},
}});
const env={
  BKE_PREPRODUCTION:"true",BKE_ACCESS_POLICY_VERIFIED:"true",
  BKE_ADMIN_PR_INVENTORY_ENABLED:"true",
  BKE_ADMIN_PAIRING_ACTIONS_ENABLED:"true",
  BKE_ADMIN_PROTECTED_PAIRING_ENABLED:"true",
  BKE_ADMIN_PAIRING_ISSUANCE_ENABLED:"true",
  BKE_ADMIN_PROPOSAL_CONSENT_ENABLED:"true",
  BKE_ADMIN_DISCOVERY_ENABLED:"true",
  BKE_ADMIN_ACCESS_ISSUER:"https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD:CONTEXT.access.aud,
  BKE_ADMIN_EMAILS:"admin@example.test",
};
const raw=()=>({
  authority:"EXISTING_GITHUB_APP_INSTALLATION",principal:"github_app_installation",
  repository_scope:"INSTALLATION_APPROVED_ONLY",
  consistency:"NON_ATOMIC_ENUMERATION",installation_id:"51",
  total_visible_repositories:76,enumerated_open_pull_requests:0,
  worker_assignments:[],
});
const resources=(i=0)=>({
  chatgpt_target_sha256:"123456789abcdef0"[i].repeat(64),
  browser_profile_sha256:"123456789abcdef0"[i+4].repeat(64),
  bridge_identity_sha256:"123456789abcdef0"[i+8].repeat(64),
});
const deny=(res,expected)=>{
  assert.equal(res.state,"BLOCKED");
  if(expected)assert.equal(res.code,expected);
  assert.deepEqual(Object.keys(res).sort(),["code","state"]);
  assert.doesNotMatch(JSON.stringify(res), /ghs_|Bearer|private|one_time_nonce/u);
};
function storage() {
  let state=new Map(),gate=Promise.resolve();
  return {
    failAt:0, transactions:0,
    async transaction(fn){
      let unlock;
      const next=new Promise(resolve=>{unlock=resolve;});
      const prev=gate;gate=next;await prev;
      const draft=new Map(structuredClone([...state]));
      let writes=0;this.transactions++;
      try {
        const result=await fn({
          get:async key=>structuredClone(draft.get(key)),
          put:async(key,value)=>{
            if(++writes===this.failAt)throw Error("private backend secret");
            draft.set(key,structuredClone(value));
          },
        });
        state=draft;return result;
      }finally{unlock();}
    },
    read:k=>structuredClone(state.get("bke:pairing:v1:"+k)),
  };
}
async function keypair(){
  const pair=await webcrypto.subtle.generateKey(
    {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const key=await webcrypto.subtle.exportKey("jwk",pair.publicKey);
  return {privateKey:pair.privateKey,
    public_key:{crv:"P-256",kty:"EC",x:key.x,y:key.y}};
}
function make(options={}){
  const backend=storage(),store=createPairingAtomicStore(backend);
  let now=100000,actualRaw=raw(),allow=true,reads=0;
  const authorize=async (proposal,context)=>{
    if(!allow || context!==CONTEXT || proposal.action!=="pair" ||
        !/^[a-f0-9]{64}$/.test(proposal.proposal_sha256)) return null;
    return SUBJECT;
  };
  const consent=createAdminProposalConsent({
    store,clock:()=>now,cryptoImpl:webcrypto,
    authorizeSubject:async(action,worker,proposal,ctx)=>
      ctx===CONTEXT && action==="pair" && /^[a-f0-9]{64}$/.test(proposal) &&
      /^[a-z0-9-]+$/.test(worker) ? SUBJECT : null,
  });
  const instance=createAtomicPairingInvitation({
    store,installationId:options.installationId??"51",
    confirmedConsent:consent,
    cryptoImpl:options.cryptoImpl??webcrypto,
    clock:()=>now,
    authorizeHumanAction:options.authorize??authorize,
    readInstallationInventory:async()=>{
      reads++;
      if(options.brokerFailure)throw Error("private provider token");
      return structuredClone(actualRaw);
    },
  });
  return {
    backend,store,instance,consent,installationId:options.installationId??"51",reads:()=>reads,
    setTime:n=>{now=n;},setRaw:v=>{actualRaw=v;},
    setHuman:v=>{allow=v;},
    finalize:createProtectedInactivePairing({
      store,installationId:options.installationId??"51",
      cryptoImpl:webcrypto,clock:()=>now,
      authorizeAccess:async ctx=>ctx===CONTEXT,
      authorizeHumanSubject:async (_a,_w,ctx)=>ctx===CONTEXT?SUBJECT:null,
      readAssignments:async()=>parseTrustedWorkerAssignmentPayload(actualRaw),
    }),
  };
}
function confirmationRequest(challenge){
  return new Request("https://cc.jl-bke.com/api/admin/pairing/confirm-proposal",{
    method:"POST",
    headers:{
      origin:"https://cc.jl-bke.com",
      "sec-fetch-site":"same-origin",
      "sec-fetch-mode":"cors",
      "content-type":"application/json",
      "x-bke-admin-action":"pair",
    },
    body:JSON.stringify({
      action:"pair",challenge_id:challenge.challenge_id,
      worker_id:challenge.worker_id,confirm_worker_id:challenge.worker_id,
      proposal_sha256:challenge.proposal_sha256,
    }),
  });
}
async function confirmed(f,key,worker_id="worker-a",r=resources()) {
  const proposal=await computePairingProposalSha256({
    installationId:f.installationId,workerId:worker_id,
    publicKey:key.public_key,resources:r,cryptoImpl:webcrypto,
  });
  if(!proposal)return null;
  const presented=await f.consent.present({
    worker_id,proposal_sha256:proposal.proposalHash,
    env,executionCtx:CONTEXT,
  });
  if(presented.state!=="AWAITING_EXPLICIT_HUMAN_CONFIRMATION")return null;
  const result=await f.consent.confirm({
    request:confirmationRequest(presented),env,executionCtx:CONTEXT,
  });
  if(result.state!=="CONFIRMED_FOR_ATOMIC_ISSUANCE")return null;
  return presented.challenge_id;
}
async function issue(f,key,worker_id="worker-a",r=resources()){
  const consent_challenge_id=await confirmed(f,key,worker_id,r);
  return f.instance.issue({
    worker_id,public_key:key.public_key,resources:r,
    consent_challenge_id,admin_context:CONTEXT,env,
  });
}

test("real P-256 and human proof issue together, finalizer consumes both atomically",async()=>{
  const f=make(),key=await keypair();
  const invitation=await issue(f,key);
  assert.equal(invitation.state,"ISSUED_FOR_SECURE_DELIVERY");
  assert.equal(invitation.pairing_authority,"NONE");
  assert.equal(invitation.dispatch_authority,"NONE");
  assert.match(invitation.device_challenge.message,/worker-pairing\/v1/u);
  assert.match(invitation.human_ticket.one_time_nonce,/^[a-f0-9]{64}$/u);
  const rows=f.backend.read("pending"),tickets=f.backend.read("admin_actions");
  assert.equal(rows.length,1);
  assert.equal(tickets.length,1);
  assert.equal(tickets[0].status,"PENDING");
  assert.equal(f.backend.read("consents")[0].status,"CONSUMED");
  assert.equal(f.backend.read("paired"),undefined);
  assert.ok(!JSON.stringify([rows,tickets]).includes(invitation.human_ticket.one_time_nonce));
  const signature=Buffer.from(new Uint8Array(await webcrypto.subtle.sign(
    {name:"ECDSA",hash:"SHA-256"},key.privateKey,
    new TextEncoder().encode(invitation.device_challenge.message)))).toString("base64url");
  const accepted=await f.finalize.finalize({
    worker_id:"worker-a",device_challenge_id:invitation.device_challenge.challenge_id,
    device_signature:signature,
    admin_challenge_id:invitation.human_ticket.challenge_id,
    admin_one_time_nonce:invitation.human_ticket.one_time_nonce,
    env,executionCtx:CONTEXT,
  });
  assert.deepEqual(accepted,{
    state:"PAIRED_INACTIVE",code:"PROTECTED_PAIRING_INACTIVE_ONLY",
  });
  assert.equal(f.backend.read("pending").length,0);
  assert.equal(f.backend.read("admin_actions")[0].status,"CONSUMED");
  assert.equal(f.backend.read("paired")[0].status,"PAIRED_INACTIVE");
});

test("second write failure rolls back BOTH invitation records",async()=>{
  const f=make(),key=await keypair();
  const consent_challenge_id=await confirmed(f,key);
  f.backend.failAt=3; // consent, pending, admin_actions: third write fails.
  deny(await f.instance.issue({
    worker_id:"worker-a",public_key:key.public_key,resources:resources(),
    consent_challenge_id,admin_context:CONTEXT,env,
  }),"INVITATION_STORAGE_UNAVAILABLE");
  assert.equal(f.backend.read("pending"),undefined);
  assert.equal(f.backend.read("admin_actions"),undefined);
  assert.equal(f.backend.read("consents")[0].status,"CONFIRMED");
  f.backend.failAt=0;
  assert.equal((await f.instance.issue({
    worker_id:"worker-a",public_key:key.public_key,resources:resources(),
    consent_challenge_id,admin_context:CONTEXT,env,
  })).state,"ISSUED_FOR_SECURE_DELIVERY");
  assert.equal(f.backend.read("consents")[0].status,"CONSUMED");
});

test("parallel invitations for one worker issue at most one complete pair",async()=>{
  const f=make(),[a,b]=await Promise.all([keypair(),keypair()]);
  const outcomes=await Promise.all([issue(f,a),issue(f,b)]);
  assert.equal(outcomes.filter(x=>x.state==="ISSUED_FOR_SECURE_DELIVERY").length,1);
  assert.equal(outcomes.filter(x=>x.state==="BLOCKED").length,1);
  assert.equal(f.backend.read("pending").length,1);
  assert.equal(f.backend.read("admin_actions").length,1);
});

test("independent workers have isolated invitations in one installation",async()=>{
  const f=make(),[a,b]=await Promise.all([keypair(),keypair()]);
  const [one,two]=await Promise.all([
    issue(f,a,"worker-a",resources(0)),issue(f,b,"worker-b",resources(1)),
  ]);
  assert.equal(one.state,"ISSUED_FOR_SECURE_DELIVERY");
  assert.equal(two.state,"ISSUED_FOR_SECURE_DELIVERY");
  assert.equal(f.backend.read("pending").length,2);
  assert.equal(f.backend.read("admin_actions").length,2);
  assert.equal(f.backend.read("consents").filter(c=>c.status==="CONSUMED").length,2);
});

test("resource collision across different workers fails closed",async()=>{
  const f=make(),[a,b]=await Promise.all([keypair(),keypair()]);
  assert.equal((await issue(f,a)).state,"ISSUED_FOR_SECURE_DELIVERY");
  deny(await issue(f,b,"worker-b",resources()),"INVITATION_CONFLICT");
  assert.equal(f.backend.read("admin_actions").length,1);
});

test("human confirmation denial blocks before GitHub reads and writes",async()=>{
  const f=make(),key=await keypair();
  f.setHuman(false);
  deny(await issue(f,key),"INVITATION_HUMAN_DENIED");
  assert.equal(f.reads(),0);
  assert.equal(f.backend.read("pending"),undefined);
});

test("cross-installation and malformed or incomplete GitHub evidence blocked",async()=>{
  const key=await keypair();
  const wrong=make({installationId:"52"});
  deny(await issue(wrong,key),"INVITATION_GITHUB_AMBIGUOUS");
  const f=make();
  f.setRaw({...raw(),worker_assignments:[{
    repository:"jan2xo/bke-worker",repository_id:1354026486,
    number:104,head_sha:"a".repeat(40),state:"open",
    labels:["bke-worker:worker-a"],
  }],enumerated_open_pull_requests:1});
  deny(await issue(f,key),"INVITATION_ELIGIBILITY_DENIED");
  // A separate fixture avoids re-presenting against the previous live,
  // unconsumed human confirmation, which must fail closed by design.
  const malformed=make();
  malformed.setRaw({...raw(),authority:"BROWSER"});
  deny(await issue(malformed,key),"INVITATION_GITHUB_UNAVAILABLE");
});

test("expired 90s ticket does not weaken P-256 challenge or future guard",async()=>{
  const f=make(),key=await keypair();
  const invited=await issue(f,key);
  f.setTime(invited.human_ticket.expires_at_ms);
  const next=await issue(f,key);
  deny(next,"INVITATION_CONFLICT");
});

test("default-OFF flag stops before consent/provider and registry I/O",async()=>{
  const f=make(),key=await keypair();
  deny(await f.instance.issue({
    worker_id:"worker-a",public_key:key.public_key,
    resources:resources(),admin_context:CONTEXT,
    env:{...env,BKE_ADMIN_PAIRING_ISSUANCE_ENABLED:undefined},
  }),"INVITATION_LOCKED");
  assert.equal(f.reads(),0);
});

test("invalid public key and forbidden extra resource fields reject",async()=>{
  const f=make(),key=await keypair();
  deny(await issue(f,{public_key:{...key.public_key,x:"bad"}}),"INVITATION_INPUT_INVALID");
  deny(await issue(f,key,"worker-a",{...resources(),token:"not allowed"}),
    "INVITATION_INPUT_INVALID");
  assert.equal(f.reads(),0);
});

test("ambiguous legacy pending registries never grant an invitation",async()=>{
  const f=make(),key=await keypair();
  const ok=await issue(f,key);
  assert.equal(ok.state,"ISSUED_FOR_SECURE_DELIVERY");
  await f.store.atomic(async tx=>{
    const arr=await tx.get("pending");
    await tx.put("pending",[...arr,{...arr[0]}]);
  });
  const other=await keypair();
  deny(await issue(f,other,"worker-b",resources(1)),"INVITATION_REGISTRY_AMBIGUOUS");
  assert.equal(f.backend.read("admin_actions").length,1);
});

test("fixture has no public API, private named issuance RPC or enabled Wrangler flag",()=>{
  const entry=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
  const runtime=readFileSync(new URL("../src/cloudflare-worker-entry.js",import.meta.url),"utf8");
  const wr=readFileSync(new URL("../wrangler.toml",import.meta.url),"utf8");
  assert.doesNotMatch(entry,/admin-atomic-pairing-invitation/u);
  assert.doesNotMatch(runtime,/admin-atomic-pairing-invitation/u);
  assert.doesNotMatch(wr,/BKE_ADMIN_PAIRING_ISSUANCE_ENABLED/u);
});

test("no consent and missing challenge always block before issuing both proofs",async()=>{
  const f=make(),key=await keypair();
  deny(await f.instance.issue({
    worker_id:"worker-a",public_key:key.public_key,resources:resources(),
    admin_context:CONTEXT,env,
  }),"INVITATION_CONSENT_REQUIRED");
  assert.equal(f.reads(),0);
  assert.equal(f.backend.read("pending"),undefined);
  assert.equal(f.backend.read("admin_actions"),undefined);
});

test("presented but unconfirmed human challenge cannot issue an invitation",async()=>{
  const f=make(),key=await keypair();
  const p=await computePairingProposalSha256({
    installationId:f.installationId,workerId:"worker-a",
    publicKey:key.public_key,resources:resources(),cryptoImpl:webcrypto,
  });
  const challenge=await f.consent.present({
    worker_id:"worker-a",proposal_sha256:p.proposalHash,
    env,executionCtx:CONTEXT,
  });
  deny(await f.instance.issue({
    worker_id:"worker-a",public_key:key.public_key,resources:resources(),
    consent_challenge_id:challenge.challenge_id,admin_context:CONTEXT,env,
  }),"INVITATION_CONSENT_DENIED");
  assert.equal(f.backend.read("consents")[0].status,"PENDING");
  assert.equal(f.backend.read("pending"),undefined);
});

test("replay of consumed confirmation cannot mint a second invitation",async()=>{
  const f=make(),key=await keypair();
  const consent_challenge_id=await confirmed(f,key);
  const arguments_={
    worker_id:"worker-a",public_key:key.public_key,resources:resources(),
    consent_challenge_id,admin_context:CONTEXT,env,
  };
  assert.equal((await f.instance.issue(arguments_)).state,"ISSUED_FOR_SECURE_DELIVERY");
  assert.equal(f.backend.read("consents")[0].status,"CONSUMED");
  const next=await f.instance.issue(arguments_);
  assert.equal(next.state,"BLOCKED");
  assert.equal(f.backend.read("admin_actions").length,1);
  assert.equal(f.backend.read("pending").length,1);
});

test("wrong worker, device key or resource proposal cannot spend confirmed consent",async()=>{
  for(const variant of ["worker","key","resources"]){
    const f=make(),key=await keypair(),other=await keypair();
    const id=await confirmed(f,key);
    const bad=variant==="worker"?
      {worker_id:"worker-b",public_key:key.public_key,resources:resources()}:
      variant==="key"?
      {worker_id:"worker-a",public_key:other.public_key,resources:resources()}:
      {worker_id:"worker-a",public_key:key.public_key,resources:resources(1)};
    deny(await f.instance.issue({
      ...bad,consent_challenge_id:id,admin_context:CONTEXT,env,
    }),"INVITATION_CONSENT_DENIED");
    assert.equal(f.backend.read("consents")[0].status,"CONFIRMED");
    assert.equal(f.backend.read("pending"),undefined);
    assert.equal(f.backend.read("admin_actions"),undefined);
  }
});

test("expired consent blocks atomically and leaves no orphaned device or Admin ticket",async()=>{
  const f=make(),key=await keypair();
  const id=await confirmed(f,key);
  f.setTime(160000); // 60-second human proposal approval boundary
  deny(await f.instance.issue({
    worker_id:"worker-a",public_key:key.public_key,resources:resources(),
    consent_challenge_id:id,admin_context:CONTEXT,env,
  }),"INVITATION_CONSENT_DENIED");
  assert.equal(f.backend.read("pending"),undefined);
  assert.equal(f.backend.read("admin_actions"),undefined);
  assert.equal(f.backend.read("consents")[0].status,"CONFIRMED");
});

test("canonical proposal digests ignore harmless input resource property order",async()=>{
  const key=await keypair();
  const normal=resources(),reordered={
    bridge_identity_sha256:normal.bridge_identity_sha256,
    browser_profile_sha256:normal.browser_profile_sha256,
    chatgpt_target_sha256:normal.chatgpt_target_sha256,
  };
  const opts={installationId:"51",workerId:"worker-a",
    publicKey:key.public_key,cryptoImpl:webcrypto};
  const p1=await computePairingProposalSha256({...opts,resources:normal});
  const p2=await computePairingProposalSha256({...opts,resources:reordered});
  assert.equal(p1.proposalHash,p2.proposalHash);
  const f=make(),id=await confirmed(f,key);
  assert.equal((await f.instance.issue({
    worker_id:"worker-a",public_key:key.public_key,resources:reordered,
    consent_challenge_id:id,admin_context:CONTEXT,env,
  })).state,"ISSUED_FOR_SECURE_DELIVERY");
});

test("independently denied proposal identity never becomes a device credential",async()=>{
  const f=make(),key=await keypair();
  const consent_challenge_id=await confirmed(f,key);
  f.setHuman(false);
  deny(await f.instance.issue({
    worker_id:"worker-a",public_key:key.public_key,resources:resources(),
    consent_challenge_id,admin_context:CONTEXT,env,
  }),"INVITATION_HUMAN_DENIED");
  assert.equal(f.backend.read("consents")[0].status,"CONFIRMED");
  assert.equal(f.backend.read("pending"),undefined);
});

test("consent flag missing forbids issuance even with a previously confirmed proposal",async()=>{
  const f=make(),key=await keypair(),consent_challenge_id=await confirmed(f,key);
  deny(await f.instance.issue({
    worker_id:"worker-a",public_key:key.public_key,resources:resources(),
    consent_challenge_id,admin_context:CONTEXT,
    env:{...env,BKE_ADMIN_PROPOSAL_CONSENT_ENABLED:undefined},
  }),"INVITATION_LOCKED");
  assert.equal(f.backend.read("consents")[0].status,"CONFIRMED");
  assert.equal(f.backend.read("pending"),undefined);
});
