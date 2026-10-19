// Default-OFF source integration: signed private DO command for human proposal consent.
// The browser cannot select GitHub installation, keyed subject, DO or RPC purpose.
import { inspectAdminRuntimeAccess } from "./admin-access.js";
import { readAdminWorkerAssignments, parseTrustedWorkerAssignmentPayload } from "./admin-worker-assignments.js";
import { computePairingProposalSha256 } from "./admin-atomic-pairing-invitation.js";
import { createAdminProposalConsent } from "./admin-pairing-proposal-consent.js";

const AUD="bke-command-center/preproduction/admin-pairing-consent-rpc/v1";
const SUB_AUD="bke-command-center/preproduction/execute-protected-inactive-pairing/v1";
const BROKER_PURPOSE=Object.freeze({purpose:"admin_worker_assignment_inventory"});
const INSTALL=/^[1-9][0-9]{0,19}$/u, HEX=/^[0-9a-f]{64}$/u;
const WORKER=/^[a-z0-9][a-z0-9-]{0,62}$/u, KEY=/^[A-Za-z0-9_-]{43}$/u;
const ORIGIN="https://cc.jl-bke.com", PATH="/api/admin/pairing/confirm-proposal";
const MAX_TTL=30000,MAX_BODY=1024;
const block=code=>Object.freeze({state:"BLOCKED",code});
const exact=(v,n)=>v&&typeof v==="object"&&!Array.isArray(v)&&
  Object.keys(v).sort().join(",")===n;
const hex=v=>Array.from(v,b=>b.toString(16).padStart(2,"0")).join("");
function keyBytes(value) {
  if(typeof value!=="string" || !KEY.test(value))return null;
  try {
    const b=atob(value.replaceAll("-","+").replaceAll("_","/")+"=");
    if(b.length!==32 || btoa(b).replaceAll("+","-").replaceAll("/","_").replace(/=+$/u,"")!==value)return null;
    return Uint8Array.from(b,c=>c.charCodeAt(0));
  }catch{return null;}
}
async function mac(key,value,subtle) {
  const k=await subtle.importKey("raw",key,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return hex(new Uint8Array(await subtle.sign("HMAC",k,new TextEncoder().encode(value))));
}
function equal(a,b){
  if(typeof a!=="string" || !HEX.test(a) || typeof b!=="string" || !HEX.test(b))return false;
  let difference=0;
  for(let i=0;i<64;i++)difference|=a.charCodeAt(i)^b.charCodeAt(i);
  return difference===0;
}
function enabled(env){
  return env?.BKE_PREPRODUCTION==="true" &&
    env?.BKE_ACCESS_POLICY_VERIFIED==="true" &&
    env?.BKE_ADMIN_PR_INVENTORY_ENABLED==="true" &&
    env?.BKE_ADMIN_PAIRING_ACTIONS_ENABLED==="true" &&
    env?.BKE_ADMIN_PROPOSAL_CONSENT_ENABLED==="true" &&
    env?.BKE_ADMIN_PAIRING_REVIEW_ENABLED==="true";
}
function time(clock){
  try{const n=clock();return Number.isSafeInteger(n)&&n>0&&n<Number.MAX_SAFE_INTEGER-MAX_TTL?n:null;}catch{return null;}
}
async function subject(env,executionCtx,key,subtle){
  try{
    const identity=await executionCtx?.access?.getIdentity?.();
    const email=identity?.email?.trim?.().toLowerCase();
    const allow=String(env.BKE_ADMIN_EMAILS).split(",").map(x=>x.trim().toLowerCase());
    if(!email || !allow.includes(email))return null;
    return mac(key,JSON.stringify([SUB_AUD,"human-subject",env.BKE_ADMIN_ACCESS_AUD,email]),subtle);
  }catch{return null;}
}
function install(snapshot){
  return snapshot?.state==="OBSERVED_ONLY" &&
    snapshot?.source==="GITHUB_APP_INSTALLATION" &&
    snapshot?.consistency==="NON_ATOMIC_ENUMERATION" &&
    snapshot?.dispatch_authority==="NONE" &&
    typeof snapshot?.trusted_installation_id==="string" &&
    INSTALL.test(snapshot.trusted_installation_id)
    ?snapshot.trusted_installation_id:null;
}
const keys="action,challenge_id,confirm_worker_id,proposal_sha256,worker_id";
function requestSafe(request){
  if(!(request instanceof Request) || request.method!=="POST")return false;
  let u;try{u=new URL(request.url);}catch{return false;}
  if(u.origin!==ORIGIN||u.pathname!==PATH||u.search||u.hash||u.username||u.password)return false;
  const h=request.headers;
  return h.get("origin")===ORIGIN && h.get("sec-fetch-site")==="same-origin" &&
    ["cors","same-origin"].includes(h.get("sec-fetch-mode")) &&
    h.get("content-type")==="application/json" && h.get("x-bke-admin-action")==="pair" &&
    !h.has("content-encoding") &&
    (!h.has("content-length")||
      (/^[0-9]{1,6}$/u.test(h.get("content-length")) &&
       Number(h.get("content-length"))<=MAX_BODY));
}
async function readIntent(request){
  if(!requestSafe(request) || !request.body)return null;
  let content;
  try{
    const reader=request.body.getReader(),parts=[];let size=0;
    try {
      while(true){
        const {done,value}=await reader.read();
        if(done)break;
        size+=value.byteLength;
        if(size>MAX_BODY) {await reader.cancel().catch(()=>{});return null;}
        parts.push(value);
      }
    }finally{reader.releaseLock();}
    if(size===0)return null;
    const all=new Uint8Array(size);let i=0;
    for(const v of parts){all.set(v,i);i+=v.byteLength;}
    content=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(all));
  }catch{return null;}
  if(!exact(content,keys) || content.action!=="pair" ||
    typeof content.worker_id!=="string" || !WORKER.test(content.worker_id) ||
    content.confirm_worker_id!==content.worker_id ||
    typeof content.challenge_id!=="string"||!HEX.test(content.challenge_id) ||
    typeof content.proposal_sha256!=="string"||!HEX.test(content.proposal_sha256))
    return null;
  return {action:"pair",challenge_id:content.challenge_id,
    confirm_worker_id:content.worker_id,proposal_sha256:content.proposal_sha256,
    worker_id:content.worker_id};
}
function commandString(kind,installId,nonce,expiry,human,payload){
  return JSON.stringify([AUD,kind,installId,nonce,expiry,human,payload]);
}
async function normalizeOffer(offer,installationId,cryptoImpl){
  if(!exact(offer,"public_key,resources,worker_id")||typeof offer.worker_id!=="string"||
    !WORKER.test(offer.worker_id))return null;
  const proposal=await computePairingProposalSha256({
    installationId,workerId:offer.worker_id,publicKey:offer.public_key,
    resources:offer.resources,cryptoImpl,
  });
  if(!proposal)return null;
  return {
    worker_id:offer.worker_id,public_key:proposal.key,
    resources:proposal.resources,proposal_sha256:proposal.proposalHash,
    identity_public_key_sha256:proposal.keyhash,
  };
}
function validateKind(kind,payload){
  if(kind==="present")return exact(payload,
    "identity_public_key_sha256,proposal_sha256,public_key,resources,worker_id") &&
    typeof payload.proposal_sha256==="string" && HEX.test(payload.proposal_sha256) &&
    typeof payload.identity_public_key_sha256==="string" && HEX.test(payload.identity_public_key_sha256);
  if(kind==="confirm")return exact(payload,keys) && payload.action==="pair" &&
    payload.confirm_worker_id===payload.worker_id && typeof payload.worker_id==="string" &&
    WORKER.test(payload.worker_id) && typeof payload.challenge_id==="string" &&
    HEX.test(payload.challenge_id) && typeof payload.proposal_sha256==="string" &&
    HEX.test(payload.proposal_sha256);
  return false;
}

// Never export the full installation or human subject to the browser.
// A human proposal is supplied only by a trusted server-side preparation adapter;
// device possession and delivery remain separately locked.
export async function sendAdminPairingConsent({
  env,executionCtx,kind,offer,request,readAssignments=readAdminWorkerAssignments,
  cryptoImpl=crypto,clock=()=>Date.now(),
}={}){
  if(!enabled(env))return block("REVIEW_RPC_LOCKED");
  const secret=keyBytes(env?.BKE_PAIRING_RPC_KEY_B64);
  if(!secret || !["present","confirm"].includes(kind) ||
    typeof readAssignments!=="function" ||
    typeof cryptoImpl?.subtle?.sign!=="function" ||
    typeof cryptoImpl?.getRandomValues!=="function")
    return block("REVIEW_RPC_ADAPTER_INVALID");
  if(await inspectAdminRuntimeAccess(executionCtx,env)!=="AUTHORIZED")
    return block("REVIEW_RPC_ADMIN_DENIED");
  const human=await subject(env,executionCtx,secret,cryptoImpl.subtle);
  if(!human)return block("REVIEW_RPC_ADMIN_DENIED");
  let snapshot;
  try {snapshot=await readAssignments(env,executionCtx);}
  catch{return block("REVIEW_RPC_GITHUB_UNAVAILABLE");}
  const id=install(snapshot);
  if(!id)return block("REVIEW_RPC_GITHUB_AMBIGUOUS");
  const payload=kind==="present"
    ? await normalizeOffer(offer,id,cryptoImpl)
    : await readIntent(request);
  if(!payload)return block("REVIEW_RPC_REQUEST_REJECTED");
  const namespace=env?.BKE_WORKER_PAIRING_VAULT;
  if(typeof namespace?.get!=="function"||typeof namespace?.idFromName!=="function")
    return block("REVIEW_RPC_NAMESPACE_UNAVAILABLE");
  const now=time(clock);
  if(now===null)return block("REVIEW_RPC_CLOCK_INVALID");
  let nonce,signature;
  const expires_at_ms=now+MAX_TTL;
  try {
    const random=new Uint8Array(32);cryptoImpl.getRandomValues(random);
    nonce=hex(random);
    signature=await mac(secret,commandString(kind,id,nonce,expires_at_ms,human,payload),
      cryptoImpl.subtle);
  }catch{return block("REVIEW_RPC_CRYPTO_UNAVAILABLE");}
  let answer;
  try{
    const target=namespace.get(namespace.idFromName("installation:"+id));
    if(typeof target?.reviewPairingConsent!=="function")
      return block("REVIEW_RPC_METHOD_UNAVAILABLE");
    answer=await target.reviewPairingConsent({
      purpose:"human_pairing_review_v1",kind,installation_id:id,nonce,expires_at_ms,
      subject_sha256:human,payload,signature,
    });
  }catch{return block("REVIEW_RPC_OUTCOME_UNCERTAIN");}
  if(answer?.state==="BLOCKED")return block("REVIEW_RPC_DENIED");
  if(kind==="present"){
    if(!exact(answer,"challenge_id,dispatch_authority,expires_at_ms,pairing_authority,proposal_sha256,state,worker_id") ||
      answer.state!=="AWAITING_EXPLICIT_HUMAN_CONFIRMATION" ||
      answer.worker_id!==payload.worker_id ||
      answer.proposal_sha256!==payload.proposal_sha256 ||
      answer.pairing_authority!=="NONE"||answer.dispatch_authority!=="NONE" ||
      typeof answer.challenge_id!=="string"||!HEX.test(answer.challenge_id)||
      !Number.isSafeInteger(answer.expires_at_ms))
      return block("REVIEW_RPC_OUTCOME_UNCERTAIN");
  }else if(!exact(answer,"challenge_id,dispatch_authority,pairing_authority,proposal_sha256,state,worker_id") ||
    answer.state!=="CONFIRMED_FOR_ATOMIC_ISSUANCE" ||
    answer.worker_id!==payload.worker_id||answer.proposal_sha256!==payload.proposal_sha256||
    answer.challenge_id!==payload.challenge_id ||
    answer.pairing_authority!=="NONE"||answer.dispatch_authority!=="NONE")
    return block("REVIEW_RPC_OUTCOME_UNCERTAIN");
  return Object.freeze({...answer});
}

// Runs inside one signed installation DO only. Signed envelope is not a
// fabricated Access context: it carries the already verified keyed subject.
export async function receiveAdminPairingConsent({
  command,env,objectId,store,cryptoImpl=crypto,clock=()=>Date.now(),
}={}){
  if(!enabled(env))return block("REVIEW_RPC_LOCKED");
  if(!exact(command,"expires_at_ms,installation_id,kind,nonce,payload,purpose,signature,subject_sha256") ||
     command.purpose!=="human_pairing_review_v1" ||
     typeof command.installation_id!=="string"||!INSTALL.test(command.installation_id)||
     !["present","confirm"].includes(command.kind)||
     typeof command.nonce!=="string"||!HEX.test(command.nonce)||
     typeof command.signature!=="string"||!HEX.test(command.signature)||
     typeof command.subject_sha256!=="string"||!HEX.test(command.subject_sha256)||
     !Number.isSafeInteger(command.expires_at_ms) ||
     !validateKind(command.kind,command.payload) ||
     typeof objectId?.toString!=="function"||typeof store?.atomic!=="function"||
     typeof env?.BKE_WORKER_PAIRING_VAULT?.idFromName!=="function")
    return block("REVIEW_RPC_REQUEST_REJECTED");
  const key=keyBytes(env.BKE_PAIRING_RPC_KEY_B64),now=time(clock);
  if(!key||now===null||command.expires_at_ms<=now||
     command.expires_at_ms>now+MAX_TTL)return block("REVIEW_RPC_REQUEST_REJECTED");
  try{
    const expected=env.BKE_WORKER_PAIRING_VAULT.idFromName(
      "installation:"+command.installation_id);
    if(expected?.toString()!==objectId.toString())
      return block("REVIEW_RPC_INSTALLATION_MISMATCH");
    const signed=await mac(key,commandString(command.kind,command.installation_id,
      command.nonce,command.expires_at_ms,command.subject_sha256,command.payload),
    cryptoImpl.subtle);
    if(!equal(signed,command.signature))return block("REVIEW_RPC_REQUEST_REJECTED");
  }catch{return block("REVIEW_RPC_REQUEST_REJECTED");}
  if(typeof env?.BKE_GITHUB_READ_BROKER?.listVerifiedWorkerAssignments!=="function")
    return block("REVIEW_RPC_BROKER_UNAVAILABLE");
  let snapshot;
  try {
    snapshot=parseTrustedWorkerAssignmentPayload(
      await env.BKE_GITHUB_READ_BROKER.listVerifiedWorkerAssignments(BROKER_PURPOSE));
  }catch{return block("REVIEW_RPC_GITHUB_UNAVAILABLE");}
  if(install(snapshot)!==command.installation_id)
    return block("REVIEW_RPC_INSTALLATION_MISMATCH");
  // Deny candidates already claimed by GitHub. This is still NON-ATOMIC evidence.
  if(snapshot.worker_claims.some(x=>x.worker_id===command.payload.worker_id))
    return block("REVIEW_RPC_ASSIGNMENT_CONFLICT");
  if(command.kind==="present"){
    const proposal=await normalizeOffer({
      worker_id:command.payload.worker_id,public_key:command.payload.public_key,
      resources:command.payload.resources,
    },command.installation_id,cryptoImpl);
    if(!proposal||JSON.stringify(proposal)!==JSON.stringify(command.payload))
      return block("REVIEW_RPC_PROPOSAL_CHANGED");
  }
  const consent=createAdminProposalConsent({
    store,cryptoImpl,clock,authorizeSubject:async()=>null,
  });
  try {
    if(command.kind==="present"){
      return await consent.presentFromVerifiedRpc({
        worker_id:command.payload.worker_id,
        proposal_sha256:command.payload.proposal_sha256,
        subject_sha256:command.subject_sha256,env,
      });
    }
    const body=command.payload;
    // Reconstructed only from HMAC-verified, server-validated exact fields.
    const request=new Request(ORIGIN+PATH,{
      method:"POST",
      headers:{"origin":ORIGIN,"sec-fetch-site":"same-origin",
        "sec-fetch-mode":"cors","content-type":"application/json",
        "x-bke-admin-action":"pair"},
      body:JSON.stringify(body),
    });
    return await consent.confirmFromVerifiedRpc({
      request,subject_sha256:command.subject_sha256,env,
    });
  }catch{return block("REVIEW_RPC_OUTCOME_UNCERTAIN");}
}
