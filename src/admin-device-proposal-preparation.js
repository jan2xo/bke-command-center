// Source-only device-origin proposal preparation, not a public ingress.
// P-256 proves possession of an unpaired device key, NOT worker authorization.
// Browser/GeckoView transport, admission approval, and activation are separate.
import { inspectAdminRuntimeAccess } from "./admin-access.js";
import { readAdminWorkerAssignments,parseTrustedWorkerAssignmentPayload } from "./admin-worker-assignments.js";
import { computePairingProposalSha256 } from "./admin-atomic-pairing-invitation.js";
import { isSafePairedRegistry,isSafePendingChallenges } from "./worker-pairing-ceremony.js";

const AUD="bke-command-center/preproduction/device-proposal-preparation/v1";
const DEVICE_AUD="bke-command-center/preproduction/device-key-possession/v1";
const HUMAN_AUD="bke-command-center/preproduction/execute-protected-inactive-pairing/v1";
const INSTALL=/^[1-9][0-9]{0,19}$/u;
const WORKER=/^[a-z0-9][a-z0-9-]{0,62}$/u;
const HEX=/^[a-f0-9]{64}$/u;
const KEY=/^[A-Za-z0-9_-]{43}$/u;
const SIG=/^[A-Za-z0-9_-]{86}$/u;
const RESOURCE=["chatgpt_target_sha256","browser_profile_sha256","bridge_identity_sha256"];
const LABELS=["chatgpt_target","browser_profile","bridge_identity"];
const COMMAND_TTL=30_000, PREPARED_TTL=90_000;
const PURPOSE="device_proposal_preparation_v1";
const BROKER_PURPOSE=Object.freeze({purpose:"admin_worker_assignment_inventory"});
const blocked=code=>Object.freeze({state:"BLOCKED",code});
const exact=(x,keys)=>x&&typeof x==="object"&&!Array.isArray(x)&&
  Object.keys(x).sort().join(",")===keys;
const hex=v=>Array.from(v,b=>b.toString(16).padStart(2,"0")).join("");
const encoding=new TextEncoder();
function decodeBase64url(value,length,pattern) {
  if(typeof value!=="string"||!pattern.test(value))return null;
  try {
    const s=atob(value.replaceAll("-","+").replaceAll("_","/")+"=".repeat((4-value.length%4)%4));
    if(s.length!==length||btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/u,"")!==value)
      return null;
    return Uint8Array.from(s,c=>c.charCodeAt(0));
  }catch{return null;}
}
function keyBytes(v){return decodeBase64url(v,32,KEY);}
function sigBytes(v){return decodeBase64url(v,64,SIG);}
function b64(v){return btoa(Array.from(v,b=>String.fromCharCode(b)).join(""))
  .replaceAll("+","-").replaceAll("/","_").replace(/=+$/u,"");}
async function mac(key,message,subtle){
  const k=await subtle.importKey("raw",key,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return hex(new Uint8Array(await subtle.sign("HMAC",k,encoding.encode(message))));
}
function equal(a,b) {
  if(typeof a!=="string"||!HEX.test(a)||typeof b!=="string"||!HEX.test(b))return false;
  let diff=0;for(let i=0;i<64;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);
  return diff===0;
}
function flags(env){
  return env?.BKE_PREPRODUCTION==="true" &&
    env?.BKE_ACCESS_POLICY_VERIFIED==="true" &&
    env?.BKE_ADMIN_PR_INVENTORY_ENABLED==="true" &&
    env?.BKE_ADMIN_PAIRING_ACTIONS_ENABLED==="true" &&
    env?.BKE_ADMIN_PAIRING_REVIEW_ENABLED==="true" &&
    env?.BKE_ADMIN_PROPOSAL_CONSENT_ENABLED==="true" &&
    env?.BKE_ADMIN_DEVICE_PREPARATION_ENABLED==="true";
}
function nowMs(clock){
  try{const n=clock();return Number.isSafeInteger(n)&&n>0&&n<Number.MAX_SAFE_INTEGER-2*PREPARED_TTL?n:null;}
  catch{return null;}
}
function trustedInstallation(snapshot){
  return snapshot?.state==="OBSERVED_ONLY" &&
    snapshot?.source==="GITHUB_APP_INSTALLATION" &&
    snapshot?.consistency==="NON_ATOMIC_ENUMERATION" &&
    snapshot?.dispatch_authority==="NONE" &&
    typeof snapshot?.trusted_installation_id==="string" &&
    INSTALL.test(snapshot.trusted_installation_id) &&
    Array.isArray(snapshot.worker_claims)
    ? snapshot.trusted_installation_id:null;
}
function labelsValid(display){
  return exact(display,LABELS.slice().sort().join(",")) &&
    LABELS.every(k=>typeof display[k]==="string"&&
      display[k].trim().length>0&&display[k].length<=160&&
      !/[\u0000-\u001f\u007f]/u.test(display[k]));
}
async function normalizeOffer(input,installationId,cryptoImpl){
  if(!exact(input,"display,public_key,resources,worker_id") ||
    typeof input.worker_id!=="string"||!WORKER.test(input.worker_id)||
    !labelsValid(input.display))return null;
  const canonical=await computePairingProposalSha256({
    installationId,workerId:input.worker_id,publicKey:input.public_key,
    resources:input.resources,cryptoImpl,
  });
  if(!canonical)return null;
  return Object.freeze({
    worker_id:input.worker_id,public_key:canonical.key,
    resources:canonical.resources,
    display:Object.fromEntries(LABELS.map(k=>[k,input.display[k]])),
    proposal_sha256:canonical.proposalHash,
    identity_public_key_sha256:canonical.keyhash,
  });
}
function envelope(kind,installationId,nonce,expiry,subject,payload){
  return JSON.stringify([AUD,PURPOSE,kind,installationId,nonce,expiry,subject,payload]);
}
function deviceMessage(installationId,subject,offer,nonce,expiry){
  return JSON.stringify([DEVICE_AUD,"prepare",installationId,offer.worker_id,
    offer.proposal_sha256,subject,nonce,expiry]);
}
async function verifyProof(offer,installationId,subject,nonce,expiry,signature,cryptoImpl){
  const raw=sigBytes(signature);
  if(!raw||typeof nonce!=="string"||!HEX.test(nonce))return false;
  try{
    const key=await cryptoImpl.subtle.importKey("jwk",offer.public_key,
      {name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
    return await cryptoImpl.subtle.verify(
      {name:"ECDSA",hash:"SHA-256"},key,raw,
      encoding.encode(deviceMessage(installationId,subject,offer,nonce,expiry)));
  }catch{return false;}
}
async function humanSubject(env,executionCtx,key,subtle){
  try{
    const identity=await executionCtx?.access?.getIdentity?.();
    const email=identity?.email?.trim?.().toLowerCase();
    const allowed=String(env.BKE_ADMIN_EMAILS).split(",").map(x=>x.trim().toLowerCase());
    if(!email||!allowed.includes(email))return null;
    return mac(key,JSON.stringify([HUMAN_AUD,"human-subject",
      env.BKE_ADMIN_ACCESS_AUD,email]),subtle);
  }catch{return null;}
}
function validPreparedRows(rows){
  if(!Array.isArray(rows)||rows.length>100)return false;
  const workers=new Set(),nonces=new Set();
  for(const row of rows) {
    if(!exact(row,"display,expires_at_ms,identity_public_key_sha256,proof_nonce,proposal_sha256,public_key,resources,subject_sha256,worker_id")||
      typeof row.worker_id!=="string"||!WORKER.test(row.worker_id) ||
      typeof row.identity_public_key_sha256!=="string"||!HEX.test(row.identity_public_key_sha256) ||
      typeof row.proposal_sha256!=="string"||!HEX.test(row.proposal_sha256) ||
      typeof row.proof_nonce!=="string"||!HEX.test(row.proof_nonce) ||
      typeof row.subject_sha256!=="string"||!HEX.test(row.subject_sha256) ||
      !Number.isSafeInteger(row.expires_at_ms)||row.expires_at_ms<0||
      !labelsValid(row.display)||workers.has(row.worker_id)||nonces.has(row.proof_nonce))return false;
    workers.add(row.worker_id);nonces.add(row.proof_nonce);
  }
  return true;
}
function conflictWith(existing,offer){
  return existing.some(r=>r.worker_id===offer.worker_id ||
    r.identity_public_key_sha256===offer.identity_public_key_sha256 ||
    RESOURCE.some(k=>r[k]===offer.resources[k]));
}
function responseOk(state,kind){
  if(kind==="stage")return exact(state,"dispatch_authority,expires_at_ms,pairing_authority,proposal_sha256,state,worker_id") &&
    state.state==="PREPARED_FOR_HUMAN_REVIEW" &&
    state.dispatch_authority==="NONE" && state.pairing_authority==="NONE" &&
    typeof state.worker_id==="string"&&WORKER.test(state.worker_id) &&
    typeof state.proposal_sha256==="string"&&HEX.test(state.proposal_sha256) &&
    Number.isSafeInteger(state.expires_at_ms);
  return exact(state,"display,proposal_sha256,public_key,resources,state,worker_id") &&
    state.state==="PREPARED_PROPOSAL_OBSERVED" &&
    typeof state.worker_id==="string"&&WORKER.test(state.worker_id) &&
    typeof state.proposal_sha256==="string"&&HEX.test(state.proposal_sha256);
}
function safeResponse(reply,kind){
  if(!exact(reply,kind==="stage"
    ?"ack_signature,dispatch_authority,expires_at_ms,pairing_authority,proposal_sha256,state,worker_id"
    :"ack_signature,display,proposal_sha256,public_key,resources,state,worker_id"))return null;
  const {ack_signature,...out}=reply;
  return typeof ack_signature==="string"&&HEX.test(ack_signature)&&responseOk(out,kind)
    ?{out,ack_signature}:null;
}
function replyMessage(kind,id,nonce,expiry,subject,result){
  return JSON.stringify([AUD,"ack",kind,id,nonce,expiry,subject,result]);
}
async function authorizedSender({env,executionCtx,readAssignments,cryptoImpl,clock}) {
  if(!flags(env))return blocked("PREPARATION_LOCKED");
  const key=keyBytes(env?.BKE_PAIRING_RPC_KEY_B64);
  if(!key||typeof readAssignments!=="function" ||
    typeof cryptoImpl?.subtle?.sign!=="function" ||
    typeof cryptoImpl?.getRandomValues!=="function")
    return blocked("PREPARATION_ADAPTER_INVALID");
  if(await inspectAdminRuntimeAccess(executionCtx,env)!=="AUTHORIZED")
    return blocked("PREPARATION_ADMIN_DENIED");
  const subject=await humanSubject(env,executionCtx,key,cryptoImpl.subtle);
  if(!subject)return blocked("PREPARATION_ADMIN_DENIED");
  let snapshot;
  try{snapshot=await readAssignments(env,executionCtx);}
  catch{return blocked("PREPARATION_GITHUB_UNAVAILABLE");}
  const id=trustedInstallation(snapshot);
  if(!id)return blocked("PREPARATION_GITHUB_AMBIGUOUS");
  const now=nowMs(clock);
  if(now===null)return blocked("PREPARATION_CLOCK_INVALID");
  const namespace=env?.BKE_WORKER_PAIRING_VAULT;
  if(typeof namespace?.idFromName!=="function"||typeof namespace?.get!=="function")
    return blocked("PREPARATION_NAMESPACE_UNAVAILABLE");
  return {id,now,subject,key,namespace};
}
async function dispatch({env,executionCtx,kind,payload,readAssignments,cryptoImpl,clock}){
  const auth=await authorizedSender({env,executionCtx,readAssignments,cryptoImpl,clock});
  if(auth?.state==="BLOCKED")return auth;
  let nonce,signature;
  const expiry=auth.now+COMMAND_TTL;
  try{
    const random=new Uint8Array(32);cryptoImpl.getRandomValues(random);nonce=hex(random);
    signature=await mac(auth.key,envelope(kind,auth.id,nonce,expiry,auth.subject,payload),cryptoImpl.subtle);
  }catch{return blocked("PREPARATION_CRYPTO_UNAVAILABLE");}
  let response;
  try{
    const stub=auth.namespace.get(auth.namespace.idFromName("installation:"+auth.id));
    if(typeof stub?.managePreparedDeviceProposal!=="function")
      return blocked("PREPARATION_METHOD_UNAVAILABLE");
    response=await stub.managePreparedDeviceProposal({
      purpose:PURPOSE,kind,installation_id:auth.id,
      expires_at_ms:expiry,nonce,subject_sha256:auth.subject,
      payload,signature,
    });
  }catch{return blocked("PREPARATION_OUTCOME_UNCERTAIN");}
  if(response?.state==="BLOCKED")return blocked("PREPARATION_DENIED");
  const reply=safeResponse(response,kind);
  if(!reply)return blocked("PREPARATION_OUTCOME_UNCERTAIN");
  let expected;
  try{expected=await mac(auth.key,replyMessage(kind,auth.id,nonce,expiry,auth.subject,
      reply.out),cryptoImpl.subtle);}
  catch{return blocked("PREPARATION_OUTCOME_UNCERTAIN");}
  if(!equal(expected,reply.ack_signature))return blocked("PREPARATION_OUTCOME_UNCERTAIN");
  if(kind==="stage"){
    if(reply.out.proposal_sha256!==payload.offer.proposal_sha256 ||
      reply.out.worker_id!==payload.offer.worker_id)
      return blocked("PREPARATION_OUTCOME_UNCERTAIN");
  }else{
    const recomputed=await normalizeOffer({
      worker_id:reply.out.worker_id,public_key:reply.out.public_key,
      resources:reply.out.resources,display:reply.out.display,
    },auth.id,cryptoImpl);
    if(!recomputed||recomputed.proposal_sha256!==reply.out.proposal_sha256)
      return blocked("PREPARATION_OUTCOME_UNCERTAIN");
  }
  return Object.freeze({...reply.out});
}
// Source-only. The bridge must be created by a separately certified native
// messaging/device-ingress transport. It supplies a private signer FUNCTION,
// not serializable JSON or a fabricated "device_authenticated" boolean.
export async function stageDeviceOriginProposal({
  env,executionCtx,deviceBridge,describeResources,readAssignments=readAdminWorkerAssignments,
  cryptoImpl=crypto,clock=()=>Date.now(),
}={}){
  if(!flags(env))return blocked("PREPARATION_LOCKED");
  if(typeof describeResources!=="function")return blocked("PREPARATION_DISPLAY_AUTHORITY_REQUIRED");
  if(typeof deviceBridge?.readCandidate!=="function")
    return blocked("PREPARATION_DEVICE_BRIDGE_REQUIRED");
  // Authenticate human and determine authoritative installation before
  // soliciting a device-key proof. A failure never calls the device bridge.
  const auth=await authorizedSender({env,executionCtx,readAssignments,cryptoImpl,clock});
  if(auth?.state==="BLOCKED")return auth;
  let raw;
  try{raw=await deviceBridge.readCandidate();}
  catch{return blocked("PREPARATION_DEVICE_UNAVAILABLE");}
  if(!exact(raw,"display,public_key,resources,signChallenge,worker_id") ||
    typeof raw.signChallenge!=="function")
    return blocked("PREPARATION_DEVICE_INVALID");
  const offer=await normalizeOffer({
    worker_id:raw.worker_id,public_key:raw.public_key,
    resources:raw.resources,display:raw.display,
  },auth.id,cryptoImpl);
  if(!offer)return blocked("PREPARATION_DEVICE_INVALID");
  const nonce=new Uint8Array(32);
  let proof_nonce,device_signature;
  const expires_at_ms=auth.now+COMMAND_TTL;
  try{
    cryptoImpl.getRandomValues(nonce);proof_nonce=hex(nonce);
    const message=deviceMessage(auth.id,auth.subject,offer,proof_nonce,expires_at_ms);
    device_signature=await raw.signChallenge(message);
  }catch{return blocked("PREPARATION_DEVICE_PROOF_UNAVAILABLE");}
  if(!await verifyProof(offer,auth.id,auth.subject,proof_nonce,expires_at_ms,device_signature,cryptoImpl))
    return blocked("PREPARATION_DEVICE_PROOF_INVALID");
  // dispatch does a fresh human/installation read. Reject if the installation
  // changed between signing and RPC; no ambiguous cross-tenant delivery.
  const sender=await authorizedSender({env,executionCtx,readAssignments,cryptoImpl,clock});
  if(sender?.state==="BLOCKED")return sender;
  if(sender.id!==auth.id||sender.subject!==auth.subject)
    return blocked("PREPARATION_SCOPE_CHANGED");
  return dispatch({env,executionCtx,kind:"stage",payload:{
    offer,proof_nonce,device_signature,device_expires_at_ms:expires_at_ms,
  },readAssignments,cryptoImpl,clock});
}
// Browser-safe offer source for the existing #54 server-only injection seam.
// It never consumes browser JSON, tenant IDs, or caller-supplied fingerprints.
export async function loadPreparedDeviceProposal({
  env,executionCtx,readAssignments=readAdminWorkerAssignments,
  cryptoImpl=crypto,clock=()=>Date.now(),
}={}){
  const result=await dispatch({env,executionCtx,kind:"read",payload:null,
    readAssignments,cryptoImpl,clock});
  if(result?.state!=="PREPARED_PROPOSAL_OBSERVED")return null;
  return Object.freeze({
    worker_id:result.worker_id,public_key:result.public_key,
    resources:result.resources,display:result.display,
  });
}
export function createAdminPreparedProposalServer({
  readAssignments=readAdminWorkerAssignments,cryptoImpl=crypto,clock=()=>Date.now(),
}={}){
  // No browser-controlled runtime overrides. This object is handed to the
  // #54 review handler only by trusted server source, never via HTTP JSON.
  return Object.freeze({
    loadPreparedProposal:async(executionCtx,env)=>{
      const offer=await loadPreparedDeviceProposal({env,executionCtx,
        readAssignments,cryptoImpl,clock});
      if(!offer)throw Error("PREPARED_PROPOSAL_NOT_AVAILABLE");
      return offer;
    },
    rpcOverrides:Object.freeze({readAssignments,cryptoImpl,clock}),
  });
}
function commandShape(command){
  return exact(command,"expires_at_ms,installation_id,kind,nonce,payload,purpose,signature,subject_sha256") &&
    command.purpose===PURPOSE&&["stage","read"].includes(command.kind) &&
    typeof command.installation_id==="string"&&INSTALL.test(command.installation_id)&&
    typeof command.nonce==="string"&&HEX.test(command.nonce)&&
    typeof command.signature==="string"&&HEX.test(command.signature)&&
    typeof command.subject_sha256==="string"&&HEX.test(command.subject_sha256)&&
    Number.isSafeInteger(command.expires_at_ms)&&
    (command.kind==="read"?command.payload===null:
      exact(command.payload,"device_expires_at_ms,device_signature,offer,proof_nonce") &&
      Number.isSafeInteger(command.payload.device_expires_at_ms) &&
      typeof command.payload.proof_nonce==="string"&&HEX.test(command.payload.proof_nonce) &&
      typeof command.payload.device_signature==="string"&&!!sigBytes(command.payload.device_signature) &&
      exact(command.payload.offer,"display,identity_public_key_sha256,proposal_sha256,public_key,resources,worker_id"));
}
// Called ONLY inside the private installation-scoped DO named RPC.
export async function receivePreparedDeviceProposal({
  command,env,objectId,store,cryptoImpl=crypto,clock=()=>Date.now(),
}={}){
  if(!flags(env))return blocked("PREPARATION_LOCKED");
  if(!commandShape(command)||typeof objectId?.toString!=="function"||
    typeof env?.BKE_WORKER_PAIRING_VAULT?.idFromName!=="function"||
    typeof store?.atomic!=="function")return blocked("PREPARATION_REQUEST_REJECTED");
  const key=keyBytes(env.BKE_PAIRING_RPC_KEY_B64),now=nowMs(clock);
  if(!key||now===null||command.expires_at_ms<=now||
    command.expires_at_ms>now+COMMAND_TTL)return blocked("PREPARATION_REQUEST_REJECTED");
  try{
    const expectedId=env.BKE_WORKER_PAIRING_VAULT.idFromName("installation:"+command.installation_id);
    if(expectedId?.toString()!==objectId.toString())return blocked("PREPARATION_INSTALLATION_MISMATCH");
    const expected=await mac(key,envelope(command.kind,command.installation_id,
      command.nonce,command.expires_at_ms,command.subject_sha256,command.payload),cryptoImpl.subtle);
    if(!equal(expected,command.signature))return blocked("PREPARATION_REQUEST_REJECTED");
  }catch{return blocked("PREPARATION_REQUEST_REJECTED");}
  const id=command.installation_id;
  let offer;
  if(command.kind==="stage"){
    offer=await normalizeOffer({
      worker_id:command.payload.offer.worker_id,
      public_key:command.payload.offer.public_key,
      resources:command.payload.offer.resources,
      display:command.payload.offer.display,
    },id,cryptoImpl);
    if(!offer||JSON.stringify(offer)!==JSON.stringify(command.payload.offer))
      return blocked("PREPARATION_PROPOSAL_CHANGED");
    if(command.payload.device_expires_at_ms<=now ||
      command.payload.device_expires_at_ms>now+COMMAND_TTL)
      return blocked("PREPARATION_DEVICE_PROOF_EXPIRED");
    if(!await verifyProof(offer,id,command.subject_sha256,
      command.payload.proof_nonce,command.payload.device_expires_at_ms,
      command.payload.device_signature,cryptoImpl))
      return blocked("PREPARATION_DEVICE_PROOF_INVALID");
  }
  const broker=env?.BKE_GITHUB_READ_BROKER?.listVerifiedWorkerAssignments;
  if(typeof broker!=="function")return blocked("PREPARATION_BROKER_UNAVAILABLE");
  let snapshot;
  try{snapshot=parseTrustedWorkerAssignmentPayload(await env.BKE_GITHUB_READ_BROKER
    .listVerifiedWorkerAssignments(BROKER_PURPOSE));}
  catch{return blocked("PREPARATION_GITHUB_UNAVAILABLE");}
  if(trustedInstallation(snapshot)!==id)return blocked("PREPARATION_INSTALLATION_MISMATCH");
  let output;
  try{
    output=await store.atomic(async tx=>{
      const prepared=(await tx.get("prepared"))??[];
      if(!validPreparedRows(prepared))return blocked("PREPARATION_REGISTRY_AMBIGUOUS");
      const active=prepared.filter(r=>r.expires_at_ms>now);
      // Never guess which proposal the human meant when multiple are present.
      if(active.length>1)return blocked("PREPARATION_AMBIGUOUS");
      const paired=(await tx.get("paired"))??[],pending=(await tx.get("pending"))??[];
      if(!isSafePairedRegistry(paired)||!isSafePendingChallenges(pending))
        return blocked("PREPARATION_REGISTRY_AMBIGUOUS");
      if(command.kind==="read"){
        if(active.length!==1)return blocked("PREPARATION_NOT_AVAILABLE");
        const current=active[0];
        const canonical=await normalizeOffer({
          worker_id:current.worker_id,public_key:current.public_key,
          resources:current.resources,display:current.display,
        },id,cryptoImpl);
        if(!canonical || canonical.proposal_sha256!==current.proposal_sha256 ||
          canonical.identity_public_key_sha256!==current.identity_public_key_sha256 ||
          current.subject_sha256!==command.subject_sha256 ||
          snapshot.worker_claims.some(x=>x.worker_id===current.worker_id) ||
          conflictWith(paired,current) ||
          conflictWith(pending.filter(r=>r.expires_at_ms>now),current))
          return blocked("PREPARATION_STALE_OR_CONFLICTED");
        return Object.freeze({
          state:"PREPARED_PROPOSAL_OBSERVED",
          worker_id:current.worker_id,public_key:current.public_key,
          resources:current.resources,display:current.display,
          proposal_sha256:current.proposal_sha256,
        });
      }
      if(active.length!==0)return blocked("PREPARATION_ALREADY_PENDING");
      if(snapshot.worker_claims.some(x=>x.worker_id===offer.worker_id))
        return blocked("PREPARATION_WORKER_ALREADY_ASSIGNED");
      if(conflictWith(paired,offer)||
        conflictWith(pending.filter(r=>r.expires_at_ms>now),offer))
        return blocked("PREPARATION_RESOURCE_CONFLICT");
      const consents=(await tx.get("consents"))??[];
      if(!Array.isArray(consents)||consents.length>100 ||
        consents.some(c=>typeof c?.worker_id!=="string" ||
          !WORKER.test(c.worker_id)||!Number.isSafeInteger(c.expires_at_ms)))
        return blocked("PREPARATION_CONSENT_REGISTRY_AMBIGUOUS");
      if(consents.some(c=>c.worker_id===offer.worker_id&&c.expires_at_ms>now))
        return blocked("PREPARATION_CONSENT_CONFLICT");
      await tx.put("prepared",[...active,{
        worker_id:offer.worker_id,public_key:offer.public_key,
        resources:offer.resources,display:offer.display,
        proposal_sha256:offer.proposal_sha256,
        identity_public_key_sha256:offer.identity_public_key_sha256,
        proof_nonce:command.payload.proof_nonce,
        subject_sha256:command.subject_sha256,
        expires_at_ms:now+PREPARED_TTL,
      }]);
      return Object.freeze({
        state:"PREPARED_FOR_HUMAN_REVIEW",worker_id:offer.worker_id,
        proposal_sha256:offer.proposal_sha256,expires_at_ms:now+PREPARED_TTL,
        pairing_authority:"NONE",dispatch_authority:"NONE",
      });
    });
  }catch{return blocked("PREPARATION_STORAGE_UNAVAILABLE");}
  if(output?.state==="BLOCKED")return output;
  try {
    const ack_signature=await mac(key,replyMessage(command.kind,id,command.nonce,
      command.expires_at_ms,command.subject_sha256,output),cryptoImpl.subtle);
    return Object.freeze({...output,ack_signature});
  }catch{return blocked("PREPARATION_OUTCOME_UNCERTAIN");}
}
