// Dormant PREPRODUCTION server-to-installation-DO invitation RPC.
// NEVER expose this sender through an HTTP route. Its private result callback
// receives the raw one-use human ticket; the return value NEVER contains it.
import { inspectAdminRuntimeAccess } from "./admin-access.js";
import { readAdminWorkerAssignments, parseTrustedWorkerAssignmentPayload } from "./admin-worker-assignments.js";
import { computePairingProposalSha256, createAtomicPairingInvitation } from "./admin-atomic-pairing-invitation.js";
import { createAdminProposalConsent } from "./admin-pairing-proposal-consent.js";

const AUD="bke-command-center/preproduction/issue-atomic-pairing-invitation/v1";
const SUBJECT_AUD="bke-command-center/preproduction/execute-protected-inactive-pairing/v1";
const PURPOSE="atomic_pairing_invitation_v1";
const BROKER_PURPOSE=Object.freeze({purpose:"admin_worker_assignment_inventory"});
const INSTALL=/^[1-9][0-9]{0,19}$/u;
const WORKER=/^[a-z0-9][a-z0-9-]{0,62}$/u;
const H64=/^[a-f0-9]{64}$/u;
const H48=/^[a-f0-9]{48}$/u;
const H32=/^[a-f0-9]{32}$/u;
const KEY_B64=/^[A-Za-z0-9_-]{43}$/u;
const TTL=30_000;
const RESOURCE=["chatgpt_target_sha256","browser_profile_sha256","bridge_identity_sha256"];
const blocked=code=>Object.freeze({state:"BLOCKED",code});
const exact=(v,k)=>v && typeof v==="object" && !Array.isArray(v) &&
  Object.keys(v).sort().join(",")===k;
const hex=b=>Array.from(b,n=>n.toString(16).padStart(2,"0")).join("");
const bytes=s=>new TextEncoder().encode(s);
function keyBytes(input) {
  if(typeof input!=="string" || !KEY_B64.test(input))return null;
  try {
    const binary=atob(input.replaceAll("-","+").replaceAll("_","/")+"=");
    if(binary.length!==32 ||
       btoa(binary).replaceAll("+","-").replaceAll("/","_").replace(/=+$/u,"")!==input)
      return null;
    return Uint8Array.from(binary,ch=>ch.charCodeAt(0));
  } catch {return null;}
}
async function mac(key,message,subtle) {
  const imported=await subtle.importKey("raw",key,
    {name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return hex(new Uint8Array(await subtle.sign("HMAC",imported,bytes(message))));
}
function constantEqual(a,b) {
  if(typeof a!=="string" || typeof b!=="string" || !H64.test(a) || !H64.test(b))return false;
  let xor=0;
  for(let i=0;i<64;i++)xor|=a.charCodeAt(i)^b.charCodeAt(i);
  return xor===0;
}
function enabled(env) {
  return env?.BKE_PREPRODUCTION==="true" &&
    env?.BKE_ACCESS_POLICY_VERIFIED==="true" &&
    env?.BKE_ADMIN_PR_INVENTORY_ENABLED==="true" &&
    env?.BKE_ADMIN_PAIRING_ACTIONS_ENABLED==="true" &&
    env?.BKE_ADMIN_DO_ROUTING_ENABLED==="true" &&
    env?.BKE_ADMIN_PROTECTED_PAIRING_ENABLED==="true" &&
    env?.BKE_ADMIN_PAIRING_ISSUANCE_ENABLED==="true" &&
    env?.BKE_ADMIN_PROPOSAL_CONSENT_ENABLED==="true" &&
    env?.BKE_ADMIN_INVITATION_RPC_ENABLED==="true";
}
function nowMs(clock) {
  try {
    const n=clock();
    return Number.isSafeInteger(n) && n>0 && n<Number.MAX_SAFE_INTEGER-TTL ? n:null;
  }catch{return null;}
}
function trustedInstall(snapshot) {
  return snapshot?.state==="OBSERVED_ONLY" &&
    snapshot?.source==="GITHUB_APP_INSTALLATION" &&
    snapshot?.consistency==="NON_ATOMIC_ENUMERATION" &&
    snapshot?.dispatch_authority==="NONE" &&
    Array.isArray(snapshot?.worker_claims) &&
    typeof snapshot?.trusted_installation_id==="string" &&
    INSTALL.test(snapshot.trusted_installation_id)
    ? snapshot.trusted_installation_id : null;
}
function canonicalProof(input,installationId,cryptoImpl) {
  // Validity is completed in normalizeProof (async P-256 import).
  if(!exact(input,"consent_challenge_id,public_key,resources,worker_id") ||
     typeof input.worker_id!=="string" || !WORKER.test(input.worker_id) ||
     typeof input.consent_challenge_id!=="string" || !H64.test(input.consent_challenge_id) ||
     typeof installationId!=="string" || !INSTALL.test(installationId) ||
     !exact(input.resources,RESOURCE.slice().sort().join(",")) ||
     !RESOURCE.every(k=>typeof input.resources[k]==="string" && H64.test(input.resources[k])))
    return null;
  return {worker_id:input.worker_id,public_key:input.public_key,
    resources:Object.fromEntries(RESOURCE.map(k=>[k,input.resources[k]])),
    consent_challenge_id:input.consent_challenge_id};
}
async function normalizeProof(input,installationId,cryptoImpl) {
  const prelim=canonicalProof(input,installationId,cryptoImpl);
  if(!prelim)return null;
  const proposal=await computePairingProposalSha256({
    installationId,workerId:prelim.worker_id,publicKey:prelim.public_key,
    resources:prelim.resources,cryptoImpl,
  });
  if(!proposal)return null;
  return Object.freeze({
    worker_id:prelim.worker_id,public_key:proposal.key,
    resources:proposal.resources,consent_challenge_id:prelim.consent_challenge_id,
    proposal_sha256:proposal.proposalHash,
  });
}
function seal(installationId,nonce,expiry,subject,proof) {
  return JSON.stringify([AUD,PURPOSE,installationId,nonce,expiry,subject,proof]);
}
function verifiedProofShape(proof) {
  return exact(proof,"consent_challenge_id,proposal_sha256,public_key,resources,worker_id") &&
    typeof proof.proposal_sha256==="string" && H64.test(proof.proposal_sha256) &&
    !!canonicalProof({
      worker_id:proof.worker_id,public_key:proof.public_key,
      resources:proof.resources,consent_challenge_id:proof.consent_challenge_id,
    }, "1");
}
// Human subject MUST match the existing protected inactive-pairing finalizer.
// Both use a separate keyed domain from invitation HMAC, never a raw email hash.
async function platformSubject(env,executionCtx,key,subtle) {
  try {
    const identity=await executionCtx?.access?.getIdentity?.();
    const email=identity?.email?.trim?.().toLowerCase();
    const allowed=String(env.BKE_ADMIN_EMAILS).split(",").map(s=>s.trim().toLowerCase());
    if(!email || !allowed.includes(email))return null;
    return await mac(key,JSON.stringify([
      SUBJECT_AUD,"human-subject",env.BKE_ADMIN_ACCESS_AUD,email,
    ]),subtle);
  }catch{return null;}
}

// This sender is server-only. The onPrivateIssued callback MUST remain within
// trusted server code; it is the only recipient of the raw one-use nonce.
// Crash/uncertain callback delivery fails closed and MUST NOT replay consent.
export async function sendAdminPairingInvitation({
  env,executionCtx,proposal,onPrivateIssued,
  readAssignments=readAdminWorkerAssignments,
  cryptoImpl=crypto,clock=()=>Date.now(),
}={}) {
  if(!enabled(env))return blocked("INVITE_RPC_LOCKED");
  const key=keyBytes(env?.BKE_PAIRING_RPC_KEY_B64);
  if(!key || typeof onPrivateIssued!=="function" ||
     typeof readAssignments!=="function" ||
     typeof cryptoImpl?.subtle?.sign!=="function" ||
     typeof cryptoImpl?.getRandomValues!=="function")
    return blocked("INVITE_RPC_ADAPTER_INVALID");
  if(await inspectAdminRuntimeAccess(executionCtx,env)!=="AUTHORIZED")
    return blocked("INVITE_RPC_ADMIN_DENIED");
  const subject=await platformSubject(env,executionCtx,key,cryptoImpl.subtle);
  if(!subject)return blocked("INVITE_RPC_ADMIN_DENIED");
  let snapshot;
  try {snapshot=await readAssignments(env,executionCtx);}
  catch{return blocked("INVITE_RPC_GITHUB_UNAVAILABLE");}
  const installationId=trustedInstall(snapshot);
  if(!installationId)return blocked("INVITE_RPC_GITHUB_AMBIGUOUS");
  const proof=await normalizeProof(proposal,installationId,cryptoImpl);
  if(!proof)return blocked("INVITE_RPC_PROPOSAL_INVALID");
  const ns=env?.BKE_WORKER_PAIRING_VAULT;
  if(typeof ns?.idFromName!=="function" || typeof ns?.get!=="function")
    return blocked("INVITE_RPC_NAMESPACE_UNAVAILABLE");
  const now=nowMs(clock);
  if(now===null)return blocked("INVITE_RPC_CLOCK_INVALID");
  let nonce,signature;
  const expires_at_ms=now+TTL;
  try {
    const random=new Uint8Array(32);
    cryptoImpl.getRandomValues(random);
    nonce=hex(random);
    signature=await mac(key,seal(installationId,nonce,expires_at_ms,subject,proof),
      cryptoImpl.subtle);
  }catch{return blocked("INVITE_RPC_CRYPTO_UNAVAILABLE");}
  let outcome;
  try {
    const target=ns.get(ns.idFromName("installation:"+installationId));
    if(typeof target?.issueAtomicPairingInvitation!=="function")
      return blocked("INVITE_RPC_METHOD_UNAVAILABLE");
    outcome=await target.issueAtomicPairingInvitation({
      purpose:PURPOSE,installation_id:installationId,expires_at_ms,
      nonce,subject_sha256:subject,proof,signature,
    });
  }catch{return blocked("INVITE_RPC_OUTCOME_UNCERTAIN");}
  if(exact(outcome,"code,state") && outcome.state==="BLOCKED" &&
     typeof outcome.code==="string" && /^INVIT(ATION|E_RPC)_[A-Z_]+$/u.test(outcome.code))
    return blocked("INVITE_RPC_ISSUANCE_DENIED");
  if(!exact(outcome,"device_challenge,dispatch_authority,human_ticket,pairing_authority,state,worker_id") ||
     outcome.state!=="ISSUED_FOR_SECURE_DELIVERY" ||
     outcome.worker_id!==proof.worker_id ||
     outcome.pairing_authority!=="NONE" || outcome.dispatch_authority!=="NONE" ||
     !exact(outcome.device_challenge,"challenge_id,expires_at_ms,message") ||
     !H48.test(outcome.device_challenge.challenge_id) ||
     typeof outcome.device_challenge.message!=="string" ||
     !Number.isSafeInteger(outcome.device_challenge.expires_at_ms) ||
     !exact(outcome.human_ticket,"challenge_id,expires_at_ms,one_time_nonce") ||
     !H32.test(outcome.human_ticket.challenge_id) ||
     !H64.test(outcome.human_ticket.one_time_nonce) ||
     !Number.isSafeInteger(outcome.human_ticket.expires_at_ms))
    return blocked("INVITE_RPC_OUTCOME_UNCERTAIN");
  // No full invitation in the public-facing return value. Deliver ONLY to
  // a local, private, explicitly provided server handler. Not an HTTP endpoint.
  try {await onPrivateIssued(outcome);}
  catch{return blocked("INVITE_RPC_OUTCOME_UNCERTAIN");}
  return Object.freeze({
    state:"ISSUED_FOR_PRIVATE_DELIVERY",worker_id:proof.worker_id,
    device_challenge_id:outcome.device_challenge.challenge_id,
    admin_challenge_id:outcome.human_ticket.challenge_id,
    pairing_authority:"NONE",dispatch_authority:"NONE",
  });
}

// Called only from the installation-scoped DO named RPC. A signed command
// does not impersonate a Cloudflare Access context: it creates a private
// in-process identity AFTER scope, HMAC, expiry and proposal verification.
export async function receiveAdminPairingInvitation({
  request,env,objectId,store,cryptoImpl=crypto,clock=()=>Date.now(),
}={}) {
  if(!enabled(env))return blocked("INVITE_RPC_LOCKED");
  if(!exact(request,"expires_at_ms,installation_id,nonce,proof,purpose,signature,subject_sha256") ||
     request.purpose!==PURPOSE ||
     typeof request.installation_id!=="string" || !INSTALL.test(request.installation_id) ||
     typeof request.nonce!=="string" || !H64.test(request.nonce) ||
     typeof request.signature!=="string" || !H64.test(request.signature) ||
     typeof request.subject_sha256!=="string" || !H64.test(request.subject_sha256) ||
     !Number.isSafeInteger(request.expires_at_ms) ||
     !verifiedProofShape(request.proof) ||
     typeof store?.atomic!=="function" ||
     typeof objectId?.toString!=="function" ||
     typeof env?.BKE_WORKER_PAIRING_VAULT?.idFromName!=="function")
    return blocked("INVITE_RPC_REQUEST_REJECTED");
  const key=keyBytes(env.BKE_PAIRING_RPC_KEY_B64);
  const now=nowMs(clock);
  if(!key || now===null || request.expires_at_ms<=now ||
     request.expires_at_ms>now+TTL)
    return blocked("INVITE_RPC_REQUEST_REJECTED");
  try {
    const scoped=env.BKE_WORKER_PAIRING_VAULT.idFromName(
      "installation:"+request.installation_id);
    if(scoped?.toString()!==objectId.toString())
      return blocked("INVITE_RPC_INSTALLATION_MISMATCH");
    const expected=await mac(key,seal(request.installation_id,request.nonce,
      request.expires_at_ms,request.subject_sha256,request.proof),cryptoImpl.subtle);
    if(!constantEqual(expected,request.signature))
      return blocked("INVITE_RPC_REQUEST_REJECTED");
    const canonical=await normalizeProof({
      worker_id:request.proof.worker_id,public_key:request.proof.public_key,
      resources:request.proof.resources,
      consent_challenge_id:request.proof.consent_challenge_id,
    },request.installation_id,cryptoImpl);
    if(!canonical || JSON.stringify(canonical)!==JSON.stringify(request.proof))
      return blocked("INVITE_RPC_PROPOSAL_CHANGED");
  }catch{return blocked("INVITE_RPC_REQUEST_REJECTED");}
  if(typeof env?.BKE_GITHUB_READ_BROKER?.listVerifiedWorkerAssignments!=="function")
    return blocked("INVITE_RPC_BROKER_UNAVAILABLE");
  const verified=Object.freeze({installation_id:request.installation_id,
    subject_sha256:request.subject_sha256});
  const readInstallationInventory=async()=>{
    const payload=await env.BKE_GITHUB_READ_BROKER.listVerifiedWorkerAssignments(
      BROKER_PURPOSE);
    const snapshot=parseTrustedWorkerAssignmentPayload(payload);
    if(snapshot.trusted_installation_id!==request.installation_id)
      throw Error("INTERNAL_INSTALLATION_MISMATCH");
    return payload;
  };
  // Do NOT create a second consent store or perform a separate consent
  // consumption. This original consent adapter is used ONLY for its tx method.
  const confirmedConsent=createAdminProposalConsent({
    store,cryptoImpl,clock,authorizeSubject:async()=>null,
  });
  const issuer=createAtomicPairingInvitation({
    store,installationId:request.installation_id,cryptoImpl,clock,
    confirmedConsent,readInstallationInventory,
    authorizeHumanAction:async(action,ctx)=>
      ctx===verified && action.action==="pair" &&
      action.worker_id===request.proof.worker_id &&
      action.installation_id===request.installation_id &&
      action.proposal_sha256===request.proof.proposal_sha256 &&
      JSON.stringify(action.resources)===JSON.stringify(request.proof.resources) &&
      action.identity_public_key_sha256===hex(new Uint8Array(
        await cryptoImpl.subtle.digest("SHA-256",
          bytes(JSON.stringify(request.proof.public_key)))))
        ? request.subject_sha256 : null,
  });
  try {
    return await issuer.issue({
      worker_id:request.proof.worker_id,public_key:request.proof.public_key,
      resources:request.proof.resources,
      consent_challenge_id:request.proof.consent_challenge_id,
      admin_context:verified,env,
    });
  }catch{return blocked("INVITE_RPC_OUTCOME_UNCERTAIN");}
}
