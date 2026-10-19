// DORMANT Admin proposal consent contract. No public HTTP route imports this.
// Browser may see only an opaque challenge + exact proposal digest; human
// approval is NOT an invitation, pairing operation or worker lease.
import { inspectAdminRuntimeAccess } from "./admin-access.js";
const ORIGIN = "https://cc.jl-bke.com";
const PATH = "/api/admin/pairing/confirm-proposal";
const WORKER = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const H64 = /^[a-f0-9]{64}$/u;
const TTL_MS = 60_000;
const LIMIT = 100;
const blocked = code => Object.freeze({ state: "BLOCKED", code });
const fields = (obj, names) => obj && typeof obj === "object" &&
  !Array.isArray(obj) && Object.keys(obj).sort().join(",") === names;
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2,"0")).join("");
function safeRows(rows) {
  if (!Array.isArray(rows) || rows.length > LIMIT) return false;
  const ids = new Set();
  for (const r of rows) {
    if (!fields(r,"challenge_id,expires_at_ms,proposal_sha256,status,subject_sha256,worker_id") ||
        typeof r.challenge_id !== "string" || !H64.test(r.challenge_id) ||
        typeof r.proposal_sha256 !== "string" || !H64.test(r.proposal_sha256) ||
        typeof r.subject_sha256 !== "string" || !H64.test(r.subject_sha256) ||
        typeof r.worker_id !== "string" || !WORKER.test(r.worker_id) ||
        !Number.isSafeInteger(r.expires_at_ms) || r.expires_at_ms < 0 ||
        !["PENDING","CONFIRMED","CONSUMED"].includes(r.status) ||
        ids.has(r.challenge_id)) return false;
    ids.add(r.challenge_id);
  }
  return true;
}
async function boundedBody(req) {
  if (!req.body || typeof req.body.getReader !== "function") return null;
  const reader=req.body.getReader(), chunks=[];
  let size=0;
  try {
    while (true) {
      const {done,value}=await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array) || (size+=value.byteLength)>1024) {
        await reader.cancel().catch(()=>{});
        return null;
      }
      chunks.push(value);
    }
    if (size===0) return null;
    const bytes=new Uint8Array(size);
    let offset=0;
    for (const chunk of chunks) { bytes.set(chunk,offset); offset+=chunk.length; }
    return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
  } catch { return null; }
  finally { try { reader.releaseLock(); } catch { /* reader aborted */ } }
}
function time(clock) {
  try {
    const n=clock();
    return Number.isSafeInteger(n) && n >= 0 && n<=Number.MAX_SAFE_INTEGER-TTL_MS ? n : null;
  } catch { return null; }
}
function flags(env) {
  return env?.BKE_PREPRODUCTION==="true" &&
    env?.BKE_ACCESS_POLICY_VERIFIED==="true" &&
    env?.BKE_ADMIN_PAIRING_ACTIONS_ENABLED==="true" &&
    env?.BKE_ADMIN_PROPOSAL_CONSENT_ENABLED==="true";
}
function requestSafe(req) {
  if (!(req instanceof Request) || req.method!=="POST") return false;
  let u;
  try { u=new URL(req.url); } catch { return false; }
  if (u.origin!==ORIGIN || u.pathname!==PATH || u.search || u.hash ||
      u.username || u.password) return false;
  const h=req.headers;
  return h.get("origin")===ORIGIN &&
    h.get("sec-fetch-site")==="same-origin" &&
    ["cors","same-origin"].includes(h.get("sec-fetch-mode")) &&
    h.get("content-type")==="application/json" &&
    h.get("x-bke-admin-action")==="pair" &&
    !h.has("content-encoding") &&
    (!h.has("content-length") ||
      (/^[0-9]{1,6}$/u.test(h.get("content-length")) &&
       Number(h.get("content-length"))<=1024));
}
// Caller MUST derive subject from a platform-verified human identity with
// server-owned HMAC key using the same subject domain as #48's pairing RPC.
// Never trust a submitted email, browser role or authorized=true field.
export function createAdminProposalConsent({
  store, authorizeSubject, cryptoImpl=crypto, clock=()=>Date.now(),
}={}) {
  if (typeof store?.atomic!=="function" || typeof authorizeSubject!=="function" ||
      typeof cryptoImpl?.getRandomValues!=="function" || typeof clock!=="function")
    throw Error("ADMIN_CONSENT_ADAPTER_INVALID");
  async function subject(ctx,env,worker,proposal) {
    if (await inspectAdminRuntimeAccess(ctx,env)!=="AUTHORIZED") return null;
    try {
      const s=await authorizeSubject("pair",worker,proposal,ctx,env);
      return typeof s==="string" && H64.test(s) ? s : null;
    } catch { return null; }
  }
  async function present({worker_id,proposal_sha256,env,executionCtx}={}) {
    if(!flags(env))return blocked("CONSENT_LOCKED");
    if(typeof worker_id!=="string" || !WORKER.test(worker_id) ||
        typeof proposal_sha256!=="string" || !H64.test(proposal_sha256))
      return blocked("CONSENT_INPUT_INVALID");
    const who=await subject(executionCtx,env,worker_id,proposal_sha256);
    if(!who)return blocked("CONSENT_ADMIN_DENIED");
    const now=time(clock);
    if(now===null)return blocked("CONSENT_CLOCK_INVALID");
    let id;
    try {
      const random=new Uint8Array(32);
      cryptoImpl.getRandomValues(random);
      id=hex(random);
    } catch {return blocked("CONSENT_RANDOM_UNAVAILABLE");}
    try {
      return await store.atomic(async tx=>{
        const all=(await tx.get("consents"))??[];
        if(!safeRows(all))return blocked("CONSENT_REGISTRY_AMBIGUOUS");
        const live=all.filter(r=>r.expires_at_ms>now);
        if(live.length>=LIMIT || live.some(r=>r.challenge_id===id ||
          (r.worker_id===worker_id && r.status!=="CONSUMED")))
          return blocked("CONSENT_ALREADY_PENDING");
        await tx.put("consents",[...live,{
          challenge_id:id,expires_at_ms:now+TTL_MS,
          worker_id,proposal_sha256,subject_sha256:who,status:"PENDING",
        }]);
        return Object.freeze({
          state:"AWAITING_EXPLICIT_HUMAN_CONFIRMATION",
          challenge_id:id,worker_id,proposal_sha256,
          expires_at_ms:now+TTL_MS,
          pairing_authority:"NONE",dispatch_authority:"NONE",
        });
      });
    } catch {return blocked("CONSENT_STORAGE_UNAVAILABLE");}
  }
  async function confirm({request,env,executionCtx}={}) {
    if(!flags(env))return blocked("CONSENT_LOCKED");
    if(!requestSafe(request))return blocked("CONSENT_REQUEST_REJECTED");
    if(await inspectAdminRuntimeAccess(executionCtx,env)!=="AUTHORIZED")
      return blocked("CONSENT_ADMIN_DENIED");
    const data=await boundedBody(request);
    if(!fields(data,"action,challenge_id,confirm_worker_id,proposal_sha256,worker_id") ||
        data.action!=="pair" ||
        typeof data.worker_id!=="string" || !WORKER.test(data.worker_id) ||
        data.confirm_worker_id!==data.worker_id ||
        typeof data.challenge_id!=="string" || !H64.test(data.challenge_id) ||
        typeof data.proposal_sha256!=="string" || !H64.test(data.proposal_sha256))
      return blocked("CONSENT_INTENT_INVALID");
    const who=await subject(executionCtx,env,data.worker_id,data.proposal_sha256);
    if(!who)return blocked("CONSENT_ADMIN_DENIED");
    const now=time(clock);
    if(now===null)return blocked("CONSENT_CLOCK_INVALID");
    try {
      return await store.atomic(async tx=>{
        const all=(await tx.get("consents"))??[];
        if(!safeRows(all))return blocked("CONSENT_REGISTRY_AMBIGUOUS");
        const record=all.find(r=>r.challenge_id===data.challenge_id);
        if(!record || record.status!=="PENDING" ||
           record.expires_at_ms<=now ||
           record.worker_id!==data.worker_id ||
           record.proposal_sha256!==data.proposal_sha256 ||
           record.subject_sha256!==who)
          return blocked("CONSENT_MISSING_OR_USED");
        await tx.put("consents",all.map(r=>r.challenge_id===data.challenge_id ?
          {...r,status:"CONFIRMED"}:r));
        return Object.freeze({
          state:"CONFIRMED_FOR_ATOMIC_ISSUANCE",
          challenge_id:data.challenge_id,worker_id:data.worker_id,
          proposal_sha256:data.proposal_sha256,
          pairing_authority:"NONE",dispatch_authority:"NONE",
        });
      });
    } catch {return blocked("CONSENT_STORAGE_UNAVAILABLE");}
  }
  // IMPORTANT: Invoke only INSIDE the later pairing invitation's SAME tx.
  // Never consume in a separate tx: orphaned approvals after a failed issue
  // violate the all-or-nothing issuance goal.
  async function consumeInTransaction(tx,{
    challenge_id,worker_id,proposal_sha256,subject_sha256,
  }={}) {
    if(typeof tx?.get!=="function" || typeof tx?.put!=="function" ||
       typeof challenge_id!=="string" || !H64.test(challenge_id) ||
       typeof worker_id!=="string" || !WORKER.test(worker_id) ||
       typeof proposal_sha256!=="string" || !H64.test(proposal_sha256) ||
       typeof subject_sha256!=="string" || !H64.test(subject_sha256))
      return blocked("CONSENT_INPUT_INVALID");
    const now=time(clock);
    if(now===null)return blocked("CONSENT_CLOCK_INVALID");
    const all=(await tx.get("consents"))??[];
    if(!safeRows(all))return blocked("CONSENT_REGISTRY_AMBIGUOUS");
    const record=all.find(r=>r.challenge_id===challenge_id);
    if(!record || record.status!=="CONFIRMED" ||
        record.worker_id!==worker_id ||
        record.proposal_sha256!==proposal_sha256 ||
        record.subject_sha256!==subject_sha256 ||
        record.expires_at_ms<=now)
      return blocked("CONSENT_MISSING_OR_USED");
    await tx.put("consents",all.map(r=>r.challenge_id===challenge_id ?
      {...r,status:"CONSUMED"}:r));
    return Object.freeze({state:"CONSENT_CONSUMED_IN_TRANSACTION"});
  }
  return Object.freeze({present,confirm,consumeInTransaction});
}
