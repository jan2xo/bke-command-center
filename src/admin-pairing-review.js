// Human-facing, default-OFF source-only Admin proposal review controller.
// No external runtime calls it until a trusted server-only prepared-proposal
// supplier is separately wired. User input NEVER selects a DO or installation.
import { inspectAdminRuntimeAccess } from "./admin-access.js";
import { computePairingProposalSha256 } from "./admin-atomic-pairing-invitation.js";
import { sendAdminPairingConsent } from "./admin-pairing-review-rpc.js";

const PAGE="/admin/pairing/review", POST="/api/admin/pairing/confirm-proposal";
const ORIGIN="https://cc.jl-bke.com";
const safe=v=>String(v??"").replaceAll("&","&amp;").replaceAll("<","&lt;")
  .replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;");
const deny=(error,status)=>Response.json({error,state:"BLOCKED"},{
  status,headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff",
    "Referrer-Policy":"no-referrer"},
});
function locked(env){
  return env?.BKE_PREPRODUCTION!=="true" ||
    env?.BKE_ACCESS_POLICY_VERIFIED!=="true" ||
    env?.BKE_ADMIN_PAIRING_REVIEW_ENABLED!=="true" ||
    env?.BKE_ADMIN_PROPOSAL_CONSENT_ENABLED!=="true";
}
const DISPLAY=["chatgpt_target","browser_profile","bridge_identity"];
// Labels are server-authored descriptions, not cryptographic evidence. The
// actual immutable SHA-256 digests are always shown and approved.
function preparedShape(value){
  if(!value||typeof value!=="object"||Array.isArray(value)||
    Object.keys(value).sort().join(",")!=="display,public_key,resources,worker_id"||
    !value.display||typeof value.display!=="object"||Array.isArray(value.display)||
    Object.keys(value.display).sort().join(",")!==DISPLAY.slice().sort().join(","))
    return false;
  return DISPLAY.every(x=>typeof value.display[x]==="string" &&
    value.display[x].trim().length>0 && value.display[x].length<=160 &&
    !/[\u0000-\u001F\u007F]/u.test(value.display[x]));
}
function securityHeaders(scriptNonce){
  return {
    "Cache-Control":"no-store","Content-Type":"text/html; charset=utf-8",
    "X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer",
    "X-Frame-Options":"DENY","Cross-Origin-Resource-Policy":"same-origin",
    "Content-Security-Policy":"default-src 'none'; base-uri 'none'; object-src 'none'; "+
      "frame-ancestors 'none'; form-action 'self'; connect-src 'self'; "+
      "script-src 'nonce-"+scriptNonce+"'; style-src 'unsafe-inline'",
  };
}
function html(offer,record,nonce){
  const resources=offer.resources;
  const publicKeyHash=offer.identity_public_key_sha256;
  const lines=[
    ["ChatGPT target",offer.display.chatgpt_target,resources.chatgpt_target_sha256],
    ["Browser profile",offer.display.browser_profile,resources.browser_profile_sha256],
    ["Bridge identity",offer.display.bridge_identity,resources.bridge_identity_sha256],
  ];
  const row=([name,label,digest])=>"<tr><th>"+safe(name)+"</th><td>"+
    safe(label)+"<code>"+safe(digest)+"</code></td></tr>";
  // No JWT, email, installation number, Admin nonce or private action ticket
  // is sent to the browser. No human confirmation is automatic.
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'+
    '<meta name="viewport" content="width=device-width,initial-scale=1">'+
    '<title>Review worker pairing · BKE Admin</title>'+
    '<style>body{font:16px system-ui,sans-serif;max-width:840px;margin:32px auto;padding:0 18px;'+
    'background:#111c2c;color:#eef4ff}main{border:1px solid #3d526e;border-radius:16px;'+
    'padding:26px}h1{font-size:1.75rem}p{line-height:1.5}code{display:block;'+
    'overflow-wrap:anywhere;font-size:13px;color:#b7d9ff;padding:8px 0}'+
    'table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;'+
    'border-bottom:1px solid #435169;padding:12px}th{width:26%}input,button{font:inherit;'+
    'padding:10px;border-radius:8px}button{background:#a6c9ff;color:#081223;border:0;'+
    'font-weight:700;cursor:pointer}input{background:#0b1423;color:#fff;border:1px solid #7d8fad}'+
    'label{display:block;margin:18px 0 8px}.warning{color:#ffe0a0}'+
    '</style></head><body><main><h1>Review one worker pairing proposal</h1>'+
    '<p class="warning">Review carefully. The public device key has NOT yet proved possession. '+
    'This is a 60-second human approval, NOT device pairing, an active worker lease or GitHub PR claim.</p>'+
    '<h2>Identity and resources</h2><table><tbody>'+
    row(["Worker ID",offer.worker_id,offer.worker_id])+
    row(["P-256 public key SHA-256","Unverified presented device identity",publicKeyHash])+
    lines.map(row).join("")+'</tbody></table>'+
    '<p><strong>Exact immutable proposal SHA-256</strong><code id="digest">'+
    safe(record.proposal_sha256)+'</code></p>'+
    '<p>Approval expires 60 seconds after creation. Confirm by typing the exact worker ID. '+
    'A mismatch, replay, expiry or changed resource denies confirmation.</p>'+
    '<label for="worker">Confirm worker ID</label>'+
    '<input id="worker" aria-label="Confirm worker ID" autocomplete="off" maxlength="63" required>'+
    '<button type="button" id="confirm">Confirm exact proposal</button>'+
    '<p id="result" role="status" aria-live="polite">Not confirmed.</p>'+
    '<script nonce="'+safe(nonce)+'">'+
    "(()=>{'use strict';const expected="+JSON.stringify(offer.worker_id)+";"+
    "const challenge="+JSON.stringify(record.challenge_id)+";"+
    "const digest="+JSON.stringify(record.proposal_sha256)+";"+
    "const button=document.getElementById('confirm');"+
    "button.addEventListener('click',async()=>{button.disabled=true;"+
    "const value=document.getElementById('worker').value;"+
    "const status=document.getElementById('result');"+
    "if(value!==expected){status.textContent='Worker ID does not match. No approval recorded.';"+
    "button.disabled=false;return;}"+
    "try{const response=await fetch("+JSON.stringify(POST)+",{method:'POST',"+
    "credentials:'same-origin',headers:{'content-type':'application/json',"+
    "'x-bke-admin-action':'pair'},body:JSON.stringify({action:'pair',"+
    "challenge_id:challenge,worker_id:expected,confirm_worker_id:value,proposal_sha256:digest})});"+
    "const data=await response.json();"+
    "status.textContent=response.ok&&data.state==='CONFIRMED_FOR_ATOMIC_ISSUANCE'"+
    "?'Proposal confirmed for later atomic invitation issuance; NOT paired.':"+
    "'Confirmation failed or expired. No pairing authorized.';}"+
    "catch{status.textContent='Confirmation uncertain. Do not retry blindly.';}"+
    "});})();</script></main></body></html>";
}
// Extra injection is intentionally absent from the deployable default entry.
// The prepared proposal must come from a future authenticated device ingress;
// never accept browser-provided installation ID, hashes or a role flag.
export async function handleAdminPairingReview({
  request,env,executionCtx,server,send=sendAdminPairingConsent,
  cryptoImpl=crypto,
}={}){
  if(locked(env))return deny("REVIEW_NOT_ENABLED",404);
  const method=request?.method;
  let url;
  try{url=new URL(request.url);}catch{return deny("INVALID_REVIEW_REQUEST",400);}
  if(url.origin!==ORIGIN||url.search||url.hash||url.username||url.password ||
     !((url.pathname===PAGE&&method==="GET") ||
       (url.pathname===POST&&method==="POST")))
    return deny("INVALID_REVIEW_REQUEST",400);
  if(typeof server?.loadPreparedProposal!=="function")
    return deny("REVIEW_PREPARATION_UNAVAILABLE",404);
  if(await inspectAdminRuntimeAccess(executionCtx,env)!=="AUTHORIZED")
    return deny("ADMIN_ACCESS_DENIED",403);
  if(url.pathname===POST){
    const answer=await send({
      ...server.rpcOverrides,
      kind:"confirm",request,env,executionCtx,
    });
    return Response.json(answer,{
      status:answer?.state==="CONFIRMED_FOR_ATOMIC_ISSUANCE"?200:403,
      headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff",
        "Referrer-Policy":"no-referrer"},
    });
  }
  let prepared;
  try{prepared=await server.loadPreparedProposal(executionCtx,env);}
  catch{return deny("REVIEW_PREPARATION_UNAVAILABLE",503);}
  if(!preparedShape(prepared))return deny("REVIEW_PREPARATION_INVALID",503);
  const offer={worker_id:prepared.worker_id,public_key:prepared.public_key,
    resources:prepared.resources};
  const answer=await send({...server.rpcOverrides,
    kind:"present",offer,env,executionCtx});
  if(answer.state!=="AWAITING_EXPLICIT_HUMAN_CONFIRMATION")
    return deny("REVIEW_PRESENTATION_DENIED",503);
  // Display SHA-256 values from the SAME canonical proposal as signed DO.
  // Only the verified private sender returns a challenge for this exact digest.
  const proposal=await computePairingProposalSha256({
    installationId:"1", // only for installation-independent public-key thumbprint
    workerId:offer.worker_id,publicKey:offer.public_key,
    resources:offer.resources,cryptoImpl,
  });
  // The actual installation-derived approval digest comes solely from the
  // signed server response. This local computation checks P-256 and key hash.
  if(!proposal)return deny("REVIEW_PROPOSAL_INVALID",503);
  let nonce;
  try{
    const random=new Uint8Array(16);cryptoImpl.getRandomValues(random);
    nonce=btoa(Array.from(random,b=>String.fromCharCode(b)).join(""))
      .replaceAll("+","-").replaceAll("/","_").replace(/=+$/u,"");
  }catch{return deny("REVIEW_RANDOM_UNAVAILABLE",503);}
  return new Response(html({...offer,display:prepared.display,
    identity_public_key_sha256:proposal.keyhash,
  },answer,nonce),{status:200,headers:securityHeaders(nonce)});
}
