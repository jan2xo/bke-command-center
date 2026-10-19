// DORMANT source-only preproduction pairing invitation: one installation DO
// transaction issues the human one-time ticket and device challenge together.
// The returned human nonce is SERVER-ONLY; NEVER expose it to a device or browser.
import { evaluateWorkerEnrollment } from "./worker-enrollment-policy.js";
import { isSafePairedRegistry, isSafePendingChallenges } from "./worker-pairing-ceremony.js";
import { isSafeAdminActionTickets } from "./admin-one-time-action-tickets.js";
import { parseTrustedWorkerAssignmentPayload } from "./admin-worker-assignments.js";

const DEVICE_AUD = "bke-command-center/preproduction/worker-pairing/v1";
const HUMAN_AUD = "bke-command-center/preproduction/admin-action/v1";
const WORKER = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const INSTALL = /^[1-9][0-9]{0,19}$/u;
const HEX = /^[a-f0-9]{64}$/u;
// The 60-second confirmed human proposal challenge is a distinct value from
// the later 90-second Admin ticket. Never accept a human approval boolean.
const KEY32 = /^[A-Za-z0-9_-]{43}$/u;
const RES = ["chatgpt_target_sha256","browser_profile_sha256","bridge_identity_sha256"];
const blocked = code => Object.freeze({ state:"BLOCKED", code });
const utf8 = s => new TextEncoder().encode(s);
const hex = bytes => Array.from(bytes,b => b.toString(16).padStart(2,"0")).join("");
const base64url = bytes => btoa(Array.from(bytes,b => String.fromCharCode(b)).join(""))
  .replaceAll("+","-").replaceAll("/","_").replace(/=+$/u,"");
const exact = (v,k) => v && typeof v === "object" && !Array.isArray(v) &&
  Object.keys(v).sort().join(",") === k;
const resourceKeys = RES.slice().sort().join(",");

function canonicalKey(jwk) {
  if (!exact(jwk,"crv,kty,x,y") || jwk.kty !== "EC" || jwk.crv !== "P-256") return null;
  for (const n of ["x","y"]) {
    if (typeof jwk[n] !== "string" || !KEY32.test(jwk[n])) return null;
    try {
      const raw = atob(jwk[n].replaceAll("-","+").replaceAll("_","/")+"=");
      if (raw.length !== 32 || base64url(Uint8Array.from(raw,c=>c.charCodeAt(0))) !== jwk[n]) return null;
    } catch { return null; }
  }
  return { crv:"P-256",kty:"EC",x:jwk.x,y:jwk.y };
}
function validResources(v) {
  return exact(v,resourceKeys) && RES.every(k => typeof v[k] === "string" && HEX.test(v[k]));
}
function clockMs(clock) {
  try {
    const n=clock();
    return Number.isSafeInteger(n) && n >= 0 && n <= Number.MAX_SAFE_INTEGER-120000 ? n : null;
  } catch { return null; }
}
async function digestHex(subtle,bytes) {
  return hex(new Uint8Array(await subtle.digest("SHA-256",bytes)));
}
function pendingUnique(rows) {
  const ids=new Set(), challenges=new Set(), resources=new Set();
  for(const r of rows) {
    if (ids.has(r.worker_id) || challenges.has(r.challenge_id)) return false;
    ids.add(r.worker_id); challenges.add(r.challenge_id);
    for (const key of ["identity_public_key_sha256","nonce_sha256",...RES]) {
      const entry=key+":"+r[key];
      if(resources.has(entry))return false;
      resources.add(entry);
    }
  }
  return true;
}
function prsFor(snapshot,installationId) {
  if (snapshot?.state!=="OBSERVED_ONLY" || snapshot.consistency!=="NON_ATOMIC_ENUMERATION" ||
      snapshot.dispatch_authority!=="NONE" ||
      snapshot.trusted_installation_id!==installationId ||
      !Array.isArray(snapshot.worker_claims)) return null;
  return snapshot.worker_claims.map(p=>({
    repository:p.repository,number:p.pr_number,state:"open",
    labels:["bke-worker:"+p.worker_id],
  }));
}
// This hash is the *sole* canonical proposal digest for future server-side
// presentation and final issuance. Normalize the public key and resource field
// order to prevent equivalent caller objects changing the approved proposal.
export async function computePairingProposalSha256({
  installationId, workerId, publicKey, resources, cryptoImpl=crypto,
}={}) {
  const key=canonicalKey(publicKey);
  if(typeof installationId!=="string" || !INSTALL.test(installationId) ||
      typeof workerId!=="string" || !WORKER.test(workerId) ||
      !key || !validResources(resources) ||
      typeof cryptoImpl?.subtle?.importKey!=="function" ||
      typeof cryptoImpl?.subtle?.digest!=="function") return null;
  try {
    await cryptoImpl.subtle.importKey("jwk",key,
      {name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
    const keyhash=await digestHex(cryptoImpl.subtle,utf8(JSON.stringify(key)));
    // Canonical order is part of the consent contract. Explicitly hash each
    // fingerprint rather than caller object insertion order.
    const canonicalResources=Object.fromEntries(RES.map(k=>[k,resources[k]]));
    const proposalHash=await digestHex(cryptoImpl.subtle,utf8(JSON.stringify([
      "pair",installationId,workerId,keyhash,canonicalResources,
    ])));
    return Object.freeze({ key, keyhash, proposalHash, resources:canonicalResources });
  } catch { return null; }
}

function enabled(env) {
  return env?.BKE_PREPRODUCTION==="true" &&
    env?.BKE_ACCESS_POLICY_VERIFIED==="true" &&
    env?.BKE_ADMIN_PR_INVENTORY_ENABLED==="true" &&
    env?.BKE_ADMIN_PAIRING_ACTIONS_ENABLED==="true" &&
    env?.BKE_ADMIN_PROTECTED_PAIRING_ENABLED==="true" &&
    env?.BKE_ADMIN_PAIRING_ISSUANCE_ENABLED==="true" &&
    env?.BKE_ADMIN_PROPOSAL_CONSENT_ENABLED==="true";
}

// A TRUSTED server adapter MUST:
// - derive installation ID only from GitHub App identity, not caller JSON;
// - obtain a fresh broker inventory with a complete strict response;
// - authorize consent to the EXACT (action,worker,key,resources,proposal digest)
//   against platform Access and a human-confirmed action;
// - return the SAME keyed human subject SHA256 used by #48's finalizer.
// No HTTP route/DO RPC invokes this factory in this PR.
export function createAtomicPairingInvitation({
  store, installationId, authorizeHumanAction, readInstallationInventory,
  confirmedConsent, cryptoImpl=crypto, clock=()=>Date.now(),
}) {
  if (typeof store?.atomic!=="function" ||
      typeof installationId!=="string" || !INSTALL.test(installationId) ||
      typeof authorizeHumanAction!=="function" ||
      typeof readInstallationInventory!=="function" ||
      typeof confirmedConsent?.consumeInTransaction!=="function" ||
      typeof cryptoImpl?.getRandomValues!=="function" ||
      typeof cryptoImpl?.subtle?.importKey!=="function" ||
      typeof cryptoImpl?.subtle?.digest!=="function" ||
      typeof clock!=="function") throw Error("INVITATION_ADAPTER_INVALID");

  async function issue({worker_id,public_key,resources,consent_challenge_id,admin_context,env}={}) {
    if(!enabled(env))return blocked("INVITATION_LOCKED");
    if(typeof worker_id!=="string" || !WORKER.test(worker_id) ||
        !canonicalKey(public_key) || !validResources(resources))
      return blocked("INVITATION_INPUT_INVALID");
    if(typeof consent_challenge_id!=="string" || !HEX.test(consent_challenge_id))
      return blocked("INVITATION_CONSENT_REQUIRED");
    const proposal=await computePairingProposalSha256({
      installationId, workerId:worker_id, publicKey:public_key, resources,cryptoImpl,
    });
    if(!proposal)return blocked("INVITATION_DEVICE_KEY_INVALID");
    const {key,keyhash,proposalHash}=proposal;
    const canonicalResources=proposal.resources;
    let subject;
    try {
      subject=await authorizeHumanAction(Object.freeze({
        action:"pair",worker_id,installation_id:installationId,
        identity_public_key_sha256:keyhash,
        resources:Object.freeze({...canonicalResources}),
        proposal_sha256:proposalHash,
      }),admin_context);
    } catch { return blocked("INVITATION_HUMAN_DENIED"); }
    if(typeof subject!=="string" || !HEX.test(subject))
      return blocked("INVITATION_HUMAN_DENIED");

    let snapshot;
    try {
      const raw=await readInstallationInventory();
      snapshot=parseTrustedWorkerAssignmentPayload(raw);
    } catch { return blocked("INVITATION_GITHUB_UNAVAILABLE"); }
    const prs=prsFor(snapshot,installationId);
    if(!prs)return blocked("INVITATION_GITHUB_AMBIGUOUS");

    const now=clockMs(clock);
    if(now===null)return blocked("INVITATION_CLOCK_INVALID");
    let deviceId, deviceNonce, deviceNonceHash, humanId, humanNonce, humanNonceHash;
    try {
      const rand=new Uint8Array(104);
      cryptoImpl.getRandomValues(rand);
      deviceId=hex(rand.slice(0,24));
      deviceNonce=base64url(rand.slice(24,56));
      deviceNonceHash=await digestHex(cryptoImpl.subtle,utf8(deviceNonce));
      humanId=hex(rand.slice(56,72));
      humanNonce=hex(rand.slice(72,104));
      humanNonceHash=await digestHex(cryptoImpl.subtle,utf8(JSON.stringify([
        HUMAN_AUD,installationId,"pair",worker_id,humanId,subject,humanNonce,
      ])));
    } catch { return blocked("INVITATION_CRYPTO_UNAVAILABLE"); }
    const deviceExpiry=now+120000, humanExpiry=now+90000;
    const message=JSON.stringify([
      DEVICE_AUD,installationId,worker_id,deviceId,deviceNonce,keyhash,
      canonicalResources.chatgpt_target_sha256,canonicalResources.browser_profile_sha256,
      canonicalResources.bridge_identity_sha256,deviceExpiry,
    ]);
    const candidate={
      worker_id,identity_public_key_sha256:keyhash,
      ...canonicalResources,nonce_sha256:deviceNonceHash,dispatch_state:"IDLE",
      expires_at_ms:deviceExpiry,
    };
    const pendingRow={...candidate,challenge_id:deviceId,public_key:key,message};
    const ticketRow={
      action:"pair",worker_id,subject_sha256:subject,challenge_id:humanId,
      nonce_sha256:humanNonceHash,expires_at_ms:humanExpiry,status:"PENDING",
    };
    try {
      return await store.atomic(async tx=>{
        const paired=(await tx.get("paired"))??[];
        const pending=(await tx.get("pending"))??[];
        const tickets=(await tx.get("admin_actions"))??[];
        if(!isSafePairedRegistry(paired) || !isSafePendingChallenges(pending) ||
            !pendingUnique(pending) || !isSafeAdminActionTickets(tickets))
          return blocked("INVITATION_REGISTRY_AMBIGUOUS");
        const decision=evaluateWorkerEnrollment({
          candidate,pairedWorkers:paired,openPullRequests:prs,
          nowMs:now,inventoryVerified:true,prSnapshotVerified:true,
        });
        if(decision.state!=="READY_FOR_HUMAN_REVIEW")
          return blocked("INVITATION_ELIGIBILITY_DENIED");
        const livePending=pending.filter(p=>p.expires_at_ms>now);
        const liveTickets=tickets.filter(t=>t.expires_at_ms>now);
        if(livePending.length>=100 || liveTickets.length>=100 ||
            livePending.some(p=>p.worker_id===worker_id ||
              ["identity_public_key_sha256","nonce_sha256",...RES].some(k=>p[k]===candidate[k])) ||
            liveTickets.some(t=>t.status==="PENDING" && t.worker_id===worker_id) ||
            liveTickets.some(t=>t.challenge_id===humanId || t.nonce_sha256===humanNonceHash))
          return blocked("INVITATION_CONFLICT");
        // The consent and both issuance writes share ONE installation-wide
        // transaction. A mismatched/replayed/expired human confirmation denies
        // the operation without issuing either proof. If a later put fails,
        // all three mutations roll back together.
        const consent=await confirmedConsent.consumeInTransaction(tx,{
          challenge_id:consent_challenge_id, worker_id,
          proposal_sha256:proposalHash, subject_sha256:subject,
        });
        if(consent?.state!=="CONSENT_CONSUMED_IN_TRANSACTION" ||
            Object.keys(consent).sort().join(",")!=="state")
          return blocked("INVITATION_CONSENT_DENIED");
        await tx.put("pending",[...livePending,pendingRow]);
        await tx.put("admin_actions",[...liveTickets,ticketRow]);
        // Human proof is returned only to the trusted server for later
        // separately consented submission; NEVER deliver this whole object
        // to a browser/device or log the nonce.
        return Object.freeze({
          state:"ISSUED_FOR_SECURE_DELIVERY",worker_id,
          device_challenge:Object.freeze({
            challenge_id:deviceId,message,expires_at_ms:deviceExpiry,
          }),
          human_ticket:Object.freeze({
            challenge_id:humanId,one_time_nonce:humanNonce,
            expires_at_ms:humanExpiry,
          }),
          pairing_authority:"NONE",dispatch_authority:"NONE",
        });
      });
    } catch {return blocked("INVITATION_STORAGE_UNAVAILABLE");}
  }
  return Object.freeze({issue});
}
