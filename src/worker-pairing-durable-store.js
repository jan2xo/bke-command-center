import { verifyVaultInstallationAttestation } from "./admin-installation-vault-attestation.js";
import { receiveProtectedInactivePairing } from "./admin-protected-pairing-rpc.js";
import { receiveAdminPairingInvitation } from "./admin-invitation-rpc.js";
import { receiveAdminPairingConsent } from "./admin-pairing-review-rpc.js";
import { receivePreparedDeviceProposal } from "./admin-device-proposal-preparation.js";
// Installation-scoped transactional store for inactive pairing and proof lifecycle.
// This adapter must execute inside one SQLite-backed Durable Object instance.
const KEY = Object.freeze({
  paired: "bke:pairing:v1:paired",
  pending: "bke:pairing:v1:pending",
  admin_actions: "bke:pairing:v1:admin_actions",
  consents: "bke:pairing:v1:consents",
  prepared: "bke:pairing:v1:prepared",
  proof_challenges: "bke:proof-challenge:v1:rows",
});
const MAX_ROWS = 100;
const MAX_SERIALIZED_BYTES = 262_144;
const invalid = () => new Error("PAIRING_STORAGE_CONTRACT_INVALID");
const PROOF_CHALLENGE_TTL_MS = 120_000;
const PROOF_PURPOSE = "android-attestation-proof-v1";
const PROOF_AUDIENCE = "bke-command-center/android-attestation-proof/v1";
const WORKER = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const INSTALLATION = /^[1-9][0-9]{0,19}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const PROOF_STATES = new Set(["ISSUED", "CLAIMED", "CONSUMED", "REJECTED"]);
const block = code => Object.freeze({ state: "BLOCKED", code });
function path(key) {
  if (typeof key !== "string" || !Object.hasOwn(KEY, key)) throw invalid();
  return KEY[key];
}
function safeCopy(value) {
  if (!Array.isArray(value) || value.length > MAX_ROWS) throw invalid();
  try {
    const json = JSON.stringify(value);
    if (typeof json !== "string" || new TextEncoder().encode(json).byteLength > MAX_SERIALIZED_BYTES) throw invalid();
    const clone = structuredClone(value);
    if (JSON.stringify(clone) !== json) throw invalid();
    return clone;
  } catch { throw invalid(); }
}
function exactObject(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === keys;
}
function safeProofRows(rows) {
  if (!Array.isArray(rows) || rows.length > MAX_ROWS) return false;
  const ids = new Set();
  for (const row of rows) {
    if (!exactObject(row, "audience,bridge_sha256,challenge_base64url,challenge_id,claimed_at_ms,expires_at_ms,installation_id,issued_at_ms,profile_sha256,purpose,session_sha256,state,target_sha256,terminal_at_ms,worker_id") ||
        typeof row.challenge_id !== "string" || !/^[a-f0-9]{64}$/u.test(row.challenge_id) ||
        ids.has(row.challenge_id) ||
        typeof row.installation_id !== "string" || !INSTALLATION.test(row.installation_id) ||
        typeof row.worker_id !== "string" || !WORKER.test(row.worker_id) ||
        !SHA256.test(row.session_sha256 || "") || !SHA256.test(row.profile_sha256 || "") ||
        !SHA256.test(row.bridge_sha256 || "") || !SHA256.test(row.target_sha256 || "") ||
        row.audience !== PROOF_AUDIENCE || row.purpose !== PROOF_PURPOSE ||
        typeof row.challenge_base64url !== "string" || !NONCE.test(row.challenge_base64url) ||
        !Number.isSafeInteger(row.issued_at_ms) || row.issued_at_ms < 1 ||
        !Number.isSafeInteger(row.expires_at_ms) || row.expires_at_ms <= row.issued_at_ms ||
        row.expires_at_ms - row.issued_at_ms > PROOF_CHALLENGE_TTL_MS ||
        !PROOF_STATES.has(row.state) ||
        !(row.claimed_at_ms === null || Number.isSafeInteger(row.claimed_at_ms)) ||
        !(row.terminal_at_ms === null || Number.isSafeInteger(row.terminal_at_ms))) return false;
    ids.add(row.challenge_id);
  }
  return true;
}
function nowMs(clock) {
  try {
    const n = clock();
    return Number.isSafeInteger(n) && n > 0 && n < Number.MAX_SAFE_INTEGER - PROOF_CHALLENGE_TTL_MS ? n : null;
  } catch { return null; }
}
function validServerContext(context, expectedInstallation) {
  return exactObject(context, "audience,bridge_sha256,installation_id,profile_sha256,purpose,session_sha256,target_sha256,worker_id") &&
    context.audience === PROOF_AUDIENCE && context.purpose === PROOF_PURPOSE &&
    typeof context.installation_id === "string" && INSTALLATION.test(context.installation_id) &&
    context.installation_id === expectedInstallation &&
    typeof context.worker_id === "string" && WORKER.test(context.worker_id) &&
    [context.session_sha256,context.profile_sha256,context.bridge_sha256,context.target_sha256]
      .every(v=>typeof v === "string" && SHA256.test(v));
}
function sameBinding(row, context) {
  return row.installation_id === context.installation_id &&
    row.worker_id === context.worker_id && row.session_sha256 === context.session_sha256 &&
    row.profile_sha256 === context.profile_sha256 && row.bridge_sha256 === context.bridge_sha256 &&
    row.target_sha256 === context.target_sha256 && row.audience === context.audience &&
    row.purpose === context.purpose;
}
function randomNonce(cryptoImpl) {
  const bytes = new Uint8Array(32);
  cryptoImpl.getRandomValues(bytes);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+","-").replaceAll("/","_").replace(/=+$/u,"");
}
function randomId(cryptoImpl) {
  const bytes = new Uint8Array(32);
  cryptoImpl.getRandomValues(bytes);
  return Array.from(bytes,b=>b.toString(16).padStart(2,"0")).join("");
}
export function createPairingAtomicStore(storage) {
  if (!storage || typeof storage.transaction !== "function") throw invalid();
  return Object.freeze({
    async atomic(operation) {
      if (typeof operation !== "function") throw invalid();
      try {
        return await storage.transaction(async transaction => {
          if (!transaction || typeof transaction.get !== "function" || typeof transaction.put !== "function") throw invalid();
          const scoped = Object.freeze({
            async get(key) {
              const value = await transaction.get(path(key));
              return value === undefined ? undefined : safeCopy(value);
            },
            async put(key, value) { await transaction.put(path(key), safeCopy(value)); },
          });
          return await operation(scoped);
        });
      } catch { throw new Error("PAIRING_STORAGE_UNAVAILABLE"); }
    },
  });
}

/**
 * Private installation-local proof challenge lifecycle.
 * resolveTrustedContext MUST derive all identity/binding values from verified
 * server-owned installation, enrollment, and active-session records.
 * Never implement it by copying properties from device/request JSON.
 */
export function createAndroidProofChallengeLifecycle({
  store, installationId, resolveTrustedContext,
  cryptoImpl = crypto, clock = () => Date.now(),
} = {}) {
  if (typeof store?.atomic !== "function" || typeof resolveTrustedContext !== "function" ||
      typeof cryptoImpl?.getRandomValues !== "function" ||
      !INSTALLATION.test(String(installationId)) || typeof clock !== "function") {
    throw Error("PROOF_CHALLENGE_ADAPTER_NOT_CONFIGURED");
  }
  const trusted = async (reference, operation) => {
    const now = nowMs(clock);
    if (now === null) return {error:"PROOF_CHALLENGE_CLOCK_INVALID"};
    let context;
    try { context = await resolveTrustedContext(reference, operation); }
    catch { return {error:"PROOF_CHALLENGE_TRUST_CONTEXT_UNAVAILABLE"}; }
    if (!validServerContext(context,String(installationId))) return {error:"PROOF_CHALLENGE_TRUST_CONTEXT_UNAVAILABLE"};
    return {context:Object.freeze(structuredClone(context)),now};
  };
  const atomic = async operation => {
    try { return await store.atomic(operation); }
    catch { return block("PROOF_CHALLENGE_STORAGE_UNAVAILABLE"); }
  };
  const rowsFrom = async tx => {
    const rows = (await tx.get("proof_challenges")) ?? [];
    if (!safeProofRows(rows)) throw Error("PROOF_CHALLENGE_REGISTRY_AMBIGUOUS");
    return rows;
  };
  // Keep expired/terminal rows for an additional bounded TTL so replay evidence
  // survives process restarts; never turn expired ISSUED/CLAIMED rows back to ISSUED.
  const retain = (rows, now) => rows.filter(row => now < row.expires_at_ms + PROOF_CHALLENGE_TTL_MS);

  return Object.freeze({
    async issue({serverReference} = {}) {
      const auth = await trusted(serverReference,"issue");
      if (auth.error) return block(auth.error);
      let nonce,id;
      try { nonce=randomNonce(cryptoImpl); id=randomId(cryptoImpl); }
      catch { return block("PROOF_CHALLENGE_RANDOM_UNAVAILABLE"); }
      const {context,now}=auth;
      const row = {
        challenge_id:id,challenge_base64url:nonce,
        installation_id:context.installation_id,worker_id:context.worker_id,
        session_sha256:context.session_sha256,profile_sha256:context.profile_sha256,
        bridge_sha256:context.bridge_sha256,target_sha256:context.target_sha256,
        audience:PROOF_AUDIENCE,purpose:PROOF_PURPOSE,
        issued_at_ms:now,expires_at_ms:now+PROOF_CHALLENGE_TTL_MS,
        state:"ISSUED",claimed_at_ms:null,terminal_at_ms:null,
      };
      return atomic(async tx => {
        const rows=await rowsFrom(tx);
        if (rows.some(r=>r.challenge_id===id || r.challenge_base64url===nonce)) return block("PROOF_CHALLENGE_COLLISION");
        const kept=retain(rows,now);
        if (kept.length>=MAX_ROWS) return block("PROOF_CHALLENGE_CAPACITY");
        await tx.put("proof_challenges",[...kept,row]);
        return Object.freeze({state:"ISSUED",challengeId:id,expiresAtMs:row.expires_at_ms,
          purpose:PROOF_PURPOSE,audience:PROOF_AUDIENCE});
      });
    },

    async claim({challengeId,serverReference} = {}) {
      if (typeof challengeId!=="string" || !/^[a-f0-9]{64}$/u.test(challengeId)) return block("PROOF_CHALLENGE_ID_INVALID");
      const auth=await trusted(serverReference,"claim");
      if (auth.error) return block(auth.error);
      const {context,now}=auth;
      return atomic(async tx=>{
        const rows=await rowsFrom(tx),matches=rows.filter(r=>r.challenge_id===challengeId);
        if (matches.length!==1) return block("PROOF_CHALLENGE_MISSING_OR_USED");
        const row=matches[0];
        if (!sameBinding(row,context)) return block("PROOF_CHALLENGE_BINDING_MISMATCH");
        if (row.state!=="ISSUED") return block("PROOF_CHALLENGE_NOT_ISSUED");
        if (now<row.issued_at_ms || now>=row.expires_at_ms) {
          await tx.put("proof_challenges",rows.map(r=>r.challenge_id===challengeId?{...r,state:"REJECTED",terminal_at_ms:now}:r));
          return block("PROOF_CHALLENGE_EXPIRED");
        }
        await tx.put("proof_challenges",rows.map(r=>r.challenge_id===challengeId?{...r,state:"CLAIMED",claimed_at_ms:now}:r));
        return Object.freeze({state:"CLAIMED",proofChallenge:Object.freeze({
          workerId:row.worker_id,challengeBase64Url:row.challenge_base64url,
          issuedAtMs:row.issued_at_ms,expiresAtMs:row.expires_at_ms,state:"CLAIMED",
        })});
      });
    },

    async finalize({challengeId,serverReference,outcome} = {}) {
      if (typeof challengeId!=="string" || !/^[a-f0-9]{64}$/u.test(challengeId) ||
          !["CONSUMED","REJECTED"].includes(outcome)) return block("PROOF_CHALLENGE_FINALIZE_INPUT_INVALID");
      const auth=await trusted(serverReference,"finalize");
      if (auth.error) return block(auth.error);
      const {context,now}=auth;
      return atomic(async tx=>{
        const rows=await rowsFrom(tx),matches=rows.filter(r=>r.challenge_id===challengeId);
        if (matches.length!==1) return block("PROOF_CHALLENGE_MISSING_OR_USED");
        const row=matches[0];
        if (!sameBinding(row,context)) return block("PROOF_CHALLENGE_BINDING_MISMATCH");
        if (row.state!=="CLAIMED") return block("PROOF_CHALLENGE_NOT_CLAIMED");
        if (now<row.issued_at_ms || now>=row.expires_at_ms) {
          await tx.put("proof_challenges",rows.map(r=>r.challenge_id===challengeId?{...r,state:"REJECTED",terminal_at_ms:now}:r));
          return block("PROOF_CHALLENGE_EXPIRED");
        }
        await tx.put("proof_challenges",rows.map(r=>r.challenge_id===challengeId?{...r,state:outcome,terminal_at_ms:now}:r));
        return Object.freeze({state:outcome});
      });
    },
  });
}
export class BkeWorkerPairingVault {
  #store; #objectId; #env;
  constructor(ctx,env){this.#store=createPairingAtomicStore(ctx?.storage);this.#objectId=ctx?.id;this.#env=env;}
  async attestInstallation(request){return verifyVaultInstallationAttestation({request,env:this.#env,objectId:this.#objectId});}
  async finalizeProtectedInactivePairing(request){return receiveProtectedInactivePairing({request,env:this.#env,objectId:this.#objectId,store:this.#store});}
  async issueAtomicPairingInvitation(request){return receiveAdminPairingInvitation({request,env:this.#env,objectId:this.#objectId,store:this.#store});}
  async reviewPairingConsent(command){return receiveAdminPairingConsent({command,env:this.#env,objectId:this.#objectId,store:this.#store});}
  async managePreparedDeviceProposal(command){return receivePreparedDeviceProposal({command,env:this.#env,objectId:this.#objectId,store:this.#store});}
  #proofLifecycle() {
    if (this.#env?.BKE_PREPRODUCTION !== "true" ||
        this.#env?.BKE_ANDROID_PROOF_CHALLENGE_ENABLED !== "true") return {blocked:block("PROOF_CHALLENGE_LOCKED")};
    if (typeof this.#env?.BKE_PROOF_CHALLENGE_CONTEXT_RESOLVER !== "function") return {blocked:block("PROOF_CHALLENGE_TRUST_CONTEXT_UNAVAILABLE")};
    const installationId=String(this.#env?.BKE_PAIRING_INSTALLATION_ID || "");
    const scope=proofScope(this.#env,this.#objectId,installationId);
    if (scope) return {blocked:scope};
    try {
      return {lifecycle:createAndroidProofChallengeLifecycle({
        store:this.#store,installationId,
        resolveTrustedContext:this.#env.BKE_PROOF_CHALLENGE_CONTEXT_RESOLVER,
      })};
    } catch { return {blocked:block("PROOF_CHALLENGE_ADAPTER_UNAVAILABLE")}; }
  }
  async issueProofChallenge({serverReference} = {}) {
    const guarded=this.#proofLifecycle(); if(guarded.blocked) return guarded.blocked;
    return guarded.lifecycle.issue({serverReference});
  }
  async claimProofChallenge({challengeId,serverReference} = {}) {
    const guarded=this.#proofLifecycle(); if(guarded.blocked) return guarded.blocked;
    return guarded.lifecycle.claim({challengeId,serverReference});
  }
  async finalizeProofChallenge({challengeId,serverReference,outcome} = {}) {
    const guarded=this.#proofLifecycle(); if(guarded.blocked) return guarded.blocked;
    return guarded.lifecycle.finalize({challengeId,serverReference,outcome});
  }
  async fetch(_request){return new Response(null,{status:404,headers:{"Cache-Control":"no-store"}});}
}
