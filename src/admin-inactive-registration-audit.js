// DORMANT, SERVER-PRIVATE, READ-ONLY projection of installation-scoped
// paired-vault rows. Never a browser-controlled registration or dispatch list.
// GitHub is PR/task truth; this is only bounded INACTIVE enrollment evidence.
import {isSafePairedRegistry} from "./worker-pairing-ceremony.js";

const INSTALL=/^[1-9][0-9]{0,19}$/u;
const WORKER=/^[a-z0-9][a-z0-9-]{0,62}$/u;
const HEX=/^[a-f0-9]{64}$/u;
const RECORD_FIELDS="bridge_identity_sha256,browser_profile_sha256,chatgpt_target_sha256,enrollment_expires_at_ms,identity_public_key_sha256,nonce_sha256,registered_at_ms,status,worker_id";
const RESOURCE_FIELDS=["identity_public_key_sha256","chatgpt_target_sha256","browser_profile_sha256","bridge_identity_sha256"];
const blocked=()=>{throw Error("INACTIVE_REGISTRATION_SNAPSHOT_UNAVAILABLE");};
const exact=(x,fields)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).sort().join(",")===fields;
const safeNow=clock=>{
  try {
    const v=clock();
    return Number.isSafeInteger(v)&&v>0&&v<Number.MAX_SAFE_INTEGER-3_600_000?v:null;
  }catch {return null;}
};

/**
 * trustedInstallationId must be resolved server-side by an independently
 * verified Admin/DO routing ceremony. It MUST NOT come from a browser or
 * request body. The store must be a real, installation-scoped
 * createPairingAtomicStore and not a client-provided adapter.
 *
 * This function cannot itself establish the injected store's provenance.
 * The trusted server must own the store and routing before invoking it.
 */
export async function observeInactivePairingRegistrations({
  store,trustedInstallationId,clock=()=>Date.now(),
}={}){
  if(typeof store?.atomic!=="function"||
    typeof trustedInstallationId!=="string"||!INSTALL.test(trustedInstallationId)||
    typeof clock!=="function")blocked();

  try {
    return await store.atomic(async tx=>{
      if(typeof tx?.get!=="function")blocked();
      const at=safeNow(clock);
      if(at===null)blocked();
      const rows=(await tx.get("paired"))??[];
      // Validate the ENTIRE registry (even expired and revoked entries) before
      // using one item. An unrelated collision invalidates the whole snapshot.
      if(!isSafePairedRegistry(rows))blocked();
      const seenWorker=new Set(),seenResources=new Set();
      const active=[];
      for(const row of rows){
        if(!exact(row,RECORD_FIELDS)||
          typeof row.worker_id!=="string"||!WORKER.test(row.worker_id)||
          seenWorker.has(row.worker_id)||
          !RESOURCE_FIELDS.every(k=>typeof row[k]==="string"&&HEX.test(row[k]))||
          typeof row.nonce_sha256!=="string"||!HEX.test(row.nonce_sha256)||
          !["PAIRED_INACTIVE","REVOKED"].includes(row.status)||
          !Number.isSafeInteger(row.registered_at_ms)||
          !Number.isSafeInteger(row.enrollment_expires_at_ms)||
          row.registered_at_ms<=0||row.registered_at_ms>at||
          row.enrollment_expires_at_ms<row.registered_at_ms||
          // The finalizer allows no more than an hour of inactivity TTL.
          (row.status==="PAIRED_INACTIVE"&&row.enrollment_expires_at_ms>row.registered_at_ms+3_600_000))blocked();
        seenWorker.add(row.worker_id);
        for(const k of [...RESOURCE_FIELDS,"nonce_sha256"]){
          const fingerprint=k+":"+row[k];
          if(seenResources.has(fingerprint))blocked();
          seenResources.add(fingerprint);
        }
        // Expired inactive and revoked registrations remain in the registry
        // but are not projected as present/current enrollments.
        if(row.status!=="PAIRED_INACTIVE"||row.enrollment_expires_at_ms<=at)continue;
        const selected={worker_id:row.worker_id};
        for(const k of RESOURCE_FIELDS)selected[k]=row[k];
        active.push(Object.freeze(selected));
      }
      const finished=safeNow(clock);
      // A transaction can outlive an enrollment's expiry. Never return an
      // apparently current registration on a backwards/advanced clock.
      if(finished===null||finished<at||finished-at>30_000||
        rows.some(row=>row.status==="PAIRED_INACTIVE"&&
          row.enrollment_expires_at_ms>at&&row.enrollment_expires_at_ms<=finished))blocked();
      active.sort((a,b)=>a.worker_id.localeCompare(b.worker_id));
      // No session binding exists in paired-vault records. Never synthesize
      // one from the nonce, pairing key or a browser profile claim.
      return Object.freeze({
        state:"PAIRED_INACTIVE_OBSERVED",
        trusted_installation_id:trustedInstallationId,
        observed_at_ms:at,
        registry_rows:rows.length,
        inactive_unexpired_workers:active.length,
        registrations:Object.freeze(active),
        session_binding_authority:"NONE",
        dispatch_authority:"NONE",
        wake_authority:"NONE",
        pairing_activation:"NONE",
      });
    });
  }catch {blocked();}
}
