// Default-OFF server-only device admission gateway. NO public device route.
// Device key proof is not enrollment authority or a browser login.
import { inspectAdminRuntimeAccess } from "./admin-access.js";
import { computePairingProposalSha256 } from "./admin-atomic-pairing-invitation.js";
import { stageDeviceOriginProposal } from "./admin-device-proposal-preparation.js";

const AUD="bke-command-center/preproduction/native-device-admission/v1";
const WORKER=/^[a-z0-9][a-z0-9-]{0,62}$/u;
const HEX=/^[0-9a-f]{64}$/u;
const MAX_TTL=30000;
const block=code=>Object.freeze({state:"BLOCKED",code});
const exact=(v,k)=>v!==null&&typeof v==="object"&&!Array.isArray(v)&&
  Object.keys(v).sort().join(",")===k;
const BINDING="audience,bridge_identity_sha256,browser_profile_sha256,chatgpt_target_sha256,expires_at_ms,identity_public_key_sha256,session_binding_sha256,source,worker_id";
const OFFER="public_key,resources,worker_id";
const RESOURCES="bridge_identity_sha256,browser_profile_sha256,chatgpt_target_sha256";
const SOURCES=new Set(["DESKTOP_EXTENSION_NATIVE","GECKOVIEW_EXTENSION_NATIVE"]);
const hash=v=>typeof v==="string"&&HEX.test(v);
function nowMs(clock) {
  try {
    const n=clock();
    return Number.isSafeInteger(n)&&n>0&&n<Number.MAX_SAFE_INTEGER-MAX_TTL?n:null;
  }catch{return null;}
}
function flags(env){
  return env?.BKE_PREPRODUCTION==="true" &&
    env?.BKE_ACCESS_POLICY_VERIFIED==="true" &&
    env?.BKE_ADMIN_PR_INVENTORY_ENABLED==="true" &&
    env?.BKE_ADMIN_PAIRING_ACTIONS_ENABLED==="true" &&
    env?.BKE_ADMIN_PAIRING_REVIEW_ENABLED==="true" &&
    env?.BKE_ADMIN_PROPOSAL_CONSENT_ENABLED==="true" &&
    env?.BKE_ADMIN_DEVICE_PREPARATION_ENABLED==="true" &&
    env?.BKE_NATIVE_DEVICE_ADMISSION_ENABLED==="true";
}
function validBinding(v,n){
  return exact(v,BINDING)&&v.audience===AUD&&SOURCES.has(v.source) &&
    typeof v.worker_id==="string"&&WORKER.test(v.worker_id) &&
    hash(v.session_binding_sha256)&&hash(v.identity_public_key_sha256) &&
    hash(v.browser_profile_sha256)&&hash(v.bridge_identity_sha256)&&
    hash(v.chatgpt_target_sha256)&&Number.isSafeInteger(v.expires_at_ms) &&
    v.expires_at_ms>n&&v.expires_at_ms<=n+MAX_TTL;
}
function validOffer(v){
  return exact(v,OFFER)&&typeof v.worker_id==="string"&&WORKER.test(v.worker_id) &&
    exact(v.resources,RESOURCES)&&Object.values(v.resources).every(hash);
}
const copy=v=>structuredClone(v);
function bindingMatch(a,b){return JSON.stringify(a)===JSON.stringify(b);}
function matchProof(binding,offer,normalized){
  return binding.worker_id===offer.worker_id &&
    binding.identity_public_key_sha256===normalized.keyhash &&
    binding.chatgpt_target_sha256===normalized.resources.chatgpt_target_sha256 &&
    binding.browser_profile_sha256===normalized.resources.browser_profile_sha256 &&
    binding.bridge_identity_sha256===normalized.resources.bridge_identity_sha256;
}

// authorizePeer MUST be supplied by a trusted server host that actually
// verifies the native-messaging/browser-profile peer using platform evidence.
// It MUST NOT turn a device-sent "trusted" flag into an attestation.
// link itself is in-process only and not derived from HTTP JSON.
export async function stageDeviceFromPrivateTransport({
  env,executionCtx,link,authorizePeer,describeResources,readAssignments,
  cryptoImpl=crypto,clock=()=>Date.now(),
}={}){
  if(!flags(env))return block("DEVICE_TRANSPORT_LOCKED");
  if(typeof authorizePeer!=="function"||typeof describeResources!=="function" ||
    typeof link?.readCandidate!=="function" ||
    typeof link?.exchangeProof!=="function" ||
    typeof cryptoImpl?.subtle?.digest!=="function")
    return block("DEVICE_TRANSPORT_ADAPTER_REQUIRED");
  if(await inspectAdminRuntimeAccess(executionCtx,env)!=="AUTHORIZED")
    return block("DEVICE_TRANSPORT_ADMIN_DENIED");
  const at=nowMs(clock);
  if(at===null)return block("DEVICE_TRANSPORT_CLOCK_INVALID");
  let binding;
  try{binding=await authorizePeer(link,executionCtx,env);}
  catch{return block("DEVICE_TRANSPORT_PEER_UNVERIFIED");}
  if(!validBinding(binding,at))return block("DEVICE_TRANSPORT_PEER_UNVERIFIED");
  binding=Object.freeze(copy(binding));
  const stillBound=async()=>{
    const currentTime=nowMs(clock);
    if(currentTime===null||currentTime>=binding.expires_at_ms)return false;
    try{
      const current=await authorizePeer(link,executionCtx,env);
      return validBinding(current,currentTime)&&bindingMatch(binding,current);
    }catch{return false;}
  };
  if(!await stillBound())return block("DEVICE_TRANSPORT_SCOPE_CHANGED");
  let offered=false;
  const bridge=Object.freeze({
    async readCandidate(){
      if(offered||!await stillBound())throw Error("DEVICE_LINK_SCOPE_CHANGED");
      offered=true;
      const raw=await link.readCandidate();
      if(!validOffer(raw))throw Error("DEVICE_LINK_OFFER_INVALID");
      const normalized=await computePairingProposalSha256({
        installationId:"1",workerId:raw.worker_id,
        publicKey:copy(raw.public_key),resources:copy(raw.resources),
        cryptoImpl,
      });
      if(!normalized||!matchProof(binding,raw,normalized))
        throw Error("DEVICE_LINK_OFFER_MISMATCH");
      if(!await stillBound())throw Error("DEVICE_LINK_SCOPE_CHANGED");
      let signed=false;
      return Object.freeze({
        worker_id:raw.worker_id,public_key:normalized.key,
        resources:normalized.resources,
        async signChallenge(message){
          if(signed||typeof message!=="string"||message.length>600)
            throw Error("DEVICE_LINK_CHALLENGE_INVALID");
          signed=true;
          if(!await stillBound())throw Error("DEVICE_LINK_SCOPE_CHANGED");
          let signature;
          try{signature=await link.exchangeProof(message);}
          catch{throw Error("DEVICE_LINK_PROOF_UNAVAILABLE");}
          if(!await stillBound())throw Error("DEVICE_LINK_SCOPE_CHANGED");
          if(typeof signature!=="string"||!/^[A-Za-z0-9_-]{86}$/u.test(signature))
            throw Error("DEVICE_LINK_PROOF_INVALID");
          return signature;
        },
      });
    },
  });
  const args={env,executionCtx,deviceBridge:bridge,describeResources,cryptoImpl,clock};
  if(readAssignments!==undefined)args.readAssignments=readAssignments;
  try{
    const result=await stageDeviceOriginProposal(args);
    if(result?.state!=="PREPARED_FOR_HUMAN_REVIEW") {
      // Expose only a bounded, known local policy reason, never a provider
      // exception, transport payload, credential or human identity.
      const safeCauses=new Set([
        "PREPARATION_DEVICE_INVALID","PREPARATION_DEVICE_PROOF_UNAVAILABLE",
        "PREPARATION_DEVICE_PROOF_INVALID","PREPARATION_SCOPE_CHANGED",
        "PREPARATION_ADMIN_DENIED","PREPARATION_GITHUB_AMBIGUOUS",
        "PREPARATION_GITHUB_UNAVAILABLE","PREPARATION_STORAGE_UNAVAILABLE",
        "PREPARATION_DENIED","PREPARATION_OUTCOME_UNCERTAIN",
      ]);
      return block(safeCauses.has(result?.code)
        ?"DEVICE_TRANSPORT_"+result.code:"DEVICE_TRANSPORT_PREPARATION_DENIED");
    }
    if(result.pairing_authority!=="NONE"||result.dispatch_authority!=="NONE")
      return block("DEVICE_TRANSPORT_OUTCOME_UNCERTAIN");
    return Object.freeze({...result});
  }catch{return block("DEVICE_TRANSPORT_OUTCOME_UNCERTAIN");}
}
