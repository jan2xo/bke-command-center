import { X509Certificate, createHash, verify as verifySignature } from "node:crypto";

const EVIDENCE_FIELDS = "attestationChainBase64Url,bridgeId,challengeBase64Url,hardwareBacked,initialAttestationChallengeBase64Url,profileId,protocolVersion,publicKeyBase64Url,sessionId,signatureBase64Url,targetOrigin,workerId";
const CONTEXT_FIELDS = "approvedPackageName,approvedRootFingerprints256,approvedSigningCertificateSha256,bridgeId,initialAttestationChallengeBase64Url,profileId,proofChallenge,revocationSnapshot,sessionId,targetOrigin,workerId";
const PROOF_FIELDS = "challengeBase64Url,expiresAtMs,issuedAtMs,state,workerId";
const REVOCATION_FIELDS = "cacheMaxAgeMs,entries,fetchedAtMs,source";
const EXT_OID = "1.3.6.1.4.1.11129.2.1.17";
const REVOCATION_URL = "https://android.googleapis.com/attestation/status";
const WORKER = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const B64URL = /^[A-Za-z0-9_-]+$/u;
const MAX_CERT = 96 * 1024;
const MAX_CHAIN = 384 * 1024;
const MAX_CERTS = 8;
const MAX_PROOF_TTL_MS = 120_000;
const blocked = (code) => Object.freeze({state:"BLOCKED",code,pairing_authority:"NONE",dispatch_authority:"NONE"});
const exact = (v, fields) => v !== null && typeof v === "object" && !Array.isArray(v) && Object.keys(v).sort().join(",") === fields;

function b64(value, limit) {
  if (typeof value !== "string" || !value || !B64URL.test(value) || value.length > Math.ceil(limit * 4 / 3) + 4) return null;
  try {
    const bytes = Buffer.from(value, "base64url");
    return bytes.length && bytes.length <= limit && bytes.toString("base64url") === value ? bytes : null;
  } catch { return null; }
}
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const serial = (v) => String(v).toLowerCase().replace(/^0+(?=[0-9a-f])/u, "") || "0";
function now(clock) {
  try { const n = clock(); return Number.isSafeInteger(n) && n > 0 && n < Number.MAX_SAFE_INTEGER - MAX_PROOF_TTL_MS ? n : null; }
  catch { return null; }
}

// Strict definite-length DER parser. Only structures used by X.509 and Android
// KeyDescription are inspected here; unsupported or malformed DER is rejected.
function node(bytes, offset = 0) {
  if (!Buffer.isBuffer(bytes) || offset < 0 || offset >= bytes.length) throw Error("DER_TRUNCATED");
  const start = offset, first = bytes[offset++];
  const tagClass = first >> 6, constructed = (first & 0x20) !== 0;
  let tagNumber = first & 31;
  if (tagNumber === 31) {
    tagNumber = 0;
    let count = 0;
    while (true) {
      if (offset >= bytes.length || count++ > 5) throw Error("DER_TAG_INVALID");
      const octet = bytes[offset++];
      if (count === 1 && (octet & 127) === 0) throw Error("DER_TAG_NONCANONICAL");
      tagNumber = tagNumber * 128 + (octet & 127);
      if (!Number.isSafeInteger(tagNumber)) throw Error("DER_TAG_OVERFLOW");
      if (!(octet & 128)) break;
    }
    if (tagNumber < 31) throw Error("DER_TAG_NONCANONICAL");
  }
  if (offset >= bytes.length) throw Error("DER_LENGTH_MISSING");
  const firstLength = bytes[offset++];
  let length;
  if (firstLength < 128) length = firstLength;
  else {
    const count = firstLength & 127;
    if (!count || count > 4 || offset + count > bytes.length || bytes[offset] === 0) throw Error("DER_LENGTH_INVALID");
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
    if (length < 128 || !Number.isSafeInteger(length)) throw Error("DER_LENGTH_NONCANONICAL");
  }
  const valueStart = offset, end = valueStart + length;
  if (!Number.isSafeInteger(end) || end > bytes.length) throw Error("DER_TRUNCATED");
  return {tagClass,tagNumber,constructed,start,valueStart,end,next:end,raw:bytes.subarray(start,end),value:bytes.subarray(valueStart,end)};
}
function children(parent, bytes) {
  if (!parent.constructed) throw Error("DER_NOT_CONSTRUCTED");
  const out = [];
  for (let off = parent.valueStart; off < parent.end;) {
    const child = node(bytes, off);
    if (child.next <= off) throw Error("DER_PROGRESS");
    out.push(child); off = child.next;
  }
  return out;
}
function tag(n, cls, number, constructed) {
  if (n.tagClass !== cls || n.tagNumber !== number || (constructed !== undefined && n.constructed !== constructed)) throw Error("DER_SCHEMA");
}
function oid(n) {
  tag(n,0,6,false);
  if (!n.value.length) throw Error("DER_OID_EMPTY");
  const arcs = []; let v = 0, ongoing = false;
  for (const b of n.value) {
    if (!ongoing && b === 128) throw Error("DER_OID_NONCANONICAL");
    v = v * 128 + (b & 127);
    if (!Number.isSafeInteger(v)) throw Error("DER_OID_OVERFLOW");
    ongoing = !!(b & 128);
    if (!ongoing) { arcs.push(v); v = 0; }
  }
  if (ongoing || !arcs.length) throw Error("DER_OID_TRUNCATED");
  const first = arcs.shift(), a = first < 40 ? 0 : first < 80 ? 1 : 2;
  return [a,first - a * 40,...arcs].join(".");
}
function certificateExtensions(der) {
  const cert = node(der); tag(cert,0,16,true);
  if (cert.next !== der.length) throw Error("CERT_TRAILING_DATA");
  const parts = children(cert,der);
  if (parts.length !== 3) throw Error("CERT_SCHEMA");
  const wrappers = children(parts[0],der).filter(x => x.tagClass === 2 && x.tagNumber === 3 && x.constructed);
  if (wrappers.length !== 1) throw Error("CERT_EXTENSIONS_SCHEMA");
  const wrapped = children(wrappers[0],der);
  if (wrapped.length !== 1) throw Error("CERT_EXTENSIONS_SCHEMA");
  tag(wrapped[0],0,16,true);
  const result = new Map();
  for (const ext of children(wrapped[0],der)) {
    tag(ext,0,16,true);
    const fields = children(ext,der);
    if (fields.length < 2 || fields.length > 3) throw Error("CERT_EXTENSION_SCHEMA");
    const name = oid(fields[0]), octet = fields[fields.length - 1];
    let critical = false;
    if (fields.length === 3) {
      tag(fields[1],0,1,false);
      if (fields[1].value.length !== 1 || ![0,255].includes(fields[1].value[0])) throw Error("CERT_EXTENSION_BOOLEAN");
      critical = fields[1].value[0] === 255;
    }
    tag(octet,0,4,false);
    if (result.has(name)) throw Error("CERT_DUPLICATE_EXTENSION");
    result.set(name,{value:Buffer.from(octet.value),critical});
  }
  return result;
}
function parseBasicConstraints(encoded) {
  const root=node(encoded); tag(root,0,16,true);
  if (root.next!==encoded.length) throw Error("BASIC_CONSTRAINTS_TRAILING");
  const fields=children(root,encoded);
  let offset=0, ca=false, pathLen=null;
  if (fields[offset]?.tagClass===0&&fields[offset]?.tagNumber===1) {
    tag(fields[offset],0,1,false);
    if (fields[offset].value.length!==1||![0,255].includes(fields[offset].value[0])) throw Error("BASIC_CONSTRAINTS_BOOLEAN");
    ca=fields[offset].value[0]===255; offset++;
  }
  if (fields[offset]) {
    tag(fields[offset],0,2,false);
    if (!fields[offset].value.length||(fields[offset].value[0]&128)||fields[offset].value.length>4) throw Error("BASIC_CONSTRAINTS_PATHLEN");
    pathLen=0;
    for (const b of fields[offset].value) pathLen=pathLen*256+b;
    offset++;
  }
  if (offset!==fields.length||(!ca&&pathLen!==null)) throw Error("BASIC_CONSTRAINTS_SCHEMA");
  return {ca,pathLen};
}

function parseAttestation(encoded) {
  const root = node(encoded); tag(root,0,16,true);
  if (root.next !== encoded.length) throw Error("ANDROID_ATTESTATION_TRAILING");
  const f = children(root,encoded);
  if (f.length !== 8) throw Error("ANDROID_ATTESTATION_SCHEMA");
  tag(f[0],0,2,false); tag(f[1],0,10,false); tag(f[2],0,2,false); tag(f[3],0,10,false);
  tag(f[4],0,4,false); tag(f[5],0,4,false); tag(f[6],0,16,true); tag(f[7],0,16,true);
  const attestationLevel = f[1].value.length === 1 ? f[1].value[0] : -1;
  const keyLevel = f[3].value.length === 1 ? f[3].value[0] : -1;
  if (![1,2].includes(attestationLevel) || ![1,2].includes(keyLevel) || attestationLevel !== keyLevel) throw Error("ANDROID_KEY_NOT_HARDWARE_ATTESTED");
  const appIds = [];
  for (const auth of [f[6],f[7]]) for (const item of children(auth,encoded)) {
    if (item.tagClass === 2 && item.tagNumber === 709) {
      if (!item.constructed) throw Error("ANDROID_APP_ID_TAG");
      const inner = children(item,encoded);
      if (inner.length !== 1) throw Error("ANDROID_APP_ID_TAG");
      tag(inner[0],0,4,false); appIds.push(Buffer.from(inner[0].value));
    }
  }
  if (appIds.length !== 1) throw Error("ANDROID_APP_ID_MISSING_OR_DUPLICATE");
  return {challenge:Buffer.from(f[4].value),attestationLevel,keyLevel,applicationId:appIds[0]};
}
function parseAppId(encoded) {
  const root = node(encoded); tag(root,0,16,true);
  if (root.next !== encoded.length) throw Error("ANDROID_APP_ID_TRAILING");
  const f = children(root,encoded);
  if (f.length !== 2) throw Error("ANDROID_APP_ID_SCHEMA");
  tag(f[0],0,17,true); tag(f[1],0,17,true);
  const packages = children(f[0],encoded).map((pkg) => {
    tag(pkg,0,16,true); const p = children(pkg,encoded);
    if (p.length !== 2) throw Error("ANDROID_PACKAGE_INFO_SCHEMA");
    tag(p[0],0,4,false); tag(p[1],0,2,false);
    const name = p[0].value.toString("utf8");
    if (!name || !Buffer.from(name,"utf8").equals(p[0].value)) throw Error("ANDROID_PACKAGE_NAME_ENCODING");
    return name;
  });
  const signatures = children(f[1],encoded).map((d) => {
    tag(d,0,4,false); if (d.value.length !== 32) throw Error("ANDROID_SIGNER_DIGEST_LENGTH");
    return Buffer.from(d.value).toString("hex");
  });
  if (packages.length !== 1 || signatures.length !== 1) throw Error("ANDROID_APP_ID_MULTIPLE_IDENTITIES");
  return {packageName:packages[0],signingCertificateSha256:signatures[0]};
}

function validRevocations(s, at) {
  if (!exact(s,REVOCATION_FIELDS) || s.source !== REVOCATION_URL ||
      !Number.isSafeInteger(s.fetchedAtMs) || s.fetchedAtMs <= 0 || s.fetchedAtMs > at ||
      !Number.isSafeInteger(s.cacheMaxAgeMs) || s.cacheMaxAgeMs < 60_000 || s.cacheMaxAgeMs > 7*24*60*60_000 ||
      at - s.fetchedAtMs > s.cacheMaxAgeMs || !s.entries || typeof s.entries !== "object" || Array.isArray(s.entries)) return false;
  for (const [sn,e] of Object.entries(s.entries)) {
    if (!/^[a-f0-9]+$/u.test(sn) || !e || typeof e !== "object" || Array.isArray(e) ||
        !["REVOKED","SUSPENDED"].includes(e.status) ||
        (e.expires !== undefined && (!/^\d{4}-\d{2}-\d{2}$/u.test(e.expires) ||
          !Number.isFinite(Date.parse(e.expires + "T00:00:00Z"))))) return false;
  }
  return true;
}
function validateContext(c, at) {
  if (!exact(c,CONTEXT_FIELDS) || typeof c.workerId !== "string" || !WORKER.test(c.workerId) ||
      typeof c.sessionId !== "string" || !UUID.test(c.sessionId) ||
      typeof c.profileId !== "string" || !UUID.test(c.profileId) ||
      typeof c.bridgeId !== "string" || !UUID.test(c.bridgeId) || c.targetOrigin !== "https://chatgpt.com" ||
      typeof c.approvedPackageName !== "string" || !/^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$/u.test(c.approvedPackageName) ||
      !HASH.test(c.approvedSigningCertificateSha256) || !Array.isArray(c.approvedRootFingerprints256) ||
      c.approvedRootFingerprints256.length < 1 || c.approvedRootFingerprints256.length > 8 ||
      c.approvedRootFingerprints256.some(x => !HASH.test(x))) return "SERVER_TRUST_CONTEXT_INVALID";
  const initial = b64(c.initialAttestationChallengeBase64Url,32);
  if (!initial || initial.length !== 32) return "INITIAL_ENROLLMENT_CHALLENGE_INVALID";
  const p = c.proofChallenge;
  if (!exact(p,PROOF_FIELDS) || p.state !== "CLAIMED" || p.workerId !== c.workerId ||
      !Number.isSafeInteger(p.issuedAtMs) || !Number.isSafeInteger(p.expiresAtMs) ||
      p.issuedAtMs <= 0 || p.issuedAtMs > at || p.expiresAtMs <= at ||
      p.expiresAtMs <= p.issuedAtMs || p.expiresAtMs-p.issuedAtMs > MAX_PROOF_TTL_MS) {
    return "SERVER_PROOF_CHALLENGE_NOT_CLAIMED_OR_EXPIRED";
  }
  const proof = b64(p.challengeBase64Url,32);
  if (!proof || proof.length !== 32) return "SERVER_PROOF_CHALLENGE_INVALID";
  if (!validRevocations(c.revocationSnapshot,at)) return "REVOCATION_STATUS_UNAVAILABLE_OR_STALE";
  return null;
}
function getChain(evidence, context, at) {
  if (!Array.isArray(evidence.attestationChainBase64Url) || evidence.attestationChainBase64Url.length < 2 ||
      evidence.attestationChainBase64Url.length > MAX_CERTS) throw Error("ATTESTATION_CHAIN_MALFORMED");
  let size=0;
  const certs=evidence.attestationChainBase64Url.map(enc => {
    const raw=b64(enc,MAX_CERT); if (!raw) throw Error("ATTESTATION_CERTIFICATE_ENCODING");
    size+=raw.length; if (size>MAX_CHAIN) throw Error("ATTESTATION_CHAIN_TOO_LARGE");
    const cert=new X509Certificate(raw), from=Date.parse(cert.validFrom), to=Date.parse(cert.validTo);
    if (!Number.isFinite(from)||!Number.isFinite(to)||from>at||to<at) throw Error("ATTESTATION_CERTIFICATE_TIME");
    return cert;
  });
  const fingerprints=certs.map(c=>c.fingerprint256.replaceAll(":","").toLowerCase());
  if (new Set(fingerprints).size!==fingerprints.length) throw Error("ATTESTATION_CHAIN_DUPLICATE_CERTIFICATE");
  const extensions=certs.map(cert=>certificateExtensions(cert.raw));
  const understoodCritical=new Set(["2.5.29.15","2.5.29.19",EXT_OID]);
  const constraints=extensions.map((items,index)=>{
    for (const [extensionOid,entry] of items) {
      if (entry.critical&&!understoodCritical.has(extensionOid)) throw Error("ATTESTATION_UNKNOWN_CRITICAL_EXTENSION");
      if (extensionOid==="2.5.29.30") throw Error("ATTESTATION_NAME_CONSTRAINTS_UNSUPPORTED");
    }
    if (!items.has("2.5.29.19")) throw Error("ATTESTATION_BASIC_CONSTRAINTS_MISSING");
    const parsed=parseBasicConstraints(items.get("2.5.29.19").value);
    if (parsed.ca!==certs[index].ca) throw Error("ATTESTATION_BASIC_CONSTRAINTS_MISMATCH");
    return parsed;
  });
  for (let i=0;i<certs.length-1;i++) {
    const child=certs[i], issuer=certs[i+1];
    // The leaf must not be a CA; intermediates below the root must be CAs.
    if ((i===0&&child.ca)||(i>0&&!child.ca)||!issuer.ca||
        !child.checkIssued(issuer)||!child.verify(issuer.publicKey)) throw Error("ATTESTATION_CHAIN_SIGNATURE_INVALID");
    if (Array.isArray(issuer.keyUsage)&&issuer.keyUsage.length&&!issuer.keyUsage.some(u=>/keyCertSign|Certificate Sign/iu.test(u))) throw Error("ATTESTATION_ISSUER_KEY_USAGE");
    const pathLen=constraints[i+1].pathLen;
    const subordinateCas=certs.slice(0,i+1).filter(cert=>cert.ca).length;
    if (pathLen!==null&&subordinateCas>pathLen) throw Error("ATTESTATION_PATH_LENGTH_EXCEEDED");
  }
  const root=certs[certs.length-1], rootFp=fingerprints[fingerprints.length-1];
  if (!root.ca||!context.approvedRootFingerprints256.includes(rootFp)||!root.checkIssued(root)||!root.verify(root.publicKey)) throw Error("ATTESTATION_ROOT_NOT_PINNED");
  const key=certs[0].publicKey;
  if (!Array.isArray(certs[0].keyUsage) || !certs[0].keyUsage.some(u=>/digitalSignature/iu.test(u))) throw Error("ATTESTATION_LEAF_KEY_USAGE");
  if (key.asymmetricKeyType!=="ec"||key.asymmetricKeyDetails?.namedCurve!=="prime256v1") throw Error("ATTESTATION_LEAF_KEY_NOT_P256");
  return {certs,extensions,rootFingerprint256:rootFp};
}
function canonicalPayload(evidence,challenge) {
  const fields=[challenge,...["workerId","sessionId","profileId","bridgeId","targetOrigin"].map(k=>Buffer.from(evidence[k],"utf8"))];
  const payload=Buffer.alloc(4+fields.reduce((n,b)=>n+4+b.length,0));
  let offset=0; payload.writeUInt32BE(1,offset); offset+=4;
  for (const b of fields) { payload.writeUInt32BE(b.length,offset); offset+=4; b.copy(payload,offset); offset+=b.length; }
  return payload;
}

/**
 * Private server-side verifier only. Never call with serverContext built from
 * HTTP/device input. The caller must build it from server-owned enrollment and
 * app-signer/root pin records, a fresh official revocation-list cache, and a
 * single-use proof challenge already exclusively claimed using atomic storage.
 *
 * It verifies evidence only. It does not consume/finalize the nonce, provision a
 * pin, pair a worker, authorize a dispatch, or assert that a private OS transport
 * authenticated this invocation. Public routes intentionally do not import it.
 */
export function verifyAndroidPeerAttestationEvidence({evidence,serverContext,clock=()=>Date.now()}={}) {
  const at=now(clock);
  if (at===null) return blocked("VERIFIER_CLOCK_INVALID");
  const contextError=validateContext(serverContext,at);
  if (contextError) return blocked(contextError);
  if (!exact(evidence,EVIDENCE_FIELDS)||evidence.protocolVersion!==1||typeof evidence.hardwareBacked!=="boolean"||
      typeof evidence.workerId!=="string"||!WORKER.test(evidence.workerId)||
      typeof evidence.sessionId!=="string"||!UUID.test(evidence.sessionId)||
      typeof evidence.profileId!=="string"||!UUID.test(evidence.profileId)||
      typeof evidence.bridgeId!=="string"||!UUID.test(evidence.bridgeId)||evidence.targetOrigin!=="https://chatgpt.com") {
    return blocked("ANDROID_EVIDENCE_SCHEMA_INVALID");
  }
  if (evidence.workerId!==serverContext.workerId||evidence.sessionId!==serverContext.sessionId||
      evidence.profileId!==serverContext.profileId||evidence.bridgeId!==serverContext.bridgeId||
      evidence.targetOrigin!==serverContext.targetOrigin||
      evidence.initialAttestationChallengeBase64Url!==serverContext.initialAttestationChallengeBase64Url||
      evidence.challengeBase64Url!==serverContext.proofChallenge.challengeBase64Url) return blocked("ANDROID_EVIDENCE_BINDING_MISMATCH");
  try {
    const challenge=b64(evidence.challengeBase64Url,32), initial=b64(evidence.initialAttestationChallengeBase64Url,32);
    const publicKeyDer=b64(evidence.publicKeyBase64Url,2048), signature=b64(evidence.signatureBase64Url,256);
    if (!challenge||challenge.length!==32||!initial||initial.length!==32||!publicKeyDer||!signature) return blocked("ANDROID_EVIDENCE_ENCODING_INVALID");
    const chain=getChain(evidence,serverContext,at), leaf=chain.certs[0];
    if (!leaf.publicKey.export({type:"spki",format:"der"}).equals(publicKeyDer)) return blocked("ANDROID_PUBLIC_KEY_MISMATCH");
    const leafExtensions=chain.extensions[0];
    if (!leafExtensions.has(EXT_OID)) return blocked("ANDROID_KEY_ATTESTATION_EXTENSION_MISSING");
    const attestation=parseAttestation(leafExtensions.get(EXT_OID).value);
    if (!attestation.challenge.equals(initial)||!attestation.challenge.equals(b64(serverContext.initialAttestationChallengeBase64Url,32))) {
      return blocked("ANDROID_INITIAL_CHALLENGE_MISMATCH");
    }
    const app=parseAppId(attestation.applicationId);
    if (app.packageName!==serverContext.approvedPackageName||app.signingCertificateSha256!==serverContext.approvedSigningCertificateSha256) {
      return blocked("ANDROID_APP_SIGNER_MISMATCH");
    }
    for (const cert of chain.certs) {
      const entry=serverContext.revocationSnapshot.entries[serial(cert.serialNumber)];
      if (entry) {
        const active=entry.expires===undefined||Date.parse(entry.expires+"T23:59:59.999Z")>=at;
        if (active) return blocked("ANDROID_ATTESTATION_CERT_REVOKED_OR_SUSPENDED");
      }
    }
    if (!verifySignature("sha256",canonicalPayload(evidence,challenge),leaf.publicKey,signature)) {
      return blocked("ANDROID_EVIDENCE_SIGNATURE_INVALID");
    }
    const finalAt=now(clock);
    if (finalAt===null||serverContext.proofChallenge.expiresAtMs<=finalAt||
        !validRevocations(serverContext.revocationSnapshot,finalAt)||
        chain.certs.some(cert=>Date.parse(cert.validFrom)>finalAt||Date.parse(cert.validTo)<finalAt)) {
      return blocked("ANDROID_VALIDATION_WINDOW_EXPIRED");
    }
    return Object.freeze({
      state:"ANDROID_PEER_EVIDENCE_VERIFIED",
      protocolVersion:1,
      workerId:evidence.workerId,
      sessionId:evidence.sessionId,
      profileId:evidence.profileId,
      bridgeId:evidence.bridgeId,
      targetOrigin:evidence.targetOrigin,
      publicKeySha256:sha256(publicKeyDer),
      attestationRootFingerprint256:chain.rootFingerprint256,
      attestationSecurityLevel:attestation.attestationLevel===2?"STRONGBOX":"TRUSTED_ENVIRONMENT",
      pairing_authority:"NONE",
      dispatch_authority:"NONE",
      nonce_consumption:"CALLER_MUST_FINALIZE_ATOMICALLY",
      hardwareBackedFlagTrusted:false,
    });
  } catch {
    return blocked("ANDROID_ATTESTATION_EVIDENCE_INVALID");
  }
}

export const ANDROID_KEY_ATTESTATION_EXTENSION_OID=EXT_OID;
