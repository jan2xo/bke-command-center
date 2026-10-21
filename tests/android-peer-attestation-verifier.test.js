import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {execFileSync} from "node:child_process";
import {createPrivateKey,createPublicKey,sign,X509Certificate} from "node:crypto";
import {verifyAndroidPeerAttestationEvidence} from "../src/android-peer-attestation-verifier.js";

const STATUS_URL="https://android.googleapis.com/attestation/status";
const PACKAGE="com.bke.worker.gecko";
const WORKER="android-worker-a";
const SESSION="123e4567-e89b-42d3-a456-426614174000";
const PROFILE="223e4567-e89b-42d3-a456-426614174001";
const BRIDGE="323e4567-e89b-42d3-a456-426614174002";
const base64url=(b)=>Buffer.from(b).toString("base64url");
const tlv=(tag,body)=>{
  const b=Buffer.from(body);
  const length=b.length<128?Buffer.from([b.length]):(()=>{let hex=b.length.toString(16);if(hex.length%2)hex="0"+hex;const l=Buffer.from(hex,"hex");return Buffer.concat([Buffer.from([0x80|l.length]),l]);})();
  return Buffer.concat([Buffer.from([tag]),length,b]);
};
const highTag=(tagBytes,body)=>{
  const b=Buffer.from(body);
  const length=b.length<128?Buffer.from([b.length]):(()=>{let hex=b.length.toString(16);if(hex.length%2)hex="0"+hex;const l=Buffer.from(hex,"hex");return Buffer.concat([Buffer.from([0x80|l.length]),l]);})();
  return Buffer.concat([Buffer.from(tagBytes),length,b]);
};
const seq=(...b)=>tlv(0x30,Buffer.concat(b));
const set=(...b)=>tlv(0x31,Buffer.concat(b));
const integer=(n)=>tlv(0x02,Buffer.from([n]));
const enumerated=(n)=>tlv(0x0a,Buffer.from([n]));
const octet=(b)=>tlv(0x04,b);

function keyDescription(initialChallenge, signerDigest, securityLevel=2) {
  const pkgInfo=seq(octet(Buffer.from(PACKAGE,"utf8")),integer(1));
  const appId=seq(set(pkgInfo),set(octet(signerDigest)));
  // AuthorizationList attestationApplicationId [709] EXPLICIT OCTET_STRING.
  const appIdTag=highTag([0xbf,0x85,0x45],octet(appId));
  return seq(integer(4),enumerated(securityLevel),integer(4),enumerated(securityLevel),
    octet(initialChallenge),octet(Buffer.alloc(0)),seq(appIdTag),seq());
}

function makeCertFixture({securityLevel=2}={}) {
  const directory=mkdtempSync(join(tmpdir(),"bke-android-attestation-"));
  const rootKey=join(directory,"root.key"),rootPem=join(directory,"root.pem");
  const intermediateKey=join(directory,"intermediate.key"),intermediateCsr=join(directory,"intermediate.csr"),intermediatePem=join(directory,"intermediate.pem");
  const leafKey=join(directory,"leaf.key"),leafCsr=join(directory,"leaf.csr"),leafPem=join(directory,"leaf.pem");
  const initialChallenge=Buffer.alloc(32,0x22);
  const proofChallenge=Buffer.alloc(32,0x11);
  const signerDigest=Buffer.alloc(32,0x44);
  const run=(args)=>execFileSync("openssl",args,{stdio:"pipe"});
  run(["ecparam","-name","prime256v1","-genkey","-noout","-out",rootKey]);
  run(["req","-x509","-new","-key",rootKey,"-sha256","-days","3650","-subj","/CN=BKE Test Attestation Root",
    "-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign",
    "-addext","subjectKeyIdentifier=hash","-out",rootPem]);
  run(["ecparam","-name","prime256v1","-genkey","-noout","-out",intermediateKey]);
  run(["req","-new","-key",intermediateKey,"-subj","/CN=BKE Test Attestation Intermediate","-out",intermediateCsr]);
  const intermediateConfig=join(directory,"intermediate.cnf");
  writeFileSync(intermediateConfig,
    "[intermediate]\n"+
    "basicConstraints=critical,CA:TRUE,pathlen:0\n"+
    "keyUsage=critical,keyCertSign,cRLSign\n"+
    "subjectKeyIdentifier=hash\n"+
    "authorityKeyIdentifier=keyid,issuer\n");
  run(["x509","-req","-in",intermediateCsr,"-CA",rootPem,"-CAkey",rootKey,"-set_serial","10",
    "-days","3650","-sha256","-extfile",intermediateConfig,"-extensions","intermediate","-out",intermediatePem]);
  run(["ecparam","-name","prime256v1","-genkey","-noout","-out",leafKey]);
  run(["req","-new","-key",leafKey,"-subj","/CN=BKE Test Attested Android Key","-out",leafCsr]);
  const extension=keyDescription(initialChallenge,signerDigest,securityLevel).toString("hex");
  const config=join(directory,"leaf.cnf");
  writeFileSync(config,
    "[leaf]\n"+
    "basicConstraints=critical,CA:FALSE\n"+
    "keyUsage=critical,digitalSignature\n"+
    "subjectKeyIdentifier=hash\n"+
    "authorityKeyIdentifier=keyid,issuer\n"+
    "1.3.6.1.4.1.11129.2.1.17=DER:"+extension+"\n");
  run(["x509","-req","-in",leafCsr,"-CA",intermediatePem,"-CAkey",intermediateKey,"-set_serial","02",
    "-days","365","-sha256","-extfile",config,"-extensions","leaf","-out",leafPem]);
  const leafDer=new X509Certificate(readFileSync(leafPem));
  const intermediateDer=new X509Certificate(readFileSync(intermediatePem));
  const rootDer=new X509Certificate(readFileSync(rootPem));
  const privateKey=createPrivateKey(readFileSync(leafKey));
  const publicKeyDer=createPublicKey(privateKey).export({type:"spki",format:"der"});
  const nowMs=Date.now();
  const evidence={
    protocolVersion:1,workerId:WORKER,sessionId:SESSION,profileId:PROFILE,bridgeId:BRIDGE,
    targetOrigin:"https://chatgpt.com",
    challengeBase64Url:base64url(proofChallenge),
    initialAttestationChallengeBase64Url:base64url(initialChallenge),
    publicKeyBase64Url:base64url(publicKeyDer),
    attestationChainBase64Url:[base64url(leafDer.raw),base64url(intermediateDer.raw),base64url(rootDer.raw)],
    signatureBase64Url:"pending",hardwareBacked:true,
  };
  const fields=[proofChallenge,Buffer.from(WORKER),Buffer.from(SESSION),Buffer.from(PROFILE),Buffer.from(BRIDGE),Buffer.from("https://chatgpt.com")];
  const payload=Buffer.alloc(4+fields.reduce((n,b)=>n+4+b.length,0));
  let offset=0;payload.writeUInt32BE(1,offset);offset+=4;
  for(const field of fields){payload.writeUInt32BE(field.length,offset);offset+=4;field.copy(payload,offset);offset+=field.length;}
  evidence.signatureBase64Url=base64url(sign("sha256",payload,privateKey));
  const context={
    workerId:WORKER,sessionId:SESSION,profileId:PROFILE,bridgeId:BRIDGE,targetOrigin:"https://chatgpt.com",
    initialAttestationChallengeBase64Url:base64url(initialChallenge),
    approvedPackageName:PACKAGE,approvedSigningCertificateSha256:signerDigest.toString("hex"),
    approvedRootFingerprints256:[rootDer.fingerprint256.replaceAll(":","").toLowerCase()],
    proofChallenge:{workerId:WORKER,challengeBase64Url:base64url(proofChallenge),issuedAtMs:nowMs-1000,expiresAtMs:nowMs+60_000,state:"CLAIMED"},
    revocationSnapshot:{source:STATUS_URL,fetchedAtMs:nowMs,cacheMaxAgeMs:60*60_000,entries:{}},
  };
  return {directory,evidence,context,leafSerial:leafDer.serialNumber.toLowerCase().replace(/^0+(?=[0-9a-f])/u,"")||"0",rootSerial:rootDer.serialNumber.toLowerCase().replace(/^0+(?=[0-9a-f])/u,"")||"0"};
}

let fixture;
const otherFixtures=[];
test.before(()=>{fixture=makeCertFixture();});
test.after(()=>{for(const f of [fixture,...otherFixtures])if(f)rmSync(f.directory,{recursive:true,force:true});});

test("verifies the Android signature, pinned certificate chain, hardware attestation challenge and package signer",()=>{
  const result=verifyAndroidPeerAttestationEvidence({evidence:fixture.evidence,serverContext:fixture.context});
  assert.equal(result.state,"ANDROID_PEER_EVIDENCE_VERIFIED");
  assert.equal(result.workerId,WORKER);
  assert.equal(result.targetOrigin,"https://chatgpt.com");
  assert.equal(result.pairing_authority,"NONE");
  assert.equal(result.dispatch_authority,"NONE");
  assert.equal(result.hardwareBackedFlagTrusted,false);
  assert.equal(result.nonce_consumption,"CALLER_MUST_FINALIZE_ATOMICALLY");
});

test("rejects a root that is not on the server-owned pin list",()=>{
  const context={...fixture.context,approvedRootFingerprints256:["0".repeat(64)]};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:fixture.evidence,serverContext:context}).state,"BLOCKED");
});

test("rejects wrong worker/profile/target and wrong proof nonce bindings",()=>{
  const wrongWorker={...fixture.evidence,workerId:"android-worker-b"};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:wrongWorker,serverContext:fixture.context}).code,"ANDROID_EVIDENCE_BINDING_MISMATCH");
  const wrongProfile={...fixture.evidence,profileId:"423e4567-e89b-42d3-a456-426614174003"};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:wrongProfile,serverContext:fixture.context}).state,"BLOCKED");
  const context={...fixture.context,proofChallenge:{...fixture.context.proofChallenge,challengeBase64Url:base64url(Buffer.alloc(32,0x33))}};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:fixture.evidence,serverContext:context}).code,"ANDROID_EVIDENCE_BINDING_MISMATCH");
});

test("rejects the wrong app signer and the wrong original key-attestation challenge",()=>{
  const wrongSigner={...fixture.context,approvedSigningCertificateSha256:"a".repeat(64)};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:fixture.evidence,serverContext:wrongSigner}).code,"ANDROID_APP_SIGNER_MISMATCH");
  const wrongInitial={...fixture.context,initialAttestationChallengeBase64Url:base64url(Buffer.alloc(32,0x55))};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:fixture.evidence,serverContext:wrongInitial}).code,"ANDROID_EVIDENCE_BINDING_MISMATCH");
});

test("rejects a changed signature, stale revocation cache, and revoked attestation certificates",()=>{
  const tampered={...fixture.evidence,signatureBase64Url:base64url(Buffer.alloc(64,0x99))};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:tampered,serverContext:fixture.context}).state,"BLOCKED");
  const stale={...fixture.context,revocationSnapshot:{...fixture.context.revocationSnapshot,fetchedAtMs:Date.now()-8*24*60*60_000}};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:fixture.evidence,serverContext:stale}).code,"REVOCATION_STATUS_UNAVAILABLE_OR_STALE");
  const revoked={...fixture.context,revocationSnapshot:{...fixture.context.revocationSnapshot,entries:{[fixture.leafSerial]:{status:"REVOKED",reason:"KEY_COMPROMISE"}}}};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:fixture.evidence,serverContext:revoked}).code,"ANDROID_ATTESTATION_CERT_REVOKED_OR_SUSPENDED");
});

test("refuses software-only Android attestation security levels",()=>{
  const f=makeCertFixture({securityLevel:0});otherFixtures.push(f);
  const result=verifyAndroidPeerAttestationEvidence({evidence:f.evidence,serverContext:f.context});
  assert.equal(result.state,"BLOCKED");
});

test("fails closed on an unclaimed or expired proof nonce and on malformed certificate evidence",()=>{
  const unclaimed={...fixture.context,proofChallenge:{...fixture.context.proofChallenge,state:"ISSUED"}};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:fixture.evidence,serverContext:unclaimed}).code,"SERVER_PROOF_CHALLENGE_NOT_CLAIMED_OR_EXPIRED");
  const expired={...fixture.context,proofChallenge:{...fixture.context.proofChallenge,expiresAtMs:Date.now()-1}};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:fixture.evidence,serverContext:expired}).code,"SERVER_PROOF_CHALLENGE_NOT_CLAIMED_OR_EXPIRED");
  const malformed={...fixture.evidence,attestationChainBase64Url:["AA","AA"]};
  assert.equal(verifyAndroidPeerAttestationEvidence({evidence:malformed,serverContext:fixture.context}).state,"BLOCKED");
});
