import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createPinnedDevicePeerAuthorizer,privateAttestorMessage,PRIVATE_ATTESTOR_AUDIENCE} from '../src/admin-pinned-device-attestor.js';
const H=c=>c.repeat(64);
const T=Date.now();
const encoded=v=>Buffer.from(v).toString('base64url');
const binding=()=>({
 audience:'bke-command-center/preproduction/native-device-admission/v1',
 source:'DESKTOP_EXTENSION_NATIVE',worker_id:'worker-a',
 identity_public_key_sha256:H('1'),session_binding_sha256:H('2'),
 chatgpt_target_sha256:H('3'),browser_profile_sha256:H('4'),
 bridge_identity_sha256:H('5'),expires_at_ms:T+20_000,
});
async function fixture(){
 const keys=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const pinnedPublicKey=await webcrypto.subtle.exportKey('jwk',keys.publicKey);
 const trusted={crv:'P-256',kty:'EC',x:pinnedPublicKey.x,y:pinnedPublicKey.y};
 let at=T;
 let mutation=x=>x;
 let signer=keys.privateKey;
 let last=null;
 const link=Object.freeze({kind:'injected-server-private-connection'});
 const seen=[];
 async function requestSignedBinding(received, challenge){
   assert.equal(received,link);
   assert.deepEqual(Object.keys(challenge).sort(),['request_nonce','version']);
   assert.equal(challenge.version,1);
   seen.push(challenge.request_nonce);
   let envelope={version:1,request_nonce:challenge.request_nonce,binding:binding()};
   const sig=await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},signer,
     new TextEncoder().encode(privateAttestorMessage(envelope.request_nonce,envelope.binding)));
   envelope.signature=encoded(sig);
   last=structuredClone(envelope);
   return mutation(envelope);
 }
 const authorizer=()=>createPinnedDevicePeerAuthorizer({pinnedPublicKey:trusted,requestSignedBinding,cryptoImpl:webcrypto,clock:()=>at});
 return {authorizer,link,seen,setTime:x=>{at=x;},mutate:x=>{mutation=x;},setSigner:k=>{signer=k;},getLast:()=>last,trust:trusted};
}

test('real pinned attestor P-256 signature returns only strictly bound session evidence',async()=>{
 const f=await fixture();const fn=f.authorizer();const value=await fn(f.link);
 assert.deepEqual(value,binding());
 assert.equal(PRIVATE_ATTESTOR_AUDIENCE,'bke-command-center/private-native-peer-attestor/v1');
 assert.equal(Object.isFrozen(value),true);
 assert.equal(value.pairing_authority,undefined);
 assert.equal(value.dispatch_authority,undefined);
 assert.deepEqual(await fn(f.link),binding());
 assert.notEqual(f.seen[0],f.seen[1]);
});

test('unsigned, tampered, wrong-key and session-substitution evidence fail closed',async()=>{
 const f=await fixture();const fn=f.authorizer();
 const modifications=[
  v=>({...v,signature:'A'.repeat(86)}),
  v=>({...v,request_nonce:'A'.repeat(43)}),
  v=>({...v,binding:{...v.binding,worker_id:'worker-b'}}),
  v=>({...v,binding:{...v.binding,session_binding_sha256:H('f')}}),
  v=>({...v,binding:{...v.binding,chatgpt_target_sha256:H('f')}}),
  v=>({...v,binding:{...v.binding,source:'CHATGPT_CONTENT_SCRIPT'}}),
  v=>({...v,binding:{...v.binding,trusted:true}}),
  v=>({...v,approved:true}),
  v=>({...v,version:2}),
  v=>({...v,binding:{...v.binding,expires_at_ms:T+30_001}}),
 ];
 for(const change of modifications){f.mutate(change);await assert.rejects(fn(f.link));}
 const replay=f.getLast();f.mutate(()=>replay);await assert.rejects(fn(f.link));
 f.mutate(v=>v);const evil=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 f.setSigner(evil.privateKey);await assert.rejects(fn(f.link));
});

test('missing owner-pinned attestor, malformed pin, outage, expired binding fail closed',async()=>{
 const f=await fixture();
 assert.throws(()=>createPinnedDevicePeerAuthorizer({}),/NOT_CONFIGURED/);
 assert.throws(()=>createPinnedDevicePeerAuthorizer({pinnedPublicKey:{...f.trust,trusted:true},requestSignedBinding:()=>{},cryptoImpl:webcrypto}),/NOT_CONFIGURED/);
 const fn=f.authorizer();
 await assert.rejects(fn(null),/LINK_INVALID/);
 f.mutate(v=>({...v,binding:{...v.binding,expires_at_ms:T}}));await assert.rejects(fn(f.link));
 f.mutate(v=>v);f.setTime(T+30_001);await assert.rejects(fn(f.link));
});

test('non-canonical signatures, malformed nonces and shape smuggling are blocked',async()=>{
 const f=await fixture(); const fn=f.authorizer();
 for(const mutation of [
  v=>({...v,signature:'@@@'}),
  v=>({...v,signature:v.signature.slice(0,-1)+'='}),
  v=>({...v,binding:{...v.binding,audience:'browser-witness'}}),
  v=>({...v,binding:{...v.binding,identity_public_key_sha256:'not-a-hash'}}),
  v=>({...v,binding:{...v.binding,expires_at_ms:'999'}}),
 ]){f.mutate(mutation);await assert.rejects(fn(f.link));}
});

test('verifier remains disconnected from Cloudflare runtime and external dispatch',()=>{
 const entry=readFileSync(new URL('../src/cloudflare-worker-entry.js',import.meta.url),'utf8');
 const index=readFileSync(new URL('../src/index.js',import.meta.url),'utf8');
 const config=readFileSync(new URL('../wrangler.toml',import.meta.url),'utf8');
 assert.doesNotMatch(entry,/createPinnedDevicePeerAuthorizer|admin-pinned-device-attestor/u);
 assert.doesNotMatch(index,/createPinnedDevicePeerAuthorizer|admin-pinned-device-attestor/u);
 assert.doesNotMatch(config,/BKE_PRIVATE_DEVICE_ATTESTOR|BKE_NATIVE_DEVICE_ADMISSION_ENABLED/u);
});
