// Source-only, server-side verifier for a future OS/browser-attested private host.
// A device signature/Chrome argv origin cannot authorize this verifier.
// No HTTP ingress, attestor private key, worker lease, or pairing authority here.
const AUD = 'bke-command-center/private-native-peer-attestor/v1';
const GATEWAY_AUD = 'bke-command-center/preproduction/native-device-admission/v1';
const HASH = /^[a-f0-9]{64}$/u;
const COORD = /^[A-Za-z0-9_-]{43}$/u;
const SIG = /^[A-Za-z0-9_-]{86}$/u;
const WORKER = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const KEY_FIELDS = 'crv,kty,x,y';
const BINDING_FIELDS = 'audience,bridge_identity_sha256,browser_profile_sha256,chatgpt_target_sha256,expires_at_ms,identity_public_key_sha256,session_binding_sha256,source,worker_id';
const ENVELOPE_FIELDS = 'binding,request_nonce,signature,version';
const SOURCES = new Set(['DESKTOP_EXTENSION_NATIVE', 'GECKOVIEW_EXTENSION_NATIVE']);
const text = new TextEncoder();
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
const isHash = value => typeof value === 'string' && HASH.test(value);
const isKey = key => exact(key, KEY_FIELDS) && key.kty === 'EC' && key.crv === 'P-256' && typeof key.x === 'string' && COORD.test(key.x) && typeof key.y === 'string' && COORD.test(key.y);
const safeTime = (clock) => {
  try { const n = clock(); return Number.isSafeInteger(n) && n > 0 && n < Number.MAX_SAFE_INTEGER - 30_000 ? n : null; }
  catch { return null; }
};
const validBinding = (b, now) => exact(b, BINDING_FIELDS) &&
  b.audience === GATEWAY_AUD && SOURCES.has(b.source) &&
  typeof b.worker_id === 'string' && WORKER.test(b.worker_id) &&
  ['identity_public_key_sha256', 'session_binding_sha256', 'browser_profile_sha256', 'bridge_identity_sha256', 'chatgpt_target_sha256'].every(k => isHash(b[k])) &&
  Number.isSafeInteger(b.expires_at_ms) && b.expires_at_ms > now && b.expires_at_ms <= now + 30_000;
function bytesToUrl(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}
function fromUrl(value) {
  if (typeof value !== 'string' || !SIG.test(value)) return null;
  try {
    const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '==');
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return bytes.length === 64 && bytesToUrl(bytes) === value ? bytes : null;
  } catch { return null; }
}
export const PRIVATE_ATTESTOR_AUDIENCE = AUD;
export function privateAttestorMessage(requestNonce, binding) {
  return JSON.stringify([AUD, 1, requestNonce, binding.audience, binding.source,
    binding.worker_id, binding.identity_public_key_sha256, binding.session_binding_sha256,
    binding.chatgpt_target_sha256, binding.browser_profile_sha256,
    binding.bridge_identity_sha256, binding.expires_at_ms]);
}

/**
 * Server-private factory. Both the pinned JWK and requestSignedBinding callback
 * must come from a verified server-owned configuration/private service, never
 * device JSON, a content script, a page, or a caller-supplied public API field.
 * The future attestor must itself verify the OS/browser peer before signing.
 */
export function createPinnedDevicePeerAuthorizer({
  pinnedPublicKey, requestSignedBinding, cryptoImpl = crypto, clock = () => Date.now(),
} = {}) {
  if (!isKey(pinnedPublicKey) || typeof requestSignedBinding !== 'function' ||
      typeof cryptoImpl?.subtle?.importKey !== 'function' ||
      typeof cryptoImpl?.subtle?.verify !== 'function' ||
      typeof cryptoImpl?.getRandomValues !== 'function') {
    throw Error('PRIVATE_ATTESTOR_NOT_CONFIGURED');
  }
  const lockedKey = structuredClone(pinnedPublicKey);
  const keyPromise = cryptoImpl.subtle.importKey('jwk', lockedKey,
    {name:'ECDSA', namedCurve:'P-256'}, false, ['verify']);
  return async function authorizePeer(link) {
    const start = safeTime(clock);
    if (start === null || !link || typeof link !== 'object') throw Error('PRIVATE_ATTESTOR_LINK_INVALID');
    const randomness = new Uint8Array(32);
    cryptoImpl.getRandomValues(randomness);
    const nonce = bytesToUrl(randomness);
    let response;
    try {
      response = await requestSignedBinding(link, Object.freeze({version:1,request_nonce:nonce}));
    } catch { throw Error('PRIVATE_ATTESTOR_UNAVAILABLE'); }
    const end = safeTime(clock);
    if (end === null || end < start || end >= start + 30_000 ||
        !exact(response, ENVELOPE_FIELDS) || response.version !== 1 ||
        response.request_nonce !== nonce || !validBinding(response.binding, end))
      throw Error('PRIVATE_ATTESTOR_EVIDENCE_INVALID');
    const signature = fromUrl(response.signature);
    if (!signature) throw Error('PRIVATE_ATTESTOR_SIGNATURE_INVALID');
    let authenticated;
    try {
      authenticated = await cryptoImpl.subtle.verify({name:'ECDSA',hash:'SHA-256'},
        await keyPromise, signature, text.encode(privateAttestorMessage(nonce,response.binding)));
    } catch { authenticated = false; }
    if (!authenticated || safeTime(clock) === null ||
        clock() >= response.binding.expires_at_ms) throw Error('PRIVATE_ATTESTOR_SIGNATURE_DENIED');
    return Object.freeze(structuredClone(response.binding));
  };
}
