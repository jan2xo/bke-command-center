// Source-only cryptographic worker pairing ceremony. No route, binding, or wake.
// The injection boundary MUST be trusted Cloudflare Admin/server code; NEVER pass
// caller-supplied authorization, inventories, or transactional store adapters.
import { evaluateWorkerEnrollment } from "./worker-enrollment-policy.js";

const ID = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const HEX = /^[a-f0-9]{64}$/u;
const B64 = /^[A-Za-z0-9_-]+$/u;
const RESOURCE_KEYS = Object.freeze([
  "chatgpt_target_sha256", "browser_profile_sha256", "bridge_identity_sha256",
]);
const AUDIENCE = "bke-command-center/preproduction/worker-pairing/v1";
const CHALLENGE_TTL_MS = 120_000;
const REGISTRY_LIMIT = 100;
const fail = (code) => Object.freeze({ state: "BLOCKED", code });
const encode = (bytes) => Array.from(bytes, b => String.fromCharCode(b)).join("");
const b64url = (bytes) => btoa(encode(bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
const utf8 = (str) => new TextEncoder().encode(str);

function signatureBytes(value) {
  if (typeof value !== "string" || !B64.test(value) || value.length !== 86) return null;
  try {
    const raw = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "==");
    if (raw.length !== 64) return null;
    const bytes = Uint8Array.from(raw, char => char.charCodeAt(0));
    return b64url(bytes) === value ? bytes : null;
  } catch { return null; }
}
function canonicalJwk(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
    Object.keys(input).sort().join(",") !== "crv,kty,x,y" ||
    input.kty !== "EC" || input.crv !== "P-256") return null;
  for (const name of ["x", "y"]) {
    const value = input[name];
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) return null;
    try {
      if (atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=").length !== 32) return null;
    } catch { return null; }
  }
  return { crv: "P-256", kty: "EC", x: input.x, y: input.y };
}
function validResources(input) {
  return input && typeof input === "object" && !Array.isArray(input) &&
    Object.keys(input).sort().join(",") === RESOURCE_KEYS.slice().sort().join(",") &&
    RESOURCE_KEYS.every(key => typeof input[key] === "string" && HEX.test(input[key]));
}
async function digestHex(bytes, subtle) {
  return Array.from(new Uint8Array(await subtle.digest("SHA-256", bytes)),
    b => b.toString(16).padStart(2, "0")).join("");
}
function sameResource(a, b) {
  return ["identity_public_key_sha256", "nonce_sha256", ...RESOURCE_KEYS]
    .some(key => a[key] === b[key]);
}
function safeRegistry(value) {
  if (!Array.isArray(value) || value.length > REGISTRY_LIMIT) return false;
  const ids = new Set();
  for (const row of value) {
    if (!row || typeof row !== "object" || !ID.test(row.worker_id || "") ||
      ids.has(row.worker_id) ||
      row.status !== "PAIRED_INACTIVE" && row.status !== "REVOKED" ||
      !HEX.test(row.identity_public_key_sha256 || "") ||
      !HEX.test(row.nonce_sha256 || "") ||
      !RESOURCE_KEYS.every(key => HEX.test(row[key] || ""))) return false;
    ids.add(row.worker_id);
  }
  return true;
}
function safePending(value) {
  return Array.isArray(value) && value.length <= REGISTRY_LIMIT &&
    value.every(row => row && ID.test(row.worker_id || "") &&
      typeof row.challenge_id === "string" && /^[a-f0-9]{48}$/u.test(row.challenge_id) &&
      Number.isSafeInteger(row.expires_at_ms) &&
      canonicalJwk(row.public_key) && HEX.test(row.identity_public_key_sha256 || "") &&
      HEX.test(row.nonce_sha256 || "") &&
      RESOURCE_KEYS.every(key => HEX.test(row[key] || "")) &&
      typeof row.message === "string" && row.message.length < 1500);
}

// store.atomic(fn) must atomically serialize read/compare/write across ALL
// worker IDs in the one installation's namespace (e.g., one SQLite-backed
// Durable Object); cross-instance KV or read-then-put is NOT acceptable.
export function createWorkerPairingCeremony({
  store, authorizeAdmin, readLiveAssignments, installationId,
  cryptoImpl = crypto, clock = () => Date.now(),
}) {
  if (typeof store?.atomic !== "function" || typeof authorizeAdmin !== "function" ||
    typeof readLiveAssignments !== "function" ||
    !/^[1-9][0-9]{0,19}$/u.test(String(installationId)) ||
    typeof cryptoImpl?.getRandomValues !== "function" ||
    typeof cryptoImpl?.subtle?.importKey !== "function" ||
    typeof clock !== "function") throw Error("PAIRING_ADAPTER_NOT_CONFIGURED");

  async function approved(action, workerId, context) {
    try {
      // This callback MUST use Cloudflare platform-verified Access identity,
      // allowlist and exact action/worker consent. No browser boolean accepted.
      return await authorizeAdmin(action, workerId, context) === true;
    } catch { return false; }
  }
  async function snapshot() {
    try {
      const result = await readLiveAssignments();
      if (!result || result.verified !== true || !Array.isArray(result.openPullRequests)) return null;
      return result.openPullRequests;
    } catch { return null; }
  }
  async function atomic(operation) {
    try { return await store.atomic(operation); }
    catch { return fail("PAIRING_STORAGE_UNAVAILABLE"); }
  }

  async function issueChallenge({ worker_id, public_key, resources, admin_context } = {}) {
    if (typeof worker_id !== "string" || !ID.test(worker_id) ||
      !canonicalJwk(public_key) || !validResources(resources)) {
      return fail("PAIRING_REQUEST_INVALID");
    }
    if (!await approved("pair", worker_id, admin_context)) return fail("PAIRING_ADMIN_DENIED");
    const prs = await snapshot();
    if (!prs) return fail("PAIRING_ASSIGNMENTS_UNAVAILABLE");
    const key = canonicalJwk(public_key);
    const now = clock();
    if (!Number.isSafeInteger(now) || now < 0) return fail("PAIRING_CLOCK_INVALID");
    let thumbprint;
    try {
      await cryptoImpl.subtle.importKey("jwk", key,
        { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      thumbprint = await digestHex(utf8(JSON.stringify(key)), cryptoImpl.subtle);
    } catch { return fail("PAIRING_PUBLIC_KEY_INVALID"); }
    const random = new Uint8Array(56);
    cryptoImpl.getRandomValues(random);
    const challenge_id = Array.from(random.slice(0, 24), b => b.toString(16).padStart(2, "0")).join("");
    const nonce = b64url(random.slice(24));
    const nonceHash = await digestHex(utf8(nonce), cryptoImpl.subtle);
    const expires_at_ms = now + CHALLENGE_TTL_MS;
    const message = JSON.stringify([
      AUDIENCE, String(installationId), worker_id, challenge_id,
      nonce, thumbprint, resources.chatgpt_target_sha256,
      resources.browser_profile_sha256, resources.bridge_identity_sha256,
      expires_at_ms,
    ]);
    const candidate = {
      worker_id, identity_public_key_sha256: thumbprint,
      ...resources, nonce_sha256: nonceHash, dispatch_state: "IDLE",
      expires_at_ms,
    };
    const newPending = { ...candidate, challenge_id, public_key: key, message };
    return atomic(async tx => {
      const paired = (await tx.get("paired")) ?? [];
      const pending = (await tx.get("pending")) ?? [];
      if (!safeRegistry(paired) || !safePending(pending)) return fail("PAIRING_REGISTRY_AMBIGUOUS");
      const policy = evaluateWorkerEnrollment({
        candidate, pairedWorkers: paired, openPullRequests: prs,
        nowMs: now, inventoryVerified: true, prSnapshotVerified: true,
      });
      if (policy.state !== "READY_FOR_HUMAN_REVIEW") return fail(policy.code);
      const live = pending.filter(item => item.expires_at_ms > now);
      if (live.length >= REGISTRY_LIMIT || live.some(item =>
        item.worker_id === worker_id || sameResource(item, candidate))) {
        return fail("PAIRING_PENDING_CONFLICT");
      }
      await tx.put("pending", [...live, newPending]);
      return Object.freeze({
        state: "CHALLENGE_ISSUED", worker_id, challenge_id, message, expires_at_ms,
      });
    });
  }

  async function completePairing({ worker_id, challenge_id, signature } = {}) {
    if (typeof worker_id !== "string" || !ID.test(worker_id) ||
      typeof challenge_id !== "string" || !/^[a-f0-9]{48}$/u.test(challenge_id)) {
      return fail("PAIRING_PROOF_INVALID");
    }
    const proof = signatureBytes(signature);
    if (!proof) return fail("PAIRING_PROOF_INVALID");
    const prs = await snapshot();
    if (!prs) return fail("PAIRING_ASSIGNMENTS_UNAVAILABLE");
    const now = clock();
    if (!Number.isSafeInteger(now) || now < 0) return fail("PAIRING_CLOCK_INVALID");
    return atomic(async tx => {
      const paired = (await tx.get("paired")) ?? [];
      const pending = (await tx.get("pending")) ?? [];
      if (!safeRegistry(paired) || !safePending(pending)) return fail("PAIRING_REGISTRY_AMBIGUOUS");
      const rows = pending.filter(row =>
        row.worker_id === worker_id && row.challenge_id === challenge_id);
      if (rows.length !== 1) return fail("PAIRING_CHALLENGE_MISSING_OR_USED");
      const challenge = rows[0];
      if (now >= challenge.expires_at_ms || challenge.expires_at_ms > now + CHALLENGE_TTL_MS) {
        return fail("PAIRING_CHALLENGE_EXPIRED");
      }
      let verified = false;
      try {
        const publicKey = await cryptoImpl.subtle.importKey("jwk", challenge.public_key,
          { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
        verified = await cryptoImpl.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          publicKey, proof, utf8(challenge.message));
      } catch { return fail("PAIRING_PROOF_INVALID"); }
      if (!verified) return fail("PAIRING_PROOF_INVALID");
      const candidate = { ...challenge, dispatch_state: "IDLE" };
      const policy = evaluateWorkerEnrollment({
        candidate, pairedWorkers: paired, openPullRequests: prs,
        nowMs: now, inventoryVerified: true, prSnapshotVerified: true,
      });
      if (policy.state !== "READY_FOR_HUMAN_REVIEW") return fail(policy.code);
      if (paired.length >= REGISTRY_LIMIT) return fail("PAIRING_REGISTRY_LIMIT");
      // Consume the nonce within the SAME storage transaction as registration.
      await tx.put("paired", [...paired, {
        worker_id, identity_public_key_sha256: challenge.identity_public_key_sha256,
        ...Object.fromEntries(RESOURCE_KEYS.map(key => [key, challenge[key]])),
        nonce_sha256: challenge.nonce_sha256, status: "PAIRED_INACTIVE",
        registered_at_ms: now, enrollment_expires_at_ms: now + 3600_000,
      }]);
      await tx.put("pending", pending.filter(row =>
        !(row.worker_id === worker_id && row.challenge_id === challenge_id)));
      return Object.freeze({ state: "PAIRED_INACTIVE", code: "PAIRING_PROOF_ACCEPTED" });
    });
  }

  async function revokePairing({ worker_id, admin_context } = {}) {
    if (typeof worker_id !== "string" || !ID.test(worker_id)) return fail("PAIRING_REQUEST_INVALID");
    if (!await approved("revoke", worker_id, admin_context)) return fail("PAIRING_ADMIN_DENIED");
    return atomic(async tx => {
      const paired = (await tx.get("paired")) ?? [];
      const pending = (await tx.get("pending")) ?? [];
      if (!safeRegistry(paired) || !safePending(pending)) return fail("PAIRING_REGISTRY_AMBIGUOUS");
      const rows = paired.filter(row => row.worker_id === worker_id);
      if (rows.length !== 1 || rows[0].status !== "PAIRED_INACTIVE") {
        return fail("PAIRING_NOT_ACTIVE");
      }
      const now = clock();
      if (!Number.isSafeInteger(now) || now < 0) return fail("PAIRING_CLOCK_INVALID");
      await tx.put("paired", paired.map(row => row.worker_id === worker_id
        ? { ...row, status: "REVOKED", enrollment_expires_at_ms: now }
        : row));
      await tx.put("pending", pending.filter(row => row.worker_id !== worker_id));
      return Object.freeze({ state: "REVOKED", code: "PAIRING_REVOKED" });
    });
  }
  return Object.freeze({ issueChallenge, completePairing, revokePairing });
}
