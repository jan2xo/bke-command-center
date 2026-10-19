// Source-only private PREPRODUCTION Durable Object installation routing proof.
// No external route, pairing action, device token, lease, or GitHub PR mutation.
import { inspectAdminRuntimeAccess } from "./admin-access.js";
import { readAdminWorkerAssignments } from "./admin-worker-assignments.js";

const AUD = "bke-command-center/preproduction/installation-vault-scope/v1";
const PURPOSE = "admin_pairing_vault_scope_v1";
const INSTALL = /^[1-9][0-9]{0,19}$/u;
const HEX64 = /^[a-f0-9]{64}$/u;
const KEY_B64 = /^[A-Za-z0-9_-]{43}$/u;
const MAX_TTL_MS = 30_000;
const fail = code => Object.freeze({ state: "BLOCKED", code });
const encode = value => new TextEncoder().encode(value);
const hex = arr => Array.from(arr, n => n.toString(16).padStart(2, "0")).join("");
const exact = (value, fields) => value && typeof value === "object" &&
  !Array.isArray(value) && Object.keys(value).sort().join(",") === fields;

function b64key(raw) {
  if (typeof raw !== "string" || !KEY_B64.test(raw)) return null;
  try {
    const normalized = raw.replaceAll("-", "+").replaceAll("_", "/") + "=";
    const data = atob(normalized);
    if (data.length !== 32) return null;
    if (btoa(data).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "") !== raw) return null;
    return Uint8Array.from(data, char => char.charCodeAt(0));
  } catch { return null; }
}
function message(kind, installationId, nonce, expiry) {
  return JSON.stringify([AUD, kind, installationId, nonce, expiry]);
}
async function mac(key, content, subtle) {
  const signingKey = await subtle.importKey("raw", key, {
    name: "HMAC", hash: "SHA-256",
  }, false, ["sign"]);
  return hex(new Uint8Array(await subtle.sign("HMAC", signingKey, encode(content))));
}
function constantHexEqual(expected, actual) {
  if (typeof expected !== "string" || typeof actual !== "string" ||
      !HEX64.test(expected) || !HEX64.test(actual)) return false;
  let diff = 0;
  for (let i = 0; i < 64; i++) diff |= expected.charCodeAt(i) ^ actual.charCodeAt(i);
  return diff === 0;
}
function nowMs(clock) {
  try {
    const now = clock();
    return Number.isSafeInteger(now) && now > 0 && now <= Number.MAX_SAFE_INTEGER - MAX_TTL_MS
      ? now : null;
  } catch { return null; }
}
function enabled(env) {
  return env?.BKE_PREPRODUCTION === "true" &&
    env?.BKE_ACCESS_POLICY_VERIFIED === "true" &&
    env?.BKE_ADMIN_PR_INVENTORY_ENABLED === "true" &&
    env?.BKE_ADMIN_DO_ROUTING_ENABLED === "true";
}
function validObserved(value) {
  return exact(value,
    "approved_repository_count,consistency,dispatch_authority,enumerated_open_pr_count,source,state,trusted_installation_id,worker_claims") &&
    value.state === "OBSERVED_ONLY" &&
    value.source === "GITHUB_APP_INSTALLATION" &&
    value.consistency === "NON_ATOMIC_ENUMERATION" &&
    value.dispatch_authority === "NONE" &&
    typeof value.trusted_installation_id === "string" &&
    INSTALL.test(value.trusted_installation_id) &&
    Number.isSafeInteger(value.approved_repository_count) &&
    value.approved_repository_count >= 1 && value.approved_repository_count <= 100 &&
    Number.isSafeInteger(value.enumerated_open_pr_count) &&
    value.enumerated_open_pr_count >= 0 && value.enumerated_open_pr_count <= 2000 &&
    Array.isArray(value.worker_claims) && value.worker_claims.length <= 500 &&
    value.worker_claims.length <= value.enumerated_open_pr_count;
}

// This function takes NO tenant ID, worker ID, or browser-selected namespace.
// GitHub App verified scope provides the ONLY tenant selection.
export async function attestAdminInstallationVault({
  env, executionCtx, readAssignments = readAdminWorkerAssignments,
  cryptoImpl = crypto, clock = () => Date.now(),
} = {}) {
  if (!enabled(env)) return fail("VAULT_SCOPE_LOCKED");
  const secret = b64key(env?.BKE_PAIRING_RPC_KEY_B64);
  if (!secret || typeof readAssignments !== "function" ||
      typeof cryptoImpl?.subtle?.importKey !== "function" ||
      typeof cryptoImpl?.subtle?.sign !== "function" ||
      typeof cryptoImpl?.getRandomValues !== "function" || typeof clock !== "function") {
    return fail("VAULT_SCOPE_ADAPTER_UNAVAILABLE");
  }
  if (await inspectAdminRuntimeAccess(executionCtx, env) !== "AUTHORIZED") {
    return fail("VAULT_SCOPE_ADMIN_DENIED");
  }
  let observation;
  try { observation = await readAssignments(env, executionCtx); }
  catch { return fail("VAULT_SCOPE_GITHUB_UNAVAILABLE"); }
  if (!validObserved(observation)) return fail("VAULT_SCOPE_GITHUB_INVALID");
  const installationId = observation.trusted_installation_id;
  const namespace = env?.BKE_WORKER_PAIRING_VAULT;
  if (typeof namespace?.idFromName !== "function" ||
      typeof namespace?.get !== "function") return fail("VAULT_SCOPE_NAMESPACE_UNAVAILABLE");
  const now = nowMs(clock);
  if (now === null) return fail("VAULT_SCOPE_CLOCK_INVALID");
  let nonce, signature;
  const expires_at_ms = now + MAX_TTL_MS;
  try {
    const data = new Uint8Array(32);
    cryptoImpl.getRandomValues(data);
    nonce = hex(data);
    signature = await mac(secret, message("request", installationId, nonce, expires_at_ms),
      cryptoImpl.subtle);
  } catch { return fail("VAULT_SCOPE_CRYPTO_UNAVAILABLE"); }
  let reply;
  try {
    const objectId = namespace.idFromName("installation:" + installationId);
    const stub = namespace.get(objectId);
    if (typeof stub?.attestInstallation !== "function") {
      return fail("VAULT_SCOPE_RPC_UNAVAILABLE");
    }
    reply = await stub.attestInstallation({
      purpose: PURPOSE, installation_id: installationId,
      nonce, expires_at_ms, signature,
    });
  } catch { return fail("VAULT_SCOPE_RPC_UNAVAILABLE"); }
  if (!exact(reply, "ack_signature,state") ||
      reply.state !== "SCOPE_ATTESTED_READ_ONLY") {
    return fail("VAULT_SCOPE_REPLY_INVALID");
  }
  let expected;
  try {
    expected = await mac(secret, message("ack", installationId, nonce, expires_at_ms),
      cryptoImpl.subtle);
  } catch { return fail("VAULT_SCOPE_CRYPTO_UNAVAILABLE"); }
  if (!constantHexEqual(expected, reply.ack_signature)) {
    return fail("VAULT_SCOPE_REPLY_INVALID");
  }
  return Object.freeze({
    state: "SCOPE_ATTESTED_READ_ONLY",
    pairing_authority: "NONE",
    dispatch_authority: "NONE",
    consistency: "NON_ATOMIC_GITHUB_EVIDENCE",
  });
}

// Runs INSIDE the named Durable Object, not over HTTP. HMAC verifies that a
// trusted broker-routing caller sent a request for THIS installation object.
// A successful proof is read-only and does not access/modify pairing storage.
export async function verifyVaultInstallationAttestation({
  request, env, objectId, cryptoImpl = crypto, clock = () => Date.now(),
} = {}) {
  if (!enabled(env) || !exact(request,
    "expires_at_ms,installation_id,nonce,purpose,signature") ||
      request.purpose !== PURPOSE ||
      typeof request.installation_id !== "string" ||
      !INSTALL.test(request.installation_id) ||
      typeof request.nonce !== "string" || !HEX64.test(request.nonce) ||
      typeof request.signature !== "string" || !HEX64.test(request.signature) ||
      !Number.isSafeInteger(request.expires_at_ms) ||
      typeof objectId?.toString !== "function" ||
      typeof env?.BKE_WORKER_PAIRING_VAULT?.idFromName !== "function") {
    return fail("VAULT_SCOPE_REQUEST_REJECTED");
  }
  const secret = b64key(env.BKE_PAIRING_RPC_KEY_B64);
  const now = nowMs(clock);
  if (!secret || now === null ||
      request.expires_at_ms <= now ||
      request.expires_at_ms > now + MAX_TTL_MS) {
    return fail("VAULT_SCOPE_REQUEST_REJECTED");
  }
  try {
    const expectedObjectId = env.BKE_WORKER_PAIRING_VAULT.idFromName(
      "installation:" + request.installation_id);
    if (typeof expectedObjectId?.toString !== "function" ||
        expectedObjectId.toString() !== objectId.toString()) {
      return fail("VAULT_SCOPE_OBJECT_MISMATCH");
    }
    const signature = await mac(secret, message("request", request.installation_id,
      request.nonce, request.expires_at_ms), cryptoImpl.subtle);
    if (!constantHexEqual(signature, request.signature)) {
      return fail("VAULT_SCOPE_REQUEST_REJECTED");
    }
    const ack_signature = await mac(secret, message("ack", request.installation_id,
      request.nonce, request.expires_at_ms), cryptoImpl.subtle);
    return Object.freeze({ state: "SCOPE_ATTESTED_READ_ONLY", ack_signature });
  } catch { return fail("VAULT_SCOPE_REQUEST_REJECTED"); }
}
