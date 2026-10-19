// Dormant, authenticated server-to-Durable-Object protected inactive pairing.
// Never expose this function or its payload through a browser pairing route.
// HMAC attests a platform-verified human action + GitHub-derived installation;
// the DO *independently* re-reads PR ownership and atomically consumes proofs.
import { inspectAdminRuntimeAccess } from "./admin-access.js";
import {
  readAdminWorkerAssignments, parseTrustedWorkerAssignmentPayload,
} from "./admin-worker-assignments.js";
import { createProtectedInactivePairing } from "./protected-inactive-pairing.js";

const AUD = "bke-command-center/preproduction/execute-protected-inactive-pairing/v1";
const BROKER_PURPOSE = Object.freeze({ purpose: "admin_worker_assignment_inventory" });
const ID = /^[1-9][0-9]{0,19}$/u;
const WORKER = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const H32 = /^[a-f0-9]{32}$/u;
const H48 = /^[a-f0-9]{48}$/u;
const H64 = /^[a-f0-9]{64}$/u;
const B64_SIG = /^[A-Za-z0-9_-]{86}$/u;
const KEY_B64 = /^[A-Za-z0-9_-]{43}$/u;
const EXPIRES = 30_000;
const block = code => Object.freeze({ state: "BLOCKED", code });
const exact = (x, keys) => x && typeof x === "object" && !Array.isArray(x) &&
  Object.keys(x).sort().join(",") === keys;
const hex = data => Array.from(data, b => b.toString(16).padStart(2, "0")).join("");
const enc = x => new TextEncoder().encode(x);
function decodeKey(raw) {
  if (typeof raw !== "string" || !KEY_B64.test(raw)) return null;
  try {
    const data = atob(raw.replaceAll("-", "+").replaceAll("_", "/") + "=");
    return data.length === 32 &&
      btoa(data).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "") === raw
      ? Uint8Array.from(data, x => x.charCodeAt(0)) : null;
  } catch { return null; }
}
async function sign(key, message, subtle) {
  const cryptoKey = await subtle.importKey("raw", key,
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(new Uint8Array(await subtle.sign("HMAC", cryptoKey, enc(message))));
}
function equals(a, b) {
  if (typeof a !== "string" || typeof b !== "string" ||
      !H64.test(a) || !H64.test(b)) return false;
  let difference = 0;
  for (let i = 0; i < 64; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
function shape(proof) {
  if (!exact(proof, "admin_challenge_id,admin_one_time_nonce,device_challenge_id,device_signature,worker_id") ||
      typeof proof.worker_id !== "string" || !WORKER.test(proof.worker_id) ||
      typeof proof.device_challenge_id !== "string" || !H48.test(proof.device_challenge_id) ||
      typeof proof.admin_challenge_id !== "string" || !H32.test(proof.admin_challenge_id) ||
      typeof proof.admin_one_time_nonce !== "string" || !H64.test(proof.admin_one_time_nonce) ||
      typeof proof.device_signature !== "string" || !B64_SIG.test(proof.device_signature)) return null;
  return {
    worker_id: proof.worker_id, device_challenge_id: proof.device_challenge_id,
    device_signature: proof.device_signature, admin_challenge_id: proof.admin_challenge_id,
    admin_one_time_nonce: proof.admin_one_time_nonce,
  };
}
function flags(env) {
  return env?.BKE_PREPRODUCTION === "true" &&
    env?.BKE_ACCESS_POLICY_VERIFIED === "true" &&
    env?.BKE_ADMIN_PR_INVENTORY_ENABLED === "true" &&
    env?.BKE_ADMIN_PAIRING_ACTIONS_ENABLED === "true" &&
    env?.BKE_ADMIN_DO_ROUTING_ENABLED === "true" &&
    env?.BKE_ADMIN_PROTECTED_PAIRING_ENABLED === "true" &&
    env?.BKE_ADMIN_PROTECTED_RPC_ENABLED === "true";
}
function nowMs(clock) {
  try {
    const n = clock();
    return Number.isSafeInteger(n) && n > 0 && n < Number.MAX_SAFE_INTEGER - EXPIRES
      ? n : null;
  } catch { return null; }
}
function envelopeMessage(id, nonce, expires, subject, proof) {
  return JSON.stringify([AUD, "pair_inactive", id, nonce, expires, subject, proof]);
}
async function deriveSubject(env, executionCtx, proof, secret, subtle) {
  try {
    // Second platform identity read must match the exact allowed Access
    // session; never honor an identity from the HTTP body or RPC proof.
    const identity = await executionCtx?.access?.getIdentity?.();
    const email = identity?.email?.trim?.().toLowerCase();
    const allow = String(env.BKE_ADMIN_EMAILS).split(",")
      .map(s => s.trim().toLowerCase());
    if (!email || !allow.includes(email) || typeof proof.worker_id !== "string") return null;
    return await sign(secret, JSON.stringify([
      AUD, "human-subject", env.BKE_ADMIN_ACCESS_AUD, email,
    ]), subtle);
  } catch { return null; }
}
function installation(snapshot) {
  return snapshot?.state === "OBSERVED_ONLY" &&
    snapshot.source === "GITHUB_APP_INSTALLATION" &&
    snapshot.consistency === "NON_ATOMIC_ENUMERATION" &&
    snapshot.dispatch_authority === "NONE" &&
    typeof snapshot.trusted_installation_id === "string" &&
    ID.test(snapshot.trusted_installation_id)
    ? snapshot.trusted_installation_id : null;
}

// Server-only: no public route calls this. The "proof" will eventually be
// obtained from a separately human-consented protected action, NOT arbitrary
// caller JSON. The human subject digest matches the one used by the future
// protected ticket/challenge issuance RPC; until then, live enrollment is OFF.
export async function sendProtectedInactivePairing({
  env, executionCtx, proof, readAssignments = readAdminWorkerAssignments,
  cryptoImpl = crypto, clock = () => Date.now(),
} = {}) {
  if (!flags(env)) return block("PAIR_RPC_LOCKED");
  const normalized = shape(proof);
  const secret = decodeKey(env?.BKE_PAIRING_RPC_KEY_B64);
  if (!normalized || !secret || typeof readAssignments !== "function" ||
      typeof cryptoImpl?.subtle?.sign !== "function" ||
      typeof cryptoImpl?.getRandomValues !== "function") {
    return block("PAIR_RPC_INPUT_INVALID");
  }
  if (await inspectAdminRuntimeAccess(executionCtx, env) !== "AUTHORIZED") {
    return block("PAIR_RPC_ADMIN_DENIED");
  }
  const subject = await deriveSubject(env, executionCtx, normalized, secret, cryptoImpl.subtle);
  if (!subject) return block("PAIR_RPC_ADMIN_DENIED");
  let snapshot;
  try { snapshot = await readAssignments(env, executionCtx); }
  catch { return block("PAIR_RPC_GITHUB_UNAVAILABLE"); }
  const id = installation(snapshot);
  if (!id) return block("PAIR_RPC_GITHUB_AMBIGUOUS");
  const namespace = env?.BKE_WORKER_PAIRING_VAULT;
  if (typeof namespace?.idFromName !== "function" ||
      typeof namespace?.get !== "function") return block("PAIR_RPC_NAMESPACE_UNAVAILABLE");
  const now = nowMs(clock);
  if (now === null) return block("PAIR_RPC_CLOCK_INVALID");
  let nonce, signature;
  const expires_at_ms = now + EXPIRES;
  try {
    const bytes = new Uint8Array(32);
    cryptoImpl.getRandomValues(bytes);
    nonce = hex(bytes);
    signature = await sign(secret, envelopeMessage(id, nonce, expires_at_ms,
      subject, normalized), cryptoImpl.subtle);
  } catch { return block("PAIR_RPC_CRYPTO_UNAVAILABLE"); }
  let outcome;
  try {
    const target = namespace.get(namespace.idFromName("installation:" + id));
    if (typeof target?.finalizeProtectedInactivePairing !== "function") {
      return block("PAIR_RPC_METHOD_UNAVAILABLE");
    }
    outcome = await target.finalizeProtectedInactivePairing({
      purpose: "protected_inactive_pairing_v1", installation_id: id,
      expires_at_ms, nonce, subject_sha256: subject, proof: normalized, signature,
    });
  } catch { return block("PAIR_RPC_OUTCOME_UNCERTAIN"); }
  if (!exact(outcome, "code,state") ||
      !["BLOCKED", "PAIRED_INACTIVE"].includes(outcome.state) ||
      typeof outcome.code !== "string" ||
      !/^PROTECTED_PAIRING_[A-Z_]+$/.test(outcome.code)) {
    return block("PAIR_RPC_OUTCOME_UNCERTAIN");
  }
  // A successful inactive record is not an activation/lease or a PR lock.
  return Object.freeze({ state: outcome.state, code: outcome.code });
}

// Runs ONLY inside installation-scoped Durable Object named RPC, after
// validating a short-lived command signature and the actual ctx.id.
// Browser JSON never becomes a fabricated Cloudflare Access session.
export async function receiveProtectedInactivePairing({
  request, env, objectId, store,
  cryptoImpl = crypto, clock = () => Date.now(),
} = {}) {
  if (!flags(env)) return block("PAIR_RPC_LOCKED");
  const proof = shape(request?.proof);
  if (!exact(request, "expires_at_ms,installation_id,nonce,proof,purpose,signature,subject_sha256") ||
      request.purpose !== "protected_inactive_pairing_v1" ||
      typeof request.installation_id !== "string" || !ID.test(request.installation_id) ||
      typeof request.nonce !== "string" || !H64.test(request.nonce) ||
      typeof request.signature !== "string" || !H64.test(request.signature) ||
      typeof request.subject_sha256 !== "string" || !H64.test(request.subject_sha256) ||
      !Number.isSafeInteger(request.expires_at_ms) || !proof ||
      typeof store?.atomic !== "function" ||
      typeof objectId?.toString !== "function" ||
      typeof env?.BKE_WORKER_PAIRING_VAULT?.idFromName !== "function") {
    return block("PAIR_RPC_REQUEST_REJECTED");
  }
  const key = decodeKey(env.BKE_PAIRING_RPC_KEY_B64);
  const now = nowMs(clock);
  if (!key || now === null || request.expires_at_ms <= now ||
      request.expires_at_ms > now + EXPIRES) return block("PAIR_RPC_REQUEST_REJECTED");
  try {
    const expected = env.BKE_WORKER_PAIRING_VAULT.idFromName(
      "installation:" + request.installation_id);
    if (expected?.toString() !== objectId.toString()) {
      return block("PAIR_RPC_INSTALLATION_MISMATCH");
    }
    const hmac = await sign(key, envelopeMessage(request.installation_id,
      request.nonce, request.expires_at_ms, request.subject_sha256, proof),
    cryptoImpl.subtle);
    if (!equals(hmac, request.signature)) return block("PAIR_RPC_REQUEST_REJECTED");
  } catch { return block("PAIR_RPC_REQUEST_REJECTED"); }

  // Cryptographic verification creates this unforgeable in-process context.
  // Never send it over Cloudflare RPC or reconstruct it from untrusted JSON.
  const verified = Object.freeze({ installation_id: request.installation_id,
    subject: request.subject_sha256 });
  const broker = env?.BKE_GITHUB_READ_BROKER?.listVerifiedWorkerAssignments;
  if (typeof broker !== "function") return block("PAIR_RPC_BROKER_UNAVAILABLE");
  const readAssignments = async () => {
    const raw = await env.BKE_GITHUB_READ_BROKER.listVerifiedWorkerAssignments(
      BROKER_PURPOSE);
    return parseTrustedWorkerAssignmentPayload(raw);
  };
  const finalizer = createProtectedInactivePairing({
    store, installationId: request.installation_id, cryptoImpl, clock,
    authorizeAccess: ctx => ctx === verified,
    authorizeHumanSubject: (_action, _worker, ctx) =>
      ctx === verified ? request.subject_sha256 : null,
    readAssignments,
  });
  try {
    return await finalizer.finalize({
      ...proof, env, executionCtx: verified,
    });
  } catch { return block("PAIR_RPC_OUTCOME_UNCERTAIN"); }
}
