// Source-only PREPRODUCTION protected *inactive* worker registration.
// One installation-wide DO transaction consumes BOTH the one-use human ticket
// and the signed device challenge while writing paired/pending/admin_actions.
// This does NOT claim a GitHub PR, authorize dispatch or mint an active lease.
import { inspectAdminRuntimeAccess } from "./admin-access.js";
import { readAdminWorkerAssignments } from "./admin-worker-assignments.js";
import { evaluateWorkerEnrollment } from "./worker-enrollment-policy.js";
import { isSafePairedRegistry, isSafePendingChallenges } from "./worker-pairing-ceremony.js";
import { isSafeAdminActionTickets } from "./admin-one-time-action-tickets.js";

const DEVICE_AUD = "bke-command-center/preproduction/worker-pairing/v1";
const HUMAN_AUD = "bke-command-center/preproduction/admin-action/v1";
const WORKER = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const INSTALL = /^[1-9][0-9]{0,19}$/u;
const H48 = /^[a-f0-9]{48}$/u;
const H32 = /^[a-f0-9]{32}$/u;
const H64 = /^[a-f0-9]{64}$/u;
const B64_32 = /^[A-Za-z0-9_-]{43}$/u;
const B64_64 = /^[A-Za-z0-9_-]{86}$/u;
const SHA = /^[a-f0-9]{40}$/u;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const RESOURCE = ["chatgpt_target_sha256", "browser_profile_sha256", "bridge_identity_sha256"];
const fail = code => Object.freeze({ state: "BLOCKED", code });
const utf8 = text => new TextEncoder().encode(text);
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
const exact = (v, spec) => v && typeof v === "object" && !Array.isArray(v) &&
  Object.keys(v).sort().join(",") === spec;

function decode64(s) {
  if (typeof s !== "string" || !B64_64.test(s)) return null;
  try {
    const raw = atob(s.replaceAll("-", "+").replaceAll("_", "/") + "==");
    if (raw.length !== 64) return null;
    const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
    return btoa(raw).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "") === s
      ? bytes : null;
  } catch { return null; }
}
async function shaHex(subtle, bytes) {
  return hex(new Uint8Array(await subtle.digest("SHA-256", bytes)));
}
function inventoryClaims(snapshot, installationId, workerId) {
  if (!exact(snapshot,
    "approved_repository_count,consistency,dispatch_authority,enumerated_open_pr_count,source,state,trusted_installation_id,worker_claims") ||
      snapshot.state !== "OBSERVED_ONLY" ||
      snapshot.source !== "GITHUB_APP_INSTALLATION" ||
      snapshot.consistency !== "NON_ATOMIC_ENUMERATION" ||
      snapshot.dispatch_authority !== "NONE" ||
      snapshot.trusted_installation_id !== installationId ||
      !Number.isSafeInteger(snapshot.approved_repository_count) ||
      snapshot.approved_repository_count < 1 || snapshot.approved_repository_count > 100 ||
      !Number.isSafeInteger(snapshot.enumerated_open_pr_count) ||
      snapshot.enumerated_open_pr_count < 0 || snapshot.enumerated_open_pr_count > 2000 ||
      !Array.isArray(snapshot.worker_claims) ||
      snapshot.worker_claims.length > 500 ||
      snapshot.worker_claims.length > snapshot.enumerated_open_pr_count) return null;
  const prs = [];
  const usedWorkers = new Set(), usedPrs = new Set(), ids = new Map(), names = new Map();
  for (const claim of snapshot.worker_claims) {
    if (!exact(claim, "head_sha,pr_number,repository,repository_id,worker_id") ||
        typeof claim.repository !== "string" || !REPO.test(claim.repository) ||
        claim.repository.split("/").some(p => p === "." || p === ".." || p.includes("..")) ||
        typeof claim.worker_id !== "string" || !WORKER.test(claim.worker_id) ||
        !Number.isSafeInteger(claim.repository_id) || claim.repository_id <= 0 ||
        !Number.isSafeInteger(claim.pr_number) || claim.pr_number <= 0 ||
        typeof claim.head_sha !== "string" || !SHA.test(claim.head_sha)) return null;
    const repo = claim.repository.toLowerCase(), pr = repo + "#" + claim.pr_number;
    if (usedPrs.has(pr) || usedWorkers.has(claim.worker_id) ||
        (ids.has(claim.repository_id) && ids.get(claim.repository_id) !== repo) ||
        (names.has(repo) && names.get(repo) !== claim.repository_id)) return null;
    usedPrs.add(pr);
    usedWorkers.add(claim.worker_id);
    ids.set(claim.repository_id, repo);
    names.set(repo, claim.repository_id);
    prs.push({ repository: claim.repository, number: claim.pr_number,
      state: "open", labels: ["bke-worker:" + claim.worker_id] });
  }
  if (ids.size > snapshot.approved_repository_count || usedWorkers.has(workerId)) return null;
  return prs;
}
function safePendingUniqueness(pending) {
  const ids = new Set(), challenges = new Set(), resources = new Set();
  for (const entry of pending) {
    if (ids.has(entry.worker_id) || challenges.has(entry.challenge_id)) return false;
    ids.add(entry.worker_id);
    challenges.add(entry.challenge_id);
    for (const key of ["identity_public_key_sha256", "nonce_sha256", ...RESOURCE]) {
      const fingerprint = key + ":" + entry[key];
      if (resources.has(fingerprint)) return false;
      resources.add(fingerprint);
    }
  }
  return true;
}
async function deviceProofValid(challenge, workerId, challengeId, signature, installationId, cryptoImpl, now) {
  if (challenge.expires_at_ms <= now || challenge.expires_at_ms > now + 120000 ||
      challenge.worker_id !== workerId || challenge.challenge_id !== challengeId ||
      !exact(challenge.public_key, "crv,kty,x,y") ||
      challenge.public_key.crv !== "P-256" || challenge.public_key.kty !== "EC" ||
      !B64_32.test(challenge.public_key.x) || !B64_32.test(challenge.public_key.y)) return false;
  let message;
  try { message = JSON.parse(challenge.message); } catch { return false; }
  if (!Array.isArray(message) || message.length !== 10 ||
      message[0] !== DEVICE_AUD || message[1] !== installationId ||
      message[2] !== workerId || message[3] !== challengeId ||
      typeof message[4] !== "string" || !B64_32.test(message[4]) ||
      message[5] !== challenge.identity_public_key_sha256 ||
      message[6] !== challenge.chatgpt_target_sha256 ||
      message[7] !== challenge.browser_profile_sha256 ||
      message[8] !== challenge.bridge_identity_sha256 ||
      message[9] !== challenge.expires_at_ms ||
      challenge.message !== JSON.stringify(message)) return false;
  try {
    const raw = atob(message[4].replaceAll("-", "+").replaceAll("_", "/") + "=");
    if (raw.length !== 32) return false;
    const thumbprint = await shaHex(cryptoImpl.subtle, utf8(JSON.stringify(challenge.public_key)));
    const nonceHash = await shaHex(cryptoImpl.subtle, utf8(message[4]));
    if (thumbprint !== challenge.identity_public_key_sha256 ||
        nonceHash !== challenge.nonce_sha256) return false;
    const publicKey = await cryptoImpl.subtle.importKey("jwk", challenge.public_key,
      { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await cryptoImpl.subtle.verify({ name: "ECDSA", hash: "SHA-256" },
      publicKey, signature, utf8(challenge.message)) === true;
  } catch { return false; }
}

// TRUST: store must be one installation-scoped, serializable DO transaction.
// authorizeHumanSubject MUST obtain a keyed subject fingerprint from the
// platform-verified human/worker/action, not any browser-supplied boolean.
// readAssignments defaults to verified Access + private GitHub App broker.
// Neither injected callbacks nor mock Access contexts are proof of production.
export function createProtectedInactivePairing({
  store, installationId, authorizeHumanSubject,
  readAssignments = readAdminWorkerAssignments, cryptoImpl = crypto,
  clock = () => Date.now(),
  authorizeAccess = async (ctx, env) =>
    (await inspectAdminRuntimeAccess(ctx, env)) === "AUTHORIZED",
}) {
  if (typeof store?.atomic !== "function" ||
      typeof installationId !== "string" || !INSTALL.test(installationId) ||
      typeof authorizeHumanSubject !== "function" ||
      typeof readAssignments !== "function" ||
      typeof authorizeAccess !== "function" ||
      typeof cryptoImpl?.subtle?.verify !== "function" ||
      typeof cryptoImpl?.subtle?.digest !== "function" ||
      typeof clock !== "function") throw Error("PROTECTED_PAIRING_ADAPTER_INVALID");

  async function finalize({ worker_id, device_challenge_id, device_signature,
    admin_challenge_id, admin_one_time_nonce, env, executionCtx } = {}) {
    if (env?.BKE_PREPRODUCTION !== "true" ||
        env?.BKE_ACCESS_POLICY_VERIFIED !== "true" ||
        env?.BKE_ADMIN_PR_INVENTORY_ENABLED !== "true" ||
        env?.BKE_ADMIN_PAIRING_ACTIONS_ENABLED !== "true" ||
        env?.BKE_ADMIN_PROTECTED_PAIRING_ENABLED !== "true") {
      return fail("PROTECTED_PAIRING_LOCKED");
    }
    const signature = decode64(device_signature);
    if (typeof worker_id !== "string" || !WORKER.test(worker_id) ||
        typeof device_challenge_id !== "string" || !H48.test(device_challenge_id) ||
        typeof admin_challenge_id !== "string" || !H32.test(admin_challenge_id) ||
        typeof admin_one_time_nonce !== "string" || !H64.test(admin_one_time_nonce) ||
        !signature) return fail("PROTECTED_PAIRING_PROOF_INVALID");
    // Inside the DO, the injected Access adapter accepts ONLY a previously
    // HMAC-verified, locally branded internal context. Never deserialize an
    // arbitrary browser/user Access object as trusted evidence.
    let authorized = false;
    try { authorized = (await authorizeAccess(executionCtx, env)) === true; }
    catch { /* fail closed on uncertain platform identity */ }
    if (!authorized) return fail("PROTECTED_PAIRING_ADMIN_DENIED");
    let subject;
    try { subject = await authorizeHumanSubject("pair", worker_id, executionCtx); }
    catch { return fail("PROTECTED_PAIRING_ADMIN_DENIED"); }
    if (typeof subject !== "string" || !H64.test(subject)) {
      return fail("PROTECTED_PAIRING_ADMIN_DENIED");
    }
    let observed;
    try { observed = await readAssignments(env, executionCtx); }
    catch { return fail("PROTECTED_PAIRING_GITHUB_UNAVAILABLE"); }
    const prs = inventoryClaims(observed, installationId, worker_id);
    if (!prs) return fail("PROTECTED_PAIRING_GITHUB_AMBIGUOUS");
    let now;
    try { now = clock(); } catch { return fail("PROTECTED_PAIRING_CLOCK_INVALID"); }
    if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - 3600000) {
      return fail("PROTECTED_PAIRING_CLOCK_INVALID");
    }
    let adminHash;
    try {
      adminHash = await shaHex(cryptoImpl.subtle, utf8(JSON.stringify([
        HUMAN_AUD, installationId, "pair", worker_id,
        admin_challenge_id, subject, admin_one_time_nonce,
      ])));
    } catch { return fail("PROTECTED_PAIRING_CRYPTO_UNAVAILABLE"); }

    try {
      return await store.atomic(async tx => {
        const paired = (await tx.get("paired")) ?? [];
        const pending = (await tx.get("pending")) ?? [];
        const tickets = (await tx.get("admin_actions")) ?? [];
        if (!isSafePairedRegistry(paired) || !isSafePendingChallenges(pending) ||
            !safePendingUniqueness(pending) || !isSafeAdminActionTickets(tickets)) {
          return fail("PROTECTED_PAIRING_REGISTRY_AMBIGUOUS");
        }
        const action = tickets.find(t => t.challenge_id === admin_challenge_id);
        if (!action || action.status !== "PENDING" || action.action !== "pair" ||
            action.worker_id !== worker_id || action.subject_sha256 !== subject ||
            action.nonce_sha256 !== adminHash || action.expires_at_ms <= now ||
            action.expires_at_ms > now + 90000) {
          return fail("PROTECTED_PAIRING_TICKET_MISSING_OR_USED");
        }
        const matching = pending.filter(p =>
          p.worker_id === worker_id && p.challenge_id === device_challenge_id);
        if (matching.length !== 1) return fail("PROTECTED_PAIRING_CHALLENGE_MISSING_OR_USED");
        const challenge = matching[0];
        if (!await deviceProofValid(challenge, worker_id, device_challenge_id,
          signature, installationId, cryptoImpl, now)) return fail("PROTECTED_PAIRING_DEVICE_PROOF_INVALID");
        const decision = evaluateWorkerEnrollment({
          candidate: { ...challenge },
          pairedWorkers: paired, openPullRequests: prs,
          inventoryVerified: true, prSnapshotVerified: true, nowMs: now,
        });
        if (decision.state !== "READY_FOR_HUMAN_REVIEW") {
          return fail("PROTECTED_PAIRING_ELIGIBILITY_DENIED");
        }
        if (paired.length >= 100) return fail("PROTECTED_PAIRING_REGISTRY_FULL");
        // ALL three writes are in one serializable transaction. Rollback on
        // any storage error; no separate ticket consumption or partially
        // registered identity. Still no active lease or permission to wake.
        await tx.put("paired", [...paired, {
          worker_id, identity_public_key_sha256: challenge.identity_public_key_sha256,
          ...Object.fromEntries(RESOURCE.map(k => [k, challenge[k]])),
          nonce_sha256: challenge.nonce_sha256,
          status: "PAIRED_INACTIVE", registered_at_ms: now,
          enrollment_expires_at_ms: now + 3600000,
        }]);
        await tx.put("pending", pending.filter(p => p.challenge_id !== device_challenge_id));
        await tx.put("admin_actions", tickets.map(t => t.challenge_id === admin_challenge_id
          ? { ...t, status: "CONSUMED" } : t));
        return Object.freeze({ state: "PAIRED_INACTIVE", code: "PROTECTED_PAIRING_INACTIVE_ONLY" });
      });
    } catch { return fail("PROTECTED_PAIRING_STORAGE_UNAVAILABLE"); }
  }
  return Object.freeze({ finalize });
}
