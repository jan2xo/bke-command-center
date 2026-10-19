// Dormant internal pairing action tickets; NEVER an HTTP route or device grant.
// Callbacks must be trusted Cloudflare server code with platform-verified
// per-action human Access identity. Never accept browser-supplied verification.
const AUDIENCE = "bke-command-center/preproduction/admin-action/v1";
const WORKER = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const INSTALL = /^[1-9][0-9]{0,19}$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
const HEX32 = /^[0-9a-f]{32}$/u;
const TTL_MS = 90_000;
const MAX_TICKETS = 100;
const ACTIONS = new Set(["pair", "revoke"]);
const blocked = code => Object.freeze({ state: "BLOCKED", code });
const hex = bytes => Array.from(bytes, x => x.toString(16).padStart(2, "0")).join("");
const utf8 = s => new TextEncoder().encode(s);

function validTicket(t) {
  return t && typeof t === "object" && !Array.isArray(t) &&
    Object.keys(t).sort().join(",") ===
      "action,challenge_id,expires_at_ms,nonce_sha256,status,subject_sha256,worker_id" &&
    ACTIONS.has(t.action) && WORKER.test(t.worker_id) &&
    HEX32.test(t.challenge_id) && HEX64.test(t.nonce_sha256) &&
    HEX64.test(t.subject_sha256) &&
    Number.isSafeInteger(t.expires_at_ms) && t.expires_at_ms >= 0 &&
    ["PENDING", "CONSUMED"].includes(t.status);
}
function registryIsSafe(rows) {
  if (!Array.isArray(rows) || rows.length > MAX_TICKETS) return false;
  const ids = new Set();
  const hashes = new Set();
  for (const row of rows) {
    if (!validTicket(row) || ids.has(row.challenge_id) || hashes.has(row.nonce_sha256)) return false;
    ids.add(row.challenge_id);
    hashes.add(row.nonce_sha256);
  }
  return true;
}

export function createAdminOneTimeActionTickets({
  store, authorizeAdmin, installationId,
  cryptoImpl = crypto, clock = () => Date.now(),
}) {
  if (typeof store?.atomic !== "function" ||
      typeof authorizeAdmin !== "function" ||
      typeof installationId !== "string" || !INSTALL.test(installationId) ||
      typeof cryptoImpl?.getRandomValues !== "function" ||
      typeof cryptoImpl?.subtle?.digest !== "function" ||
      typeof clock !== "function") throw Error("ADMIN_ACTION_ADAPTER_INVALID");

  async function subject(action, workerId, context) {
    try {
      // The trusted callback derives an opaque keyed SHA-256 identifier from
      // already platform-verified Cloudflare Access human identity.
      const result = await authorizeAdmin(action, workerId, context);
      return typeof result === "string" && HEX64.test(result) ? result : null;
    } catch { return null; }
  }
  function timestamp() {
    try {
      const value = clock();
      return Number.isSafeInteger(value) && value >= 0 &&
        value <= Number.MAX_SAFE_INTEGER - TTL_MS ? value : null;
    } catch { return null; }
  }
  async function digest(action, workerId, challengeId, subjectId, nonce) {
    try {
      return hex(new Uint8Array(await cryptoImpl.subtle.digest("SHA-256", utf8(JSON.stringify([
        AUDIENCE, installationId, action, workerId, challengeId, subjectId, nonce,
      ])))));
    } catch { return null; }
  }
  async function atomic(operation) {
    try { return await store.atomic(operation); }
    catch { return blocked("ADMIN_ACTION_STORAGE_UNAVAILABLE"); }
  }

  async function issue({ action, worker_id, admin_context } = {}) {
    if (!ACTIONS.has(action) || typeof worker_id !== "string" || !WORKER.test(worker_id)) {
      return blocked("ADMIN_ACTION_REQUEST_INVALID");
    }
    const id = await subject(action, worker_id, admin_context);
    if (!id) return blocked("ADMIN_ACTION_HUMAN_DENIED");
    const now = timestamp();
    if (now === null) return blocked("ADMIN_ACTION_CLOCK_INVALID");
    let challenge_id, one_time_nonce;
    try {
      const random = new Uint8Array(48);
      cryptoImpl.getRandomValues(random);
      challenge_id = hex(random.slice(0, 16));
      one_time_nonce = hex(random.slice(16));
    } catch { return blocked("ADMIN_ACTION_RANDOM_UNAVAILABLE"); }
    const nonce_sha256 = await digest(action, worker_id, challenge_id, id, one_time_nonce);
    if (!nonce_sha256) return blocked("ADMIN_ACTION_CRYPTO_UNAVAILABLE");
    const expires_at_ms = now + TTL_MS;
    return atomic(async tx => {
      const rows = (await tx.get("admin_actions")) ?? [];
      if (!registryIsSafe(rows)) return blocked("ADMIN_ACTION_REGISTRY_AMBIGUOUS");
      const active = rows.filter(t => t.expires_at_ms > now);
      if (active.length >= MAX_TICKETS || active.some(t =>
          t.status === "PENDING" && t.worker_id === worker_id) ||
          active.some(t => t.challenge_id === challenge_id || t.nonce_sha256 === nonce_sha256)) {
        return blocked("ADMIN_ACTION_PENDING_CONFLICT");
      }
      await tx.put("admin_actions", [...active, {
        action, worker_id, subject_sha256: id, challenge_id,
        nonce_sha256, expires_at_ms, status: "PENDING",
      }]);
      // The raw nonce is returned only after the durable write.
      // Do not log or persist it. This is NOT a worker pairing/lease token.
      return Object.freeze({
        state: "ISSUED_FOR_CONFIRMATION", action, worker_id,
        challenge_id, one_time_nonce, expires_at_ms,
      });
    });
  }

  async function consume({ action, worker_id, challenge_id, one_time_nonce, admin_context } = {}) {
    if (!ACTIONS.has(action) || typeof worker_id !== "string" || !WORKER.test(worker_id) ||
        typeof challenge_id !== "string" || !HEX32.test(challenge_id) ||
        typeof one_time_nonce !== "string" || !HEX64.test(one_time_nonce)) {
      return blocked("ADMIN_ACTION_PROOF_INVALID");
    }
    const id = await subject(action, worker_id, admin_context);
    if (!id) return blocked("ADMIN_ACTION_HUMAN_DENIED");
    const now = timestamp();
    if (now === null) return blocked("ADMIN_ACTION_CLOCK_INVALID");
    const nonce_sha256 = await digest(action, worker_id, challenge_id, id, one_time_nonce);
    if (!nonce_sha256) return blocked("ADMIN_ACTION_CRYPTO_UNAVAILABLE");
    return atomic(async tx => {
      const rows = (await tx.get("admin_actions")) ?? [];
      if (!registryIsSafe(rows)) return blocked("ADMIN_ACTION_REGISTRY_AMBIGUOUS");
      const match = rows.find(t => t.challenge_id === challenge_id);
      if (!match || match.status !== "PENDING" || match.expires_at_ms <= now ||
          match.action !== action || match.worker_id !== worker_id ||
          match.subject_sha256 !== id || match.nonce_sha256 !== nonce_sha256) {
        return blocked("ADMIN_ACTION_PROOF_MISSING_OR_USED");
      }
      await tx.put("admin_actions", rows.map(t => t.challenge_id === challenge_id ?
        { ...t, status: "CONSUMED" } : t));
      // Never grant pairing, revocation or dispatch authority from this result.
      return Object.freeze({ state: "CONSUMED_FOR_PREFLIGHT", code: "ADMIN_ACTION_SINGLE_USE_OK" });
    });
  }
  return Object.freeze({ issue, consume });
}

// Shared validation for the same-installation protected atomic finalizer.
export { registryIsSafe as isSafeAdminActionTickets };
