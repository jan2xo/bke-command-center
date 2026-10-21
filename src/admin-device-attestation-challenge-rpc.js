// Default-OFF, installation-scoped Android Key Attestation challenge ledger.
// This records nonce/replay state only. It never grants enrollment/session authority.
// Private named Durable Object RPC only; no public HTTP endpoint is added.
const AUDIENCE = "bke-command-center/preproduction/android-key-attestation/v1";
const PURPOSE = "android_key_attestation";
const MAX_TTL_MS = 30_000;
const MAX_ROWS = 100;
const WORKER = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const INSTALLATION = /^[1-9][0-9]{0,19}$/u;
const HEX32 = /^[a-f0-9]{32}$/u;
const HEX64 = /^[a-f0-9]{64}$/u;
const KEY_B64 = /^[A-Za-z0-9_-]{43}$/u;

const block = code => Object.freeze({ state: "BLOCKED", code, authority: "NONE" });
const exact = (value, keys) => value !== null && typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === keys.split(",").sort().join(",");
const enc = value => new TextEncoder().encode(value);
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");

function fromHex(value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) return null;
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function decodeSecret(value) {
  if (typeof value !== "string" || !KEY_B64.test(value)) return null;
  try {
    const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=");
    const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
    return bytes.length === 32 && bytesToBase64Url(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function flags(env) {
  return env?.BKE_PREPRODUCTION === "true" &&
    env?.BKE_DEVICE_ATTESTATION_CHALLENGE_RPC_ENABLED === "true";
}

function nowMs(clock) {
  try {
    const value = clock();
    return Number.isSafeInteger(value) && value > 0 &&
      value < Number.MAX_SAFE_INTEGER - MAX_TTL_MS ? value : null;
  } catch {
    return null;
  }
}

function commandFields(request) {
  if (request?.action === "issue" &&
      exact(request, "action,expires_at_ms,installation_id,issued_at_ms,operation_id,signature,worker_id")) {
    return [
      AUDIENCE, 1, "issue", request.installation_id, request.worker_id,
      PURPOSE, request.operation_id, request.issued_at_ms, request.expires_at_ms,
    ];
  }
  if (request?.action === "consume" &&
      exact(request, "action,challenge,challenge_id,expires_at_ms,installation_id,issued_at_ms,operation_id,signature,worker_id")) {
    return [
      AUDIENCE, 1, "consume", request.installation_id, request.worker_id,
      PURPOSE, request.challenge_id, request.challenge, request.operation_id,
      request.issued_at_ms, request.expires_at_ms,
    ];
  }
  return null;
}

async function verifyCommand(request, env, cryptoImpl) {
  const fields = commandFields(request);
  const secret = decodeSecret(env?.BKE_DEVICE_ATTESTATION_CHALLENGE_RPC_KEY_B64);
  const signature = fromHex(request?.signature, HEX64);
  if (!fields || !secret || !signature ||
      typeof cryptoImpl?.subtle?.importKey !== "function" ||
      typeof cryptoImpl?.subtle?.verify !== "function") return false;
  try {
    const key = await cryptoImpl.subtle.importKey(
      "raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["verify"],
    );
    return await cryptoImpl.subtle.verify("HMAC", key, signature, enc(JSON.stringify(fields)));
  } catch {
    return false;
  }
}

function validFreshCommand(request, now) {
  return Number.isSafeInteger(request.issued_at_ms) &&
    Number.isSafeInteger(request.expires_at_ms) &&
    request.issued_at_ms > 0 &&
    request.issued_at_ms <= now &&
    request.issued_at_ms >= now - MAX_TTL_MS &&
    request.expires_at_ms > now &&
    request.expires_at_ms <= request.issued_at_ms + MAX_TTL_MS &&
    typeof request.operation_id === "string" && HEX64.test(request.operation_id) &&
    typeof request.installation_id === "string" && INSTALLATION.test(request.installation_id) &&
    typeof request.worker_id === "string" && WORKER.test(request.worker_id);
}

function matchesInstallationObject(env, objectId, installationId) {
  try {
    const namespace = env?.BKE_WORKER_PAIRING_VAULT;
    if (typeof namespace?.idFromName !== "function" ||
        typeof objectId?.toString !== "function") return false;
    const expected = namespace.idFromName("installation:" + installationId)?.toString();
    return typeof expected === "string" && expected.length > 0 &&
      objectId.toString() === expected;
  } catch {
    return false;
  }
}

function validStoredRow(row) {
  return exact(row, "audience,challenge_id,challenge_sha256,consumed_at_ms,consume_operation_id,expires_at_ms,installation_id,issue_operation_id,issued_at_ms,purpose,worker_id") &&
    HEX32.test(row.challenge_id) && HEX64.test(row.challenge_sha256) &&
    INSTALLATION.test(row.installation_id) && WORKER.test(row.worker_id) &&
    row.audience === AUDIENCE && row.purpose === PURPOSE &&
    Number.isSafeInteger(row.issued_at_ms) && row.issued_at_ms > 0 &&
    Number.isSafeInteger(row.expires_at_ms) &&
    row.expires_at_ms > row.issued_at_ms &&
    row.expires_at_ms <= row.issued_at_ms + MAX_TTL_MS &&
    HEX64.test(row.issue_operation_id) &&
    (row.consumed_at_ms === null ||
      (Number.isSafeInteger(row.consumed_at_ms) &&
        row.consumed_at_ms >= row.issued_at_ms &&
        row.consumed_at_ms < row.expires_at_ms)) &&
    (row.consume_operation_id === null || HEX64.test(row.consume_operation_id)) &&
    ((row.consumed_at_ms === null) === (row.consume_operation_id === null));
}

function validLedger(rows) {
  if (!Array.isArray(rows) || rows.length > MAX_ROWS ||
      rows.some(row => !validStoredRow(row))) return false;
  const ids = new Set();
  const issueOperations = new Set();
  const consumeOperations = new Set();
  for (const row of rows) {
    if (ids.has(row.challenge_id) || issueOperations.has(row.issue_operation_id)) return false;
    ids.add(row.challenge_id);
    issueOperations.add(row.issue_operation_id);
    if (row.consume_operation_id !== null) {
      if (consumeOperations.has(row.consume_operation_id)) return false;
      consumeOperations.add(row.consume_operation_id);
    }
  }
  return true;
}

async function sha256Hex(value, cryptoImpl) {
  return hex(new Uint8Array(await cryptoImpl.subtle.digest("SHA-256", enc(value))));
}

async function issue({ request, env, objectId, store, cryptoImpl, clock }) {
  const now = nowMs(clock);
  if (now === null) return block("ATTESTATION_CHALLENGE_CLOCK_INVALID");
  if (!validFreshCommand(request, now)) return block("ATTESTATION_CHALLENGE_COMMAND_STALE");
  if (!matchesInstallationObject(env, objectId, request.installation_id)) {
    return block("ATTESTATION_CHALLENGE_INSTALLATION_MISMATCH");
  }
  if (!await verifyCommand(request, env, cryptoImpl)) {
    return block("ATTESTATION_CHALLENGE_COMMAND_INVALID");
  }
  if (typeof store?.atomic !== "function") return block("ATTESTATION_CHALLENGE_STORAGE_UNAVAILABLE");

  let challengeId;
  let challenge;
  let challengeHash;
  try {
    const idBytes = new Uint8Array(16);
    const nonceBytes = new Uint8Array(32);
    cryptoImpl.getRandomValues(idBytes);
    cryptoImpl.getRandomValues(nonceBytes);
    challengeId = hex(idBytes);
    // Use a canonical 64-byte ASCII challenge, suitable for Android's
    // KeyDescription.attestationChallenge OCTET STRING (limit 128 bytes).
    challenge = hex(nonceBytes);
    challengeHash = await sha256Hex(challenge, cryptoImpl);
  } catch {
    return block("ATTESTATION_CHALLENGE_CRYPTO_UNAVAILABLE");
  }

  try {
    return await store.atomic(async tx => {
      const current = (await tx.get("attestation_challenges")) || [];
      if (!validLedger(current)) throw new Error("STORAGE_SHAPE_INVALID");
      const live = current.filter(row => row.expires_at_ms > now);
      if (live.length !== current.length) await tx.put("attestation_challenges", live);
      if (live.some(row => row.issue_operation_id === request.operation_id)) {
        return block("ATTESTATION_CHALLENGE_ISSUE_REPLAY");
      }
      if (live.length >= MAX_ROWS) return block("ATTESTATION_CHALLENGE_LEDGER_FULL");
      if (live.some(row => row.challenge_id === challengeId)) {
        return block("ATTESTATION_CHALLENGE_COLLISION");
      }
      const row = {
        challenge_id: challengeId,
        challenge_sha256: challengeHash,
        installation_id: request.installation_id,
        worker_id: request.worker_id,
        audience: AUDIENCE,
        purpose: PURPOSE,
        issued_at_ms: now,
        expires_at_ms: request.expires_at_ms,
        issue_operation_id: request.operation_id,
        consumed_at_ms: null,
        consume_operation_id: null,
      };
      await tx.put("attestation_challenges", [...live, row]);
      // The plaintext challenge is returned once over the named private RPC;
      // only its digest is retained in durable storage.
      return Object.freeze({
        state: "CHALLENGE_ISSUED",
        code: "ATTESTATION_CHALLENGE_ISSUED",
        authority: "NONE",
        challenge_id: challengeId,
        challenge,
        audience: AUDIENCE,
        purpose: PURPOSE,
        issued_at_ms: now,
        expires_at_ms: request.expires_at_ms,
      });
    });
  } catch {
    // An unknown write outcome is never retried or treated as issued.
    return block("ATTESTATION_CHALLENGE_ISSUE_OUTCOME_UNCERTAIN");
  }
}

async function consume({ request, env, objectId, store, cryptoImpl, clock }) {
  const now = nowMs(clock);
  if (now === null) return block("ATTESTATION_CHALLENGE_CLOCK_INVALID");
  if (!validFreshCommand(request, now) ||
      typeof request.challenge_id !== "string" || !HEX32.test(request.challenge_id) ||
      typeof request.challenge !== "string" || !HEX64.test(request.challenge)) {
    return block("ATTESTATION_CHALLENGE_COMMAND_STALE");
  }
  if (!matchesInstallationObject(env, objectId, request.installation_id)) {
    return block("ATTESTATION_CHALLENGE_INSTALLATION_MISMATCH");
  }
  if (!await verifyCommand(request, env, cryptoImpl)) {
    return block("ATTESTATION_CHALLENGE_COMMAND_INVALID");
  }
  if (typeof store?.atomic !== "function") return block("ATTESTATION_CHALLENGE_STORAGE_UNAVAILABLE");

  let challengeHash;
  try {
    challengeHash = await sha256Hex(request.challenge, cryptoImpl);
  } catch {
    return block("ATTESTATION_CHALLENGE_CRYPTO_UNAVAILABLE");
  }

  try {
    return await store.atomic(async tx => {
      const rows = (await tx.get("attestation_challenges")) || [];
      if (!validLedger(rows)) throw new Error("STORAGE_SHAPE_INVALID");
      const row = rows.find(candidate => candidate.challenge_id === request.challenge_id);
      if (!row) return block("ATTESTATION_CHALLENGE_UNKNOWN");
      if (row.installation_id !== request.installation_id ||
          row.worker_id !== request.worker_id ||
          row.audience !== AUDIENCE || row.purpose !== PURPOSE) {
        return block("ATTESTATION_CHALLENGE_SCOPE_MISMATCH");
      }
      if (!Number.isSafeInteger(row.expires_at_ms) || row.expires_at_ms <= now) {
        return block("ATTESTATION_CHALLENGE_EXPIRED");
      }
      if (row.consumed_at_ms !== null || row.consume_operation_id !== null) {
        return block("ATTESTATION_CHALLENGE_REPLAY");
      }
      if (rows.some(candidate => candidate.consume_operation_id === request.operation_id)) {
        return block("ATTESTATION_CHALLENGE_CONSUME_OPERATION_REPLAY");
      }
      if (row.challenge_sha256 !== challengeHash) {
        return block("ATTESTATION_CHALLENGE_VALUE_MISMATCH");
      }
      const next = rows.map(candidate => candidate.challenge_id === row.challenge_id
        ? { ...candidate, consumed_at_ms: now, consume_operation_id: request.operation_id }
        : candidate);
      await tx.put("attestation_challenges", next);
      // Consumption proves only single-use nonce lifecycle, never device trust.
      return Object.freeze({
        state: "CHALLENGE_CONSUMED",
        code: "ATTESTATION_CHALLENGE_CONSUMED",
        authority: "NONE",
        challenge_id: row.challenge_id,
        consumed_at_ms: now,
        audience: AUDIENCE,
        purpose: PURPOSE,
      });
    });
  } catch {
    return block("ATTESTATION_CHALLENGE_CONSUME_OUTCOME_UNCERTAIN");
  }
}

/**
 * Runs only inside the installation-named Durable Object's private named RPC.
 * The caller must already have performed platform Admin authorization and
 * derived installation/worker scope from trusted server-side sources.
 * This RPC additionally checks a dedicated HMAC command capability and the
 * actual Durable Object installation identity. The key and feature flag are
 * intentionally absent from the checked-in PREPRODUCTION configuration.
 */
export async function receiveDeviceAttestationChallenge({
  request, env, objectId, store, cryptoImpl = crypto, clock = () => Date.now(),
} = {}) {
  if (!flags(env)) return block("ATTESTATION_CHALLENGE_RPC_LOCKED");
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return block("ATTESTATION_CHALLENGE_COMMAND_INVALID");
  }
  if (request.action === "issue" &&
      exact(request, "action,expires_at_ms,installation_id,issued_at_ms,operation_id,signature,worker_id")) {
    return issue({ request, env, objectId, store, cryptoImpl, clock });
  }
  if (request.action === "consume" &&
      exact(request, "action,challenge,challenge_id,expires_at_ms,installation_id,issued_at_ms,operation_id,signature,worker_id")) {
    return consume({ request, env, objectId, store, cryptoImpl, clock });
  }
  return block("ATTESTATION_CHALLENGE_COMMAND_INVALID");
}
