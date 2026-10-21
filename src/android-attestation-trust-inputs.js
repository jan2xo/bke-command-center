const POLICY_SCHEMA = "bke.android-key-attestation-policy.v1";
const GOOGLE_STATUS_URL = "https://android.googleapis.com/attestation/status";
const HASH256 = /^[a-f0-9]{64}$/u;
const PACKAGE_NAME = /^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$/u;
const SERIAL_KEY = /^[a-f1-9][a-f0-9]{0,63}$/u;
const SERIAL_INPUT = /^[a-fA-F0-9]{1,64}$/u;
const REASONS = new Set(["UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "SUPERSEDED", "SOFTWARE_FLAW"]);
const STATUSES = new Set(["REVOKED", "SUSPENDED"]);
const MAX_ROOT_PINS = 8;
const MAX_SIGNER_DIGESTS = 8;
const MAX_BODY_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 3000;
const MAX_FRESHNESS_MS = 6 * 60 * 60 * 1000;
const MIN_SNAPSHOT_FRESHNESS_MS = 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const POLICY_FIELDS = [
  "schema", "version", "policyVersion", "approvalStatus", "approvalReference",
  "approvedAtMs", "approvedRootFingerprints256", "approvedPackageName",
  "approvedSigningCertificateSha256Digests",
];
const SNAPSHOT_FIELDS = ["source", "fetchedAtMs", "cacheMaxAgeMs", "entries"];

const blocked = (code, extra = {}) => Object.freeze({ state: "BLOCKED", code, authority: "NONE", ...extra });
const isRecord = (v) => v !== null && typeof v === "object" && !Array.isArray(v) &&
  (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
const hasExactKeys = (v, keys) => isRecord(v) &&
  Object.keys(v).sort().join(",") === [...keys].sort().join(",");
const isSafeTime = (v) => Number.isSafeInteger(v) && v > 0 && v < Number.MAX_SAFE_INTEGER - MAX_FRESHNESS_MS;

function validCalendarDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/u.test(value)) return false;
  const parsed = Date.parse(value + "T00:00:00.000Z");
  return Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 10) === value;
}

function cloneJson(value) {
  try {
    return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
  } catch {
    return undefined;
  }
}

function validUniquePins(value, limit) {
  return Array.isArray(value) && value.length >= 1 && value.length <= limit &&
    value.every((item) => typeof item === "string" && HASH256.test(item)) &&
    new Set(value).size === value.length;
}

/**
 * Validate a server-owned, owner-provisioned policy input.
 * A successful shape check is not proof of provenance and always carries authority NONE.
 * No root or signer pins are configured by this module.
 */
export function validateAndroidAttestationPolicy(candidate, atMs = Date.now()) {
  if (candidate === null || candidate === undefined) return blocked("POLICY_MISSING");
  if (!hasExactKeys(candidate, POLICY_FIELDS) || candidate.schema !== POLICY_SCHEMA) {
    return blocked("POLICY_INVALID");
  }
  if (candidate.version !== 1 || typeof candidate.policyVersion !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(candidate.policyVersion)) {
    return blocked("POLICY_VERSION_UNSUPPORTED");
  }
  if (!["APPROVED", "UNAPPROVED", "REVOKED"].includes(candidate.approvalStatus)) {
    return blocked("POLICY_INVALID");
  }
  if (candidate.approvalStatus === "REVOKED") return blocked("POLICY_REVOKED");
  if (candidate.approvalStatus === "UNAPPROVED") return blocked("POLICY_UNAPPROVED");
  if (!isSafeTime(atMs) || !isSafeTime(candidate.approvedAtMs) || candidate.approvedAtMs > atMs ||
      typeof candidate.approvalReference !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}$/u.test(candidate.approvalReference)) {
    return blocked("POLICY_INVALID");
  }
  if (!validUniquePins(candidate.approvedRootFingerprints256, MAX_ROOT_PINS) ||
      typeof candidate.approvedPackageName !== "string" ||
      !PACKAGE_NAME.test(candidate.approvedPackageName) ||
      !validUniquePins(candidate.approvedSigningCertificateSha256Digests, MAX_SIGNER_DIGESTS)) {
    return blocked("POLICY_INVALID");
  }
  const policy = Object.freeze({
    schema: POLICY_SCHEMA,
    version: 1,
    policyVersion: candidate.policyVersion,
    approvalStatus: "APPROVED",
    approvalReference: candidate.approvalReference,
    approvedAtMs: candidate.approvedAtMs,
    approvedRootFingerprints256: Object.freeze([...candidate.approvedRootFingerprints256]),
    approvedPackageName: candidate.approvedPackageName,
    approvedSigningCertificateSha256Digests: Object.freeze([...candidate.approvedSigningCertificateSha256Digests]),
  });
  return Object.freeze({ state: "POLICY_INPUT_VALID", policy, authority: "NONE" });
}

/**
 * Compare already-extracted identity fields against the validated policy.
 * This is pin membership policy only; it does not inspect or verify any certificate.
 */
export function evaluateAndroidAttestationIdentity(policyCandidate, observedIdentity, atMs = Date.now()) {
  const checked = validateAndroidAttestationPolicy(policyCandidate, atMs);
  if (checked.state !== "POLICY_INPUT_VALID") return checked;
  if (!hasExactKeys(observedIdentity, ["rootFingerprint256", "packageName", "signingCertificateSha256"]) ||
      typeof observedIdentity.rootFingerprint256 !== "string" ||
      !HASH256.test(observedIdentity.rootFingerprint256) ||
      typeof observedIdentity.packageName !== "string" ||
      !PACKAGE_NAME.test(observedIdentity.packageName) ||
      typeof observedIdentity.signingCertificateSha256 !== "string" ||
      !HASH256.test(observedIdentity.signingCertificateSha256)) {
    return blocked("ATTESTATION_IDENTITY_INVALID");
  }
  if (!checked.policy.approvedRootFingerprints256.includes(observedIdentity.rootFingerprint256)) {
    return blocked("ROOT_NOT_APPROVED", { policyVersion: checked.policy.policyVersion });
  }
  if (observedIdentity.packageName !== checked.policy.approvedPackageName) {
    return blocked("PACKAGE_NOT_APPROVED", { policyVersion: checked.policy.policyVersion });
  }
  if (!checked.policy.approvedSigningCertificateSha256Digests.includes(observedIdentity.signingCertificateSha256)) {
    return blocked("APP_SIGNER_NOT_APPROVED", { policyVersion: checked.policy.policyVersion });
  }
  return Object.freeze({
    state: "IDENTITY_POLICY_MATCH",
    policyVersion: checked.policy.policyVersion,
    authority: "NONE",
  });
}

function errorWithCode(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function parseCacheLifetime(headers) {
  const cacheControl = headers.get("cache-control");
  if (typeof cacheControl !== "string" || cacheControl.length > 2048) {
    return { error: "CACHE_CONTROL_INVALID" };
  }
  const directives = cacheControl.split(",").map((part) => part.trim().toLowerCase());
  if (directives.some((part) => part === "no-cache" || part === "no-store" || part === "max-age")) {
    return { error: "CACHE_CONTROL_INVALID" };
  }
  const maxAgeDirectives = directives.filter((part) => /^max-age=/u.test(part));
  if (maxAgeDirectives.length !== 1) return { error: "CACHE_CONTROL_INVALID" };
  const match = /^max-age=(?:([0-9]+)|"([0-9]+)")$/u.exec(maxAgeDirectives[0]);
  if (!match) return { error: "CACHE_CONTROL_INVALID" };
  const maxAgeSeconds = Number(match[1] ?? match[2]);
  if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds < 1 ||
      maxAgeSeconds > Math.floor(Number.MAX_SAFE_INTEGER / 1000)) {
    return { error: "CACHE_CONTROL_INVALID" };
  }
  const ageHeader = headers.get("age");
  let ageSeconds = 0;
  if (ageHeader !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(ageHeader)) return { error: "AGE_HEADER_INVALID" };
    ageSeconds = Number(ageHeader);
    if (!Number.isSafeInteger(ageSeconds) || ageSeconds > Math.floor(Number.MAX_SAFE_INTEGER / 1000)) {
      return { error: "AGE_HEADER_INVALID" };
    }
  }
  const upstreamRemainingMs = maxAgeSeconds * 1000 - ageSeconds * 1000;
  const effectiveFreshnessMs = Math.min(upstreamRemainingMs, MAX_FRESHNESS_MS);
  if (!Number.isSafeInteger(effectiveFreshnessMs) || effectiveFreshnessMs < MIN_SNAPSHOT_FRESHNESS_MS) {
    return { error: "CACHE_NOT_FRESH_ENOUGH" };
  }
  return { effectiveFreshnessMs };
}

function parseStatusEntries(payload) {
  if (!hasExactKeys(payload, ["entries"]) || !isRecord(payload.entries)) {
    throw errorWithCode("STATUS_SCHEMA_INVALID");
  }
  const entries = Object.create(null);
  const sourceEntries = Object.entries(payload.entries);
  if (sourceEntries.length > 100000) throw errorWithCode("STATUS_SCHEMA_INVALID");
  for (const [serial, detail] of sourceEntries) {
    if (!SERIAL_KEY.test(serial) || serial.length > 64 || !isRecord(detail) ||
        !Object.hasOwn(detail, "status") || !STATUSES.has(detail.status) ||
        Object.keys(detail).some((key) => !["status", "expires", "reason"].includes(key))) {
      throw errorWithCode("STATUS_SCHEMA_INVALID");
    }
    if (Object.hasOwn(detail, "expires") && !validCalendarDate(detail.expires)) {
      throw errorWithCode("STATUS_SCHEMA_INVALID");
    }
    if (Object.hasOwn(detail, "reason") && !REASONS.has(detail.reason)) {
      throw errorWithCode("STATUS_SCHEMA_INVALID");
    }
    const normalized = { status: detail.status };
    if (Object.hasOwn(detail, "expires")) normalized.expires = detail.expires;
    entries[serial] = Object.freeze(normalized);
  }
  return Object.freeze(entries);
}

async function readBoundedJson(response) {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength)) throw errorWithCode("CONTENT_LENGTH_INVALID");
    const length = Number(contentLength);
    if (!Number.isSafeInteger(length) || length > MAX_BODY_BYTES) throw errorWithCode("STATUS_BODY_TOO_LARGE");
  }
  const chunks = [];
  let total = 0;
  if (response.body && typeof response.body.getReader === "function") {
    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_BODY_BYTES) {
          try { await reader.cancel(); } catch {}
          throw errorWithCode("STATUS_BODY_TOO_LARGE");
        }
        chunks.push(value);
      }
    } finally {
      try { reader.releaseLock(); } catch {}
    }
  } else {
    const bytes = new Uint8Array(await response.arrayBuffer());
    total = bytes.byteLength;
    if (total > MAX_BODY_BYTES) throw errorWithCode("STATUS_BODY_TOO_LARGE");
    chunks.push(bytes);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  let decoded;
  try { decoded = new TextDecoder("utf-8", { fatal: true }).decode(body); }
  catch { throw errorWithCode("STATUS_JSON_INVALID"); }
  try { return JSON.parse(decoded); }
  catch { throw errorWithCode("STATUS_JSON_INVALID"); }
}

function cloneSnapshot(snapshot) {
  const entries = Object.create(null);
  for (const [serial, detail] of Object.entries(snapshot.entries)) {
    entries[serial] = Object.freeze({ ...detail });
  }
  return Object.freeze({
    source: snapshot.source,
    fetchedAtMs: snapshot.fetchedAtMs,
    cacheMaxAgeMs: snapshot.cacheMaxAgeMs,
    entries: Object.freeze(entries),
  });
}

function validateSnapshot(snapshot, atMs) {
  if (!hasExactKeys(snapshot, SNAPSHOT_FIELDS) || snapshot.source !== GOOGLE_STATUS_URL ||
      !isSafeTime(snapshot.fetchedAtMs) || !Number.isSafeInteger(snapshot.cacheMaxAgeMs) ||
      snapshot.cacheMaxAgeMs < MIN_SNAPSHOT_FRESHNESS_MS ||
      snapshot.cacheMaxAgeMs > MAX_FRESHNESS_MS || atMs < snapshot.fetchedAtMs ||
      atMs >= snapshot.fetchedAtMs + snapshot.cacheMaxAgeMs || !isRecord(snapshot.entries)) {
    return false;
  }
  try {
    parseStatusEntries({ entries: snapshot.entries });
    return true;
  } catch {
    return false;
  }
}

/**
 * Create a private Google revocation-status loader. The URL, headers, redirect
 * policy, timeout and freshness bounds are constants, not caller parameters.
 * Inject fetch/clock only to test transport and time behavior. Results never
 * confer enrollment, pairing, verifier, or dispatch authority.
 */
export function createGoogleAttestationRevocationLoader({
  serverOwnedPolicy,
  fetchImpl = globalThis.fetch,
  now = () => Date.now(),
} = {}) {
  const policySnapshot = cloneJson(serverOwnedPolicy);
  let cached = null;
  let inFlight = null;
  let lastObservedNowMs = null;

  function readClock() {
    let value;
    try { value = now(); } catch { return null; }
    if (!isSafeTime(value) || (lastObservedNowMs !== null && value < lastObservedNowMs)) return null;
    lastObservedNowMs = value;
    return value;
  }

  async function refresh() {
    if (typeof fetchImpl !== "function") return { blocked: blocked("FETCH_UNAVAILABLE") };
    const controller = new AbortController();
    let timedOut = false;
    let timer;
    const work = (async () => {
      try {
        const response = await fetchImpl(GOOGLE_STATUS_URL, {
          method: "GET",
          headers: { accept: "application/json" },
          redirect: "error",
          signal: controller.signal,
        });
        if (!response || !response.headers || typeof response.status !== "number") {
          throw errorWithCode("STATUS_RESPONSE_INVALID");
        }
        if (response.status >= 300 && response.status < 400) throw errorWithCode("REDIRECT_REJECTED");
        if (response.status !== 200) throw errorWithCode("HTTP_STATUS_BLOCKED");
        if (response.url && response.url !== GOOGLE_STATUS_URL) throw errorWithCode("STATUS_SOURCE_MISMATCH");
        const contentType = response.headers.get("content-type");
        if (typeof contentType !== "string" || !/^application\/json(?:\s*;|\s*$)/iu.test(contentType)) {
          throw errorWithCode("CONTENT_TYPE_INVALID");
        }
        const payload = await readBoundedJson(response);
        const entries = parseStatusEntries(payload);
        const receivedAtMs = readClock();
        if (receivedAtMs === null) throw errorWithCode("CLOCK_UNCERTAIN");
        const dateHeader = response.headers.get("date");
        const serverDateMs = typeof dateHeader === "string" ? Date.parse(dateHeader) : NaN;
        if (!Number.isFinite(serverDateMs) || Math.abs(serverDateMs - receivedAtMs) > MAX_CLOCK_SKEW_MS) {
          throw errorWithCode("CLOCK_UNCERTAIN");
        }
        const freshness = parseCacheLifetime(response.headers);
        if (freshness.error) throw errorWithCode(freshness.error);
        const expiresAtMs = receivedAtMs + freshness.effectiveFreshnessMs;
        if (!isSafeTime(expiresAtMs) || expiresAtMs <= receivedAtMs) throw errorWithCode("CLOCK_UNCERTAIN");
        const snapshot = Object.freeze({
          source: GOOGLE_STATUS_URL,
          fetchedAtMs: receivedAtMs,
          cacheMaxAgeMs: freshness.effectiveFreshnessMs,
          entries,
        });
        return { cache: Object.freeze({ snapshot, expiresAtMs }) };
      } catch (error) {
        const code = error?.code ??
          (timedOut || error?.name === "TimeoutError" || error?.name === "AbortError"
            ? "FETCH_TIMEOUT" : "FETCH_FAILED");
        return { blocked: blocked(code) };
      }
    })();
    const deadline = new Promise((resolve) => {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
        resolve({ blocked: blocked("FETCH_TIMEOUT") });
      }, REQUEST_TIMEOUT_MS);
    });
    try {
      // The race enforces the deadline even if a fetch adapter ignores AbortSignal.
      // Late completions are handled by work but cannot replace the timed-out result.
      return await Promise.race([work, deadline]);
    } finally {
      clearTimeout(timer);
    }
  }
  function available(cache) {
    return Object.freeze({
      state: "REVOCATION_STATUS_AVAILABLE",
      revocationSnapshot: cloneSnapshot(cache.snapshot),
      expiresAtMs: cache.expiresAtMs,
      authority: "NONE",
    });
  }

  async function load() {
    const atStart = readClock();
    if (atStart === null) return blocked("CLOCK_UNCERTAIN");
    const policyResult = validateAndroidAttestationPolicy(policySnapshot, atStart);
    if (policyResult.state !== "POLICY_INPUT_VALID") {
      return blocked(policyResult.code ?? "POLICY_INVALID");
    }
    if (cached && atStart < cached.expiresAtMs) return available(cached);

    let active = inFlight;
    if (!active) {
      active = refresh();
      inFlight = active;
    }
    let outcome;
    try { outcome = await active; }
    finally { if (inFlight === active) inFlight = null; }
    if (outcome.blocked) return outcome.blocked;

    const atReturn = readClock();
    if (atReturn === null) return blocked("CLOCK_UNCERTAIN");
    if (atReturn >= outcome.cache.expiresAtMs || !validateSnapshot(outcome.cache.snapshot, atReturn)) {
      cached = null;
      return blocked("REVOCATION_STATUS_STALE");
    }
    cached = outcome.cache;
    return available(cached);
  }

  return Object.freeze({ load });
}

/** Check a certificate serial against a fresh compatible snapshot. */
export function evaluateGoogleAttestationRevocation(snapshot, certificateSerial) {
  const atMs = Date.now();
  if (!isSafeTime(atMs) || !validateSnapshot(snapshot, atMs)) {
    return blocked("REVOCATION_STATUS_STALE_OR_INVALID");
  }
  if (typeof certificateSerial !== "string" || !SERIAL_INPUT.test(certificateSerial)) {
    return blocked("CERTIFICATE_SERIAL_INVALID");
  }
  const normalized = certificateSerial.toLowerCase().replace(/^0+/u, "");
  if (!normalized || normalized.length > 64 || !/^[a-f1-9][a-f0-9]{0,63}$/u.test(normalized)) {
    return blocked("CERTIFICATE_SERIAL_INVALID");
  }
  const entry = snapshot.entries[normalized];
  if (!entry) return Object.freeze({ state: "NOT_LISTED", authority: "NONE" });
  if (entry.status === "REVOKED") return blocked("CERTIFICATE_REVOKED");
  if (entry.status === "SUSPENDED") return blocked("CERTIFICATE_SUSPENDED");
  return blocked("STATUS_ENTRY_INVALID");
}

export const androidAttestationTrustInputConstants = Object.freeze({
  policySchema: POLICY_SCHEMA,
  revocationStatusUrl: GOOGLE_STATUS_URL,
  maxBodyBytes: MAX_BODY_BYTES,
  requestTimeoutMs: REQUEST_TIMEOUT_MS,
  maxFreshnessMs: MAX_FRESHNESS_MS,
  minSnapshotFreshnessMs: MIN_SNAPSHOT_FRESHNESS_MS,
});
