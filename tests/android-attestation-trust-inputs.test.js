import test from "node:test";
import assert from "node:assert/strict";
import {
  androidAttestationTrustInputConstants as constants,
  createGoogleAttestationRevocationLoader,
  evaluateGoogleAttestationRevocation,
  evaluateAndroidAttestationIdentity,
  validateAndroidAttestationPolicy,
} from "../src/android-attestation-trust-inputs.js";

const URL = constants.revocationStatusUrl;
const NOW = Date.now();
const ROOT = "a".repeat(64);
const SIGNER = "b".repeat(64);
const OTHER = "c".repeat(64);

function makePolicy(overrides = {}) {
  return {
    schema: constants.policySchema,
    version: 1,
    policyVersion: "owner-approved-2026-01",
    approvalStatus: "APPROVED",
    approvalReference: "owner-review-2026-10-22",
    approvedAtMs: NOW - 10_000,
    approvedRootFingerprints256: [ROOT],
    approvedPackageName: "com.example.geckoworker",
    approvedSigningCertificateSha256Digests: [SIGNER],
    ...overrides,
  };
}

function response(payload = { entries: {} }, options = {}) {
  const now = options.now ?? NOW;
  const headers = new Headers({
    "content-type": options.contentType ?? "application/json; charset=utf-8",
    "cache-control": options.cacheControl ?? "public, max-age=3600",
    age: options.age ?? "0",
    date: options.date ?? new Date(now).toUTCString(),
    ...options.headers,
  });
  const body = options.rawBody ?? JSON.stringify(payload);
  return new Response(body, { status: options.status ?? 200, headers });
}

function loader({ policy = makePolicy(), fetchImpl, nowRef, now = () => nowRef?.value ?? NOW } = {}) {
  return createGoogleAttestationRevocationLoader({
    serverOwnedPolicy: policy,
    fetchImpl: fetchImpl ?? (async () => response({ entries: {} }, { now: now() })),
    now,
  });
}

test("valid policy is shape-checked but explicitly non-authoritative", () => {
  const result = validateAndroidAttestationPolicy(makePolicy(), NOW);
  assert.equal(result.state, "POLICY_INPUT_VALID");
  assert.equal(result.authority, "NONE");
  assert.deepEqual([...result.policy.approvedRootFingerprints256], [ROOT]);
});

test("missing, invalid, unknown-version, unapproved and revoked policies fail closed distinctly", () => {
  assert.equal(validateAndroidAttestationPolicy(null, NOW).code, "POLICY_MISSING");
  assert.equal(validateAndroidAttestationPolicy({ ...makePolicy(), invented: true }, NOW).code, "POLICY_INVALID");
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ version: 2 }), NOW).code, "POLICY_VERSION_UNSUPPORTED");
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ approvalStatus: "UNAPPROVED" }), NOW).code, "POLICY_UNAPPROVED");
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ approvalStatus: "REVOKED" }), NOW).code, "POLICY_REVOKED");
});

test("policy rejects malformed and duplicate root pins", () => {
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ approvedRootFingerprints256: ["ABC"] }), NOW).code, "POLICY_INVALID");
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ approvedRootFingerprints256: [ROOT, ROOT] }), NOW).code, "POLICY_INVALID");
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ approvedRootFingerprints256: [] }), NOW).code, "POLICY_INVALID");
});

test("policy rejects malformed and duplicate app signer pins and bad package identity", () => {
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ approvedSigningCertificateSha256Digests: ["g".repeat(64)] }), NOW).code, "POLICY_INVALID");
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ approvedSigningCertificateSha256Digests: [SIGNER, SIGNER] }), NOW).code, "POLICY_INVALID");
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ approvedPackageName: "not-a-package" }), NOW).code, "POLICY_INVALID");
});

test("policy rejects future approval time and missing approval reference", () => {
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ approvedAtMs: NOW + 1 }), NOW).code, "POLICY_INVALID");
  assert.equal(validateAndroidAttestationPolicy(makePolicy({ approvalReference: "" }), NOW).code, "POLICY_INVALID");
});

test("identity policy rejects wrong root, package, signer, and malformed identity", () => {
  const common = { rootFingerprint256: ROOT, packageName: "com.example.geckoworker", signingCertificateSha256: SIGNER };
  assert.equal(evaluateAndroidAttestationIdentity(makePolicy(), { ...common, rootFingerprint256: OTHER }, NOW).code, "ROOT_NOT_APPROVED");
  assert.equal(evaluateAndroidAttestationIdentity(makePolicy(), { ...common, packageName: "com.other.app" }, NOW).code, "PACKAGE_NOT_APPROVED");
  assert.equal(evaluateAndroidAttestationIdentity(makePolicy(), { ...common, signingCertificateSha256: OTHER }, NOW).code, "APP_SIGNER_NOT_APPROVED");
  assert.equal(evaluateAndroidAttestationIdentity(makePolicy(), { ...common, extra: true }, NOW).code, "ATTESTATION_IDENTITY_INVALID");
  assert.equal(evaluateAndroidAttestationIdentity(makePolicy(), common, NOW).authority, "NONE");
});

test("loader refuses absent/unapproved/revoked policy before any network request", async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return response({ entries: {} }); };
  const absent = loader({ policy: null, fetchImpl });
  assert.equal((await absent.load()).code, "POLICY_MISSING");
  const unapproved = loader({ policy: makePolicy({ approvalStatus: "UNAPPROVED" }), fetchImpl });
  assert.equal((await unapproved.load()).code, "POLICY_UNAPPROVED");
  const revoked = loader({ policy: makePolicy({ approvalStatus: "REVOKED" }), fetchImpl });
  assert.equal((await revoked.load()).code, "POLICY_REVOKED");
  assert.equal(calls, 0);
});

test("loader calls only the fixed official HTTPS URL and ignores load-time URL/pin injection", async () => {
  const calls = [];
  const configured = loader({ fetchImpl: async (url, options) => {
    calls.push({ url, options });
    return response({ entries: {} });
  } });
  const result = await configured.load({ url: "https://attacker.invalid/status", approvedRootFingerprints256: [OTHER] });
  assert.equal(result.state, "REVOCATION_STATUS_AVAILABLE");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, URL);
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[0].options.method, "GET");
  assert.equal(result.authority, "NONE");
});

test("missing policy cannot be injected through load-time arguments", async () => {
  let calls = 0;
  const noPolicy = loader({ policy: null, fetchImpl: async () => { calls++; return response(); } });
  assert.equal((await noPolicy.load({ serverOwnedPolicy: makePolicy() })).code, "POLICY_MISSING");
  assert.equal(calls, 0);
});

test("revocation snapshot has exact documented #62-compatible field shape", async () => {
  const result = await loader().load();
  assert.equal(result.state, "REVOCATION_STATUS_AVAILABLE");
  assert.deepEqual(Object.keys(result.revocationSnapshot).sort(), ["cacheMaxAgeMs", "entries", "fetchedAtMs", "source"]);
  assert.equal(result.revocationSnapshot.source, URL);
  assert.equal(result.revocationSnapshot.fetchedAtMs, NOW);
  assert.equal(result.revocationSnapshot.cacheMaxAgeMs, 60 * 60 * 1000);
  assert.equal(result.expiresAtMs, NOW + 60 * 60 * 1000);
});

test("Google REVOKED and SUSPENDED serials produce explicit denial", async () => {
  const result = await loader({ fetchImpl: async () => response({ entries: {
    a1: { status: "REVOKED", reason: "KEY_COMPROMISE" },
    b2: { status: "SUSPENDED", expires: "2030-01-01" },
  } }) }).load();
  assert.equal(result.state, "REVOCATION_STATUS_AVAILABLE");
  assert.equal(evaluateGoogleAttestationRevocation(result.revocationSnapshot, "a1").code, "CERTIFICATE_REVOKED");
  assert.equal(evaluateGoogleAttestationRevocation(result.revocationSnapshot, "b2").code, "CERTIFICATE_SUSPENDED");
  assert.equal(evaluateGoogleAttestationRevocation(result.revocationSnapshot, "00c3").state, "NOT_LISTED");
});

test("revocation serial parser rejects uppercase/noncanonical, invalid, zero and oversized keys", async () => {
  for (const serial of ["A1", "0", "00", "g1", "f".repeat(65)]) {
    const bad = await loader({ fetchImpl: async () => response({ entries: { [serial]: { status: "REVOKED" } } }) }).load();
    assert.equal(bad.code, "STATUS_SCHEMA_INVALID", serial);
  }
  assert.equal(evaluateGoogleAttestationRevocation({ source: URL, fetchedAtMs: NOW - 100, cacheMaxAgeMs: 60_000, entries: {} }, "0x01").code,
    "CERTIFICATE_SERIAL_INVALID");
});

test("loader rejects extra top-level and per-entry schema fields", async () => {
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {}, extra: true }) }).load()).code, "STATUS_SCHEMA_INVALID");
  assert.equal((await loader({ fetchImpl: async () => response({ entries: { a1: { status: "REVOKED", extra: true } } }) }).load()).code, "STATUS_SCHEMA_INVALID");
});

test("loader rejects unknown status/reason and invalid calendar dates", async () => {
  assert.equal((await loader({ fetchImpl: async () => response({ entries: { a1: { status: "GOOD" } } }) }).load()).code, "STATUS_SCHEMA_INVALID");
  assert.equal((await loader({ fetchImpl: async () => response({ entries: { a1: { status: "REVOKED", reason: "NOPE" } } }) }).load()).code, "STATUS_SCHEMA_INVALID");
  assert.equal((await loader({ fetchImpl: async () => response({ entries: { a1: { status: "REVOKED", expires: "2030-02-31" } } }) }).load()).code, "STATUS_SCHEMA_INVALID");
});

test("non-200, redirect and mismatched source fail closed", async () => {
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { status: 503 }) }).load()).code, "HTTP_STATUS_BLOCKED");
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { status: 302 }) }).load()).code, "REDIRECT_REJECTED");
  const wrongSource = async () => {
    const result = response();
    Object.defineProperty(result, "url", { value: "https://attacker.invalid/status" });
    return result;
  };
  assert.equal((await loader({ fetchImpl: wrongSource }).load()).code, "STATUS_SOURCE_MISMATCH");
});

test("network failure blocks and an actual abort deadline is enforced", async () => {
  assert.equal((await loader({ fetchImpl: async () => { throw new Error("offline"); } }).load()).code, "FETCH_FAILED");
  // Deliberately ignore AbortSignal: the loader's Promise.race must still enforce its deadline.
  const timed = loader({ fetchImpl: async () => new Promise(() => {}) });
  assert.equal((await timed.load()).code, "FETCH_TIMEOUT");
});

test("wrong content type, malformed JSON, and invalid UTF-8 fail closed", async () => {
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { contentType: "text/plain" }) }).load()).code, "CONTENT_TYPE_INVALID");
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { rawBody: "{" }) }).load()).code, "STATUS_JSON_INVALID");
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { rawBody: new Uint8Array([0xff]) }) }).load()).code, "STATUS_JSON_INVALID");
});

test("body size is bounded using Content-Length and streamed bytes", async () => {
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { headers: { "content-length": String(constants.maxBodyBytes + 1) } }) }).load()).code,
    "STATUS_BODY_TOO_LARGE");
  const tooLarge = " ".repeat(constants.maxBodyBytes + 1);
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { rawBody: tooLarge }) }).load()).code, "STATUS_BODY_TOO_LARGE");
});

test("Cache-Control max-age is mandatory, unique and bounded by six hours", async () => {
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { cacheControl: "public" }) }).load()).code, "CACHE_CONTROL_INVALID");
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { cacheControl: "max-age=60, max-age=120" }) }).load()).code, "CACHE_CONTROL_INVALID");
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { cacheControl: "no-store, max-age=3600" }) }).load()).code, "CACHE_CONTROL_INVALID");
  const capped = await loader({ fetchImpl: async () => response({ entries: {} }, { cacheControl: "public, max-age=86400" }) }).load();
  assert.equal(capped.revocationSnapshot.cacheMaxAgeMs, constants.maxFreshnessMs);
});

test("Age is subtracted from upstream TTL and too little remaining freshness blocks", async () => {
  const aged = await loader({ fetchImpl: async () => response({ entries: {} }, { cacheControl: "max-age=3600", age: "300" }) }).load();
  assert.equal(aged.revocationSnapshot.cacheMaxAgeMs, 55 * 60 * 1000);
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { cacheControl: "max-age=60", age: "1" }) }).load()).code,
    "CACHE_NOT_FRESH_ENOUGH");
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { age: "-1" }) }).load()).code, "AGE_HEADER_INVALID");
});

test("missing/future/stale server Date fails with clock uncertainty", async () => {
  const missingDate = await loader({ fetchImpl: async () => {
    const result = response();
    const headers = new Headers(result.headers); headers.delete("date");
    return new Response(await result.text(), { status: 200, headers });
  } }).load();
  assert.equal(missingDate.code, "CLOCK_UNCERTAIN");
  assert.equal((await loader({ fetchImpl: async () => response({ entries: {} }, { date: new Date(NOW + 600_000).toUTCString() }) }).load()).code, "CLOCK_UNCERTAIN");
});

test("cache is reused only until expiry; a failed refresh never serves stale data", async () => {
  const clock = { value: NOW };
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    if (calls === 1) return response({ entries: {} }, { now: clock.value, cacheControl: "max-age=60" });
    throw new Error("network offline");
  };
  const instance = loader({ fetchImpl, nowRef: clock });
  assert.equal((await instance.load()).state, "REVOCATION_STATUS_AVAILABLE");
  clock.value += 59_000;
  assert.equal((await instance.load()).state, "REVOCATION_STATUS_AVAILABLE");
  clock.value += 1_000;
  assert.equal((await instance.load()).code, "FETCH_FAILED");
  assert.equal(calls, 2);
});

test("wall-clock rollback blocks cache success and refresh", async () => {
  const clock = { value: NOW };
  let calls = 0;
  const instance = loader({ fetchImpl: async () => { calls++; return response({ entries: {} }, { now: clock.value }); }, nowRef: clock });
  assert.equal((await instance.load()).state, "REVOCATION_STATUS_AVAILABLE");
  clock.value -= 1;
  assert.equal((await instance.load()).code, "CLOCK_UNCERTAIN");
  assert.equal(calls, 1);
});

test("concurrent callers share one refresh and receive the same bounded outcome", async () => {
  let calls = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const instance = loader({ fetchImpl: async () => {
    calls++;
    await gate;
    return response({ entries: {} });
  } });
  const first = instance.load();
  const second = instance.load();
  await Promise.resolve();
  release();
  const [a, b] = await Promise.all([first, second]);
  assert.equal(calls, 1);
  assert.equal(a.state, "REVOCATION_STATUS_AVAILABLE");
  assert.equal(b.state, "REVOCATION_STATUS_AVAILABLE");
  assert.equal(a.revocationSnapshot.fetchedAtMs, b.revocationSnapshot.fetchedAtMs);
});

test("invalid snapshot and expired cache never imply a clear certificate", () => {
  const stale = { source: URL, fetchedAtMs: Date.now() - 61_000, cacheMaxAgeMs: 60_000, entries: {} };
  assert.equal(evaluateGoogleAttestationRevocation(stale, "a1").code, "REVOCATION_STATUS_STALE_OR_INVALID");
});


test("official Google comment is accepted, validated, and excluded from revocation decisions", async () => {
  const result = await loader({ fetchImpl: async () => response({ entries: {
    "2c8cdddfd5e03bfc": {
      status: "REVOKED",
      reason: "KEY_COMPROMISE",
      comment: "Key stored on unsecure system",
    },
    "3b9ad37f": {
      status: "SUSPENDED",
      expires: "2030-01-01",
      comment: "Suspended pending review",
    },
  } }) }).load();
  assert.equal(result.state, "REVOCATION_STATUS_AVAILABLE");
  assert.equal(evaluateGoogleAttestationRevocation(result.revocationSnapshot, "2c8cdddfd5e03bfc").code,
    "CERTIFICATE_REVOKED");
  assert.equal(evaluateGoogleAttestationRevocation(result.revocationSnapshot, "3b9ad37f").code,
    "CERTIFICATE_SUSPENDED");
  assert.equal(Object.hasOwn(result.revocationSnapshot.entries["2c8cdddfd5e03bfc"], "comment"), false);
});

test("optional Google comment must be a string no longer than 140 characters", async () => {
  for (const comment of [null, 42, {}, "x".repeat(141)]) {
    const result = await loader({ fetchImpl: async () => response({ entries: {
      a1: { status: "REVOKED", comment },
    } }) }).load();
    assert.equal(result.code, "STATUS_SCHEMA_INVALID", String(comment).slice(0, 20));
  }
  const atLimit = await loader({ fetchImpl: async () => response({ entries: {
    a1: { status: "REVOKED", comment: "x".repeat(140) },
  } }) }).load();
  assert.equal(atLimit.state, "REVOCATION_STATUS_AVAILABLE");
  assert.equal(evaluateGoogleAttestationRevocation(atLimit.revocationSnapshot, "a1").code, "CERTIFICATE_REVOKED");
});

test("raw JSON duplicate serial keys are rejected before object parsing can overwrite them", async () => {
  const raw = '{"entries":{"a1":{"status":"REVOKED"},"a1":{"status":"SUSPENDED"}}}';
  const result = await loader({ fetchImpl: async () => response({}, { rawBody: raw }) }).load();
  assert.equal(result.code, "STATUS_JSON_INVALID");
});

test("raw JSON duplicate top-level entries keys are rejected", async () => {
  const raw = '{"entries":{"a1":{"status":"REVOKED"}},"entries":{}}';
  const result = await loader({ fetchImpl: async () => response({}, { rawBody: raw }) }).load();
  assert.equal(result.code, "STATUS_JSON_INVALID");
});

test("raw JSON duplicate escaped object-member spellings are rejected by decoded key", async () => {
  const raw = '{"entries":{"a1":{"status":"REVOKED","commen\\u0074":"one","comment":"two"}}}';
  const result = await loader({ fetchImpl: async () => response({}, { rawBody: raw }) }).load();
  assert.equal(result.code, "STATUS_JSON_INVALID");
});

test("raw duplicate nested object members are rejected, not just duplicate top-level keys", async () => {
  const raw = '{"entries":{"a1":{"status":"REVOKED","reason":"KEY_COMPROMISE","reason":"SOFTWARE_FLAW"}}}';
  const result = await loader({ fetchImpl: async () => response({}, { rawBody: raw }) }).load();
  assert.equal(result.code, "STATUS_JSON_INVALID");
});

test("loader clones policy at construction to prevent later mutation", async () => {
  const candidate = makePolicy();
  const instance = loader({ policy: candidate });
  candidate.approvalStatus = "REVOKED";
  const result = await instance.load();
  assert.equal(result.state, "REVOCATION_STATUS_AVAILABLE");
  assert.equal(result.authority, "NONE");
});
