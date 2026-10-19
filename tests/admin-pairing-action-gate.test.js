import test from "node:test";
import assert from "node:assert/strict";
import { inspectPairingAdminAction } from "../src/admin-pairing-action-gate.js";
import { readFileSync } from "node:fs";

const origin = "https://cc.jl-bke.com";
const environment = Object.freeze({
  BKE_PREPRODUCTION: "true",
  BKE_ACCESS_POLICY_VERIFIED: "true",
  BKE_ADMIN_PAIRING_ACTIONS_ENABLED: "true",
  BKE_ADMIN_DISCOVERY_ENABLED: "true",
  BKE_ADMIN_ACCESS_ISSUER: "https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD: "0123456789abcdef0123456789abcdef",
  BKE_ADMIN_EMAILS: "admin@example.test",
});
const identity = (email = "admin@example.test", aud = environment.BKE_ADMIN_ACCESS_AUD) =>
  ({ access: { aud, async getIdentity() { return { email }; } } });
const payload = (action = "pair", worker_id = "worker-a") =>
  ({ action, worker_id, confirm_worker_id: worker_id });
const make = (body = payload(), overrides = {}) =>
  new Request(overrides.url || origin + "/api/admin/worker-pairing/action", {
    method: overrides.method || "POST",
    headers: {
      origin,
      "sec-fetch-site": "same-origin",
      "sec-fetch-mode": "cors",
      "content-type": "application/json",
      "x-bke-admin-action": body?.action ?? "pair",
      ...overrides.headers,
    },
    body: overrides.method === "GET" ? undefined
      : overrides.rawBody === undefined ? JSON.stringify(body) : overrides.rawBody,
  });
const blocked = (result, expected) => {
  assert.deepEqual(result, { state: "BLOCKED", code: expected });
  assert.doesNotMatch(JSON.stringify(result), /email|example.test|secret|ghs_|Bearer|private_key/iu);
};

test("OFF by default even with valid platform identity and browser origin", async () => {
  blocked(await inspectPairingAdminAction(make(), {
    ...environment, BKE_ADMIN_PAIRING_ACTIONS_ENABLED: undefined,
  }, identity()), "PAIRING_ACTIONS_LOCKED");
  blocked(await inspectPairingAdminAction(make(), {}, identity()), "PAIRING_ACTIONS_LOCKED");
});

test("PREPRODUCTION and Access policy fail closed without exact flags", async () => {
  for (const values of [
    { BKE_PREPRODUCTION: false }, { BKE_PREPRODUCTION: undefined },
    { BKE_ACCESS_POLICY_VERIFIED: "false" },
    { BKE_ACCESS_POLICY_VERIFIED: undefined },
  ]) blocked(await inspectPairingAdminAction(make(),
    { ...environment, ...values }, identity()), "PAIRING_ENVIRONMENT_LOCKED");
});

test("pair and revoke require explicit matching worker confirmation", async () => {
  for (const action of ["pair", "revoke"]) {
    const result = await inspectPairingAdminAction(
      make(payload(action, "worker-b")), environment, identity());
    assert.deepEqual(result, {
      state: "AUTHORIZED_FOR_PREFLIGHT", action, worker_id: "worker-b",
    });
    assert.ok(Object.isFrozen(result));
    assert.ok(!("token" in result || "lease" in result || "identity" in result));
  }
});

test("forged header or stale user session without platform ctx.access is denied", async () => {
  const headers = { "cf-access-jwt-assertion": "forged", "cf-access-authenticated-user-email": "admin@example.test" };
  blocked(await inspectPairingAdminAction(make(payload(), { headers }),
    environment, undefined), "PAIRING_ADMIN_DENIED");
  blocked(await inspectPairingAdminAction(make(), environment,
    { access: { aud: environment.BKE_ADMIN_ACCESS_AUD } }), "PAIRING_ADMIN_DENIED");
});

test("wrong Admin user, audience, missing policy and identity lookup errors fail", async () => {
  for (const ctx of [
    identity("unlisted@example.test"),
    identity("admin@example.test", "wrong-aud"),
    { access: { aud: environment.BKE_ADMIN_ACCESS_AUD,
      async getIdentity() { throw Error("sensitive upstream"); } } },
  ]) blocked(await inspectPairingAdminAction(make(), environment, ctx),
    "PAIRING_ADMIN_DENIED");
  blocked(await inspectPairingAdminAction(make(), {
    ...environment, BKE_ADMIN_EMAILS: "",
  }, identity()), "PAIRING_ADMIN_DENIED");
});

test("CSRF: absent/cross-site origin and Fetch Metadata never pass", async () => {
  for (const headers of [
    { origin: "https://evil.example" }, { origin: "" },
    { "sec-fetch-site": "cross-site" }, { "sec-fetch-site": "same-site" },
    { "sec-fetch-site": "" }, { "sec-fetch-mode": "navigate" },
    { "sec-fetch-mode": "" },
  ]) blocked(await inspectPairingAdminAction(make(payload(), { headers }),
    environment, identity()), "PAIRING_BROWSER_ORIGIN_REJECTED");
});

test("wrong host, plain HTTP, credentials in URL and URL query fail closed", async () => {
  for (const url of [
    "https://evil.example/api/admin/worker-pairing/action",
    "http://cc.jl-bke.com/api/admin/worker-pairing/action",
    origin + "/api/admin/worker-pairing/action?token=1",
    origin + "/api/admin/worker-pairing/action#fragment",
  ]) blocked(await inspectPairingAdminAction(make(payload(), { url }),
    environment, identity()), "PAIRING_ORIGIN_REJECTED");
});

test("wrong method, input type, encoding, fake length or oversized body fail", async () => {
  blocked(await inspectPairingAdminAction(make(payload(), { method: "GET" }),
    environment, identity()), "PAIRING_METHOD_REJECTED");
  for (const headers of [
    { "content-type": "text/plain" },
    { "content-type": "application/x-www-form-urlencoded" },
    { "content-encoding": "gzip" },
    { "content-length": "99999" },
    { "content-length": "Infinity" },
  ]) blocked(await inspectPairingAdminAction(make(payload(), { headers }),
    environment, identity()), "PAIRING_CONTENT_TYPE_REJECTED");
  blocked(await inspectPairingAdminAction(make(payload(), {
    rawBody: " ".repeat(1025),
  }), environment, identity()), "PAIRING_INTENT_INVALID");
});

test("payload schema denies unconfirmed, cross-worker, privilege fields or bogus action", async () => {
  const cases = [
    { ...payload(), confirm_worker_id: "worker-b" },
    { ...payload(), worker_id: "Worker-A" },
    { ...payload(), action: "assign" },
    { ...payload(), installation_id: "42" },
    { ...payload(), admin_authorized: true },
    { ...payload(), token: "ghs_invalid" },
    [payload()],
    null,
  ];
  for (const value of cases) blocked(await inspectPairingAdminAction(
    make(value), environment, identity()), "PAIRING_INTENT_INVALID");
});

test("header and JSON action must match, no implicit fallback to pairing", async () => {
  blocked(await inspectPairingAdminAction(make(payload("revoke"), {
    headers: { "x-bke-admin-action": "pair" },
  }), environment, identity()), "PAIRING_INTENT_INVALID");
  blocked(await inspectPairingAdminAction(make(payload(), {
    headers: { "x-bke-admin-action": "" },
  }), environment, identity()), "PAIRING_INTENT_INVALID");
});

test("invalid UTF8 and malformed JSON produce only redacted errors", async () => {
  for (const rawBody of ["{invalid", new Uint8Array([0xff, 0xfe, 0xfd])]) {
    blocked(await inspectPairingAdminAction(make(payload(), { rawBody }),
      environment, identity()), "PAIRING_INTENT_INVALID");
  }
});

test("not connected to Admin HTTP route and not enabled in Wrangler", () => {
  const index = readFileSync(new URL("../src/index.js", import.meta.url), "utf8");
  const wrangler = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.doesNotMatch(index, /admin-pairing-action-gate/u);
  assert.doesNotMatch(index, /\/api\/admin\/worker-pairing\/action/u);
  assert.doesNotMatch(wrangler, /BKE_ADMIN_PAIRING_ACTIONS_ENABLED\s*=\s*"true"/u);
});
