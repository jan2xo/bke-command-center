import assert from "node:assert/strict";
import test from "node:test";
import {
  B1_ACCOUNT_ID, B1_TARGET, B1_DENIED_WORKERS, verifyScopedToken,
} from "../scripts/verify-cloudflare-deploy-token.mjs";

const token = "test_non_secret_token_value_for_mock_only";
const prefix = "https://api.cloudflare.com/client/v4/accounts/" + B1_ACCOUNT_ID;
const active = { success: true, result: { status: "active", id: "redacted" } };
const settings = { success: true, result: { bindings: [] } };

function respond(status, payload = { success: false }) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function fixture(overrides = {}) {
  const seen = [];
  const fetchImpl = async (url, options) => {
    seen.push({ url, method: options.method, redirect: options.redirect,
      auth: options.headers.Authorization });
    if (url === prefix + "/tokens/verify") {
      return overrides.verify ?? respond(200, active);
    }
    if (url === prefix + "/workers/scripts/" + B1_TARGET + "/settings") {
      return overrides.target ?? respond(200, settings);
    }
    if (B1_DENIED_WORKERS.some((name) =>
      url === prefix + "/workers/scripts/" + name + "/settings")) {
      return overrides.denied ?? respond(403);
    }
    throw Error("Unexpected URL");
  };
  return { seen, fetchImpl };
}

test("scoped account token can read intended worker but not unrelated workers", async () => {
  const { seen, fetchImpl } = fixture();
  const result = await verifyScopedToken(token, { fetchImpl });
  assert.deepEqual(result, {
    tokenStatus: "ACTIVE",
    targetWorker: "bke-command-center-preproduction",
    targetRead: "PASS",
    unrelatedWorkerReads: "DENIED",
    verifiedDenials: 2,
    deploymentPerformed: false,
    priorDeploymentPrincipal: "NOT_PROVEN",
    editorWritePermission: "OPERATOR_ATTESTED_NOT_API_PROVEN",
  });
  assert.equal(seen.length, 4);
  for (const entry of seen) {
    assert.equal(entry.method, "GET");
    assert.equal(entry.redirect, "error");
    assert.equal(entry.auth, "Bearer " + token);
  }
  assert.equal(JSON.stringify(result).includes(token), false);
});

test("Cloudflare existence-hiding 404 is accepted only for known unrelated Workers", async () => {
  const f = fixture({ denied: respond(404) });
  assert.equal((await verifyScopedToken(token, { fetchImpl: f.fetchImpl })).unrelatedWorkerReads, "DENIED");
});

test("inactive/invalid tokens fail closed", async () => {
  for (const bad of [
    respond(401), respond(403), respond(200, { success: true, result: { status: "disabled" } }),
    respond(200, { success: false, result: { status: "active" } }),
  ]) {
    const f = fixture({ verify: bad });
    await assert.rejects(verifyScopedToken(token, { fetchImpl: f.fetchImpl }),
      /ACCOUNT_TOKEN_VERIFY_DENIED|ACCOUNT_TOKEN_NOT_ACTIVE/u);
    assert.equal(f.seen.length, 1);
  }
});

test("target worker must be accessible as the intended named Worker", async () => {
  for (const bad of [
    respond(403), respond(404), respond(200, { success: false }),
    respond(200, { success: true, result: null }),
  ]) {
    const f = fixture({ target: bad });
    await assert.rejects(verifyScopedToken(token, { fetchImpl: f.fetchImpl }),
      /TARGET_WORKER_READ_DENIED|TARGET_WORKER_PROOF_INVALID/u);
    assert.equal(f.seen.length, 2);
  }
});

test("unrelated Worker access or transient errors do not count as restricted scope", async () => {
  for (const status of [200, 201, 401, 500, 503]) {
    const f = fixture({ denied: respond(status, status === 200 ? settings : undefined) });
    await assert.rejects(verifyScopedToken(token, { fetchImpl: f.fetchImpl }),
      /UNRELATED_WORKER_READ_NOT_DENIED/u);
  }
});

test("transport failure and invalid local input fail closed", async () => {
  await assert.rejects(
    verifyScopedToken(token, { fetchImpl: async () => { throw Error("secret in upstream error"); } }),
    /CLOUDFLARE_TRANSPORT_UNAVAILABLE/u,
  );
  for (const invalid of ["", "too short", "pasted token with spaces"].concat([null])) {
    await assert.rejects(verifyScopedToken(invalid), /TOKEN_INPUT_INVALID/u);
  }
  await assert.rejects(verifyScopedToken(token, {
    fetchImpl: fixture().fetchImpl, deniedWorkers: [B1_TARGET],
  }), /B1_SCOPE_CONFIGURATION_INVALID/u);
  await assert.rejects(verifyScopedToken(token, {
    fetchImpl: fixture().fetchImpl, deniedWorkers: [],
  }), /B1_SCOPE_CONFIGURATION_INVALID/u);
});

test("no text returned from upstream becomes proof when token verification response is malformed", async () => {
  const f = fixture({ verify: new Response("untrusted token and payload", { status: 200 }) });
  await assert.rejects(verifyScopedToken(token, { fetchImpl: f.fetchImpl }), /ACCOUNT_TOKEN_NOT_ACTIVE/u);
});
