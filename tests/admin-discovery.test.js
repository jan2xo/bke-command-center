import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { authorizeAdminAccess, adminAccessConfigured, inspectAdminAccess } from "../src/admin-access.js";
import { discoverGitHubRepositories } from "../src/admin-discovery.js";
import { handleRequest, preproductionFetch } from "../src/index.js";

const env = {
  BKE_ADMIN_DISCOVERY_ENABLED: "true",
  BKE_ADMIN_ACCESS_ISSUER: "https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD: "0123456789abcdef0123456789abcdef",
  BKE_ADMIN_EMAILS: "admin@example.test",
  GITHUB_TOKEN: "test-provider-credential",
};
const enc = (value) => Buffer.isBuffer(value) ? value.toString("base64url") : Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");
const fakeRepo = (id, name) => ({
  id, full_name: "jan2xo/" + name, default_branch: "main", visibility: "private", private: true, archived: false,
});
let keys;
async function rsaFixture() {
  if (keys) return keys;
  const pair = await webcrypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"]);
  const jwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  keys = { pair, jwk: { ...jwk, kid: "trusted-kid", alg: "RS256", use: "sig" } };
  return keys;
}
async function signedAccessToken(overrides = {}) {
  const { pair } = await rsaFixture();
  const now = Math.floor(Date.now() / 1000);
  const header = enc({ alg: "RS256", kid: "trusted-kid", typ: "JWT" });
  const claims = enc({
    type: "app", iss: env.BKE_ADMIN_ACCESS_ISSUER, aud: [env.BKE_ADMIN_ACCESS_AUD],
    iat: now - 5, exp: now + 120, sub: "human-admin", email: "admin@example.test",
    ...overrides,
  });
  const signed = await webcrypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(header + "." + claims));
  return header + "." + claims + "." + enc(Buffer.from(signed));
}
async function jwksFetch(url) {
  assert.equal(url, env.BKE_ADMIN_ACCESS_ISSUER + "/cdn-cgi/access/certs");
  return Response.json({ keys: [(await rsaFixture()).jwk] });
}
const request = (jwt, route = "/admin") => new Request("https://cc.jl-bke.com" + route,
  { headers: { "cf-access-jwt-assertion": jwt } });

test("Admin default OFF and no verified Access claims are denied before discovery", async () => {
  assert.equal(adminAccessConfigured({}), false);
  assert.equal(await authorizeAdminAccess(request(""), env, jwksFetch, webcrypto), false);
  assert.equal((await handleRequest(request(""), {}, () => ({}))).status, 404);
  assert.equal((await handleRequest(request(""), env, () => ({}))).status, 403);
  const locked = preproductionFetch(request(""), { BKE_PREPRODUCTION: "true", BKE_ACCESS_POLICY_VERIFIED: "false" });
  assert.equal(locked.status, 503);
});

test("Admin requires authentic RSA signature, exact audience, issuer, identity and expiry", async () => {
  const jwt = await signedAccessToken();
  assert.equal(await authorizeAdminAccess(request(jwt), env, jwksFetch, webcrypto), true);
  assert.equal(await authorizeAdminAccess(request(jwt), { ...env, BKE_ADMIN_EMAILS: "another@example.test" }, jwksFetch, webcrypto), false);
  assert.equal(await authorizeAdminAccess(request(await signedAccessToken({ exp: 1 })), env, jwksFetch, webcrypto), false);
  assert.equal(await authorizeAdminAccess(request(await signedAccessToken({ aud: ["wrong"] })), env, jwksFetch, webcrypto), false);
  assert.equal(await authorizeAdminAccess(request(await signedAccessToken({ type: "org" })), env, jwksFetch, webcrypto), false);
  assert.equal(await authorizeAdminAccess(request(await signedAccessToken({ sub: "" })), env, jwksFetch, webcrypto), false);
  const [h, p, signature] = jwt.split(".");
  assert.equal(await authorizeAdminAccess(request(h + "." + enc({ fake: true }) + "." + signature), env, jwksFetch, webcrypto), false);
  assert.equal(await authorizeAdminAccess(request(jwt), { ...env, BKE_ADMIN_ACCESS_ISSUER: "https://attacker.com" }, jwksFetch, webcrypto), false);
});

test("GitHub discovery derives repository links and never leaks server token", async () => {
  let observed = 0;
  const mock = async (url, options) => {
    observed++;
    assert.equal(new URL(url).hostname, "api.github.com");
    assert.equal(options.headers.Authorization, "Bearer test-provider-credential");
    assert.equal(options.redirect, "error");
    return Response.json([fakeRepo(2, "bke-worker"), fakeRepo(1, "bke-command-center")]);
  };
  const state = await discoverGitHubRepositories(env, mock);
  assert.equal(observed, 1);
  assert.equal(state.total_visible, 2);
  assert.deepEqual(state.repositories.map((r) => r.full_name),
    ["jan2xo/bke-command-center", "jan2xo/bke-worker"]);
  assert.equal(state.repositories[0].url, "https://github.com/jan2xo/bke-command-center");
  assert.equal(state.credential.auto_rotation, false);
  assert.doesNotMatch(JSON.stringify(state), /test-provider-credential/);
});

test("Installation-token mode uses its own GitHub repository endpoint", async () => {
  const result = await discoverGitHubRepositories({ ...env, GITHUB_DISCOVERY_PRINCIPAL: "installation" },
    async (url) => {
      assert.match(url, /\/installation\/repositories/);
      return Response.json({ total_count: 1, repositories: [fakeRepo(2, "bke-worker")] });
    });
  assert.equal(result.principal, "installation");
});

test("Paginated GitHub discovery either completes or fails closed; no false partial success", async () => {
  let pageCount = 0;
  const state = await discoverGitHubRepositories(env, async () => {
    pageCount++;
    return Response.json([fakeRepo(pageCount, "repo" + pageCount)], {
      headers: pageCount === 1 ? { link: '<https://api.github.com/user/repos?page=2>; rel="next"' } : {},
    });
  });
  assert.equal(state.total_visible, 2);
  let i = 0;
  await assert.rejects(() => discoverGitHubRepositories(env, async () => {
    i++;
    return Response.json([fakeRepo(i, "repo" + i)], { headers: { link: '<https://api.github.com/user/repos?page=1000>; rel="next"' } });
  }), /GITHUB_DISCOVERY_PAGINATION_LIMIT/);
});

test("Discovery must not fetch sources for missing or rejected credentials", async () => {
  let fetches = 0;
  const stub = async () => { fetches++; return new Response("", { status: 401 }); };
  await assert.rejects(() => discoverGitHubRepositories({}, stub), /GITHUB_CREDENTIAL_NOT_CONFIGURED/);
  assert.equal(fetches, 0);
  await assert.rejects(() => discoverGitHubRepositories(env, stub), /GITHUB_DISCOVERY_AUTH_UNAVAILABLE/);
  assert.equal(fetches, 1);
  await assert.rejects(() => discoverGitHubRepositories(env, async () => Response.json([{ ...fakeRepo(1, "ok"), full_name: "../evil" }])), /GITHUB_REPOSITORY_RESPONSE_INVALID/);
});

test("Admin UI/API deny unsafe methods, reject missing JWT, and never use GET for mutations", async () => {
  const fakeAdapter = () => ({ });
  const post = new Request("https://cc.jl-bke.com/api/admin/discovery", { method: "POST" });
  assert.equal((await handleRequest(post, env, fakeAdapter)).status, 405);
  assert.equal((await handleRequest(request("fake", "/api/admin/discovery"), env, fakeAdapter)).status, 403);
  assert.equal((await handleRequest(request("fake", "/admin"), { ...env, BKE_ADMIN_DISCOVERY_ENABLED: "false" }, fakeAdapter)).status, 404);
});

test("Verified Admin GET returns a live GitHub-derived inventory, never its token", async () => {
  const jwt = await signedAccessToken();
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push(String(url));
    if (String(url).includes("/cdn-cgi/access/certs")) return jwksFetch(url);
    if (String(url).startsWith("https://api.github.com/user/repos?")) {
      assert.equal(options.headers.Authorization, "Bearer " + env.GITHUB_TOKEN);
      return Response.json([fakeRepo(444, "BKE_RENDER_DOCK")]);
    }
    throw new Error("unexpected outbound endpoint");
  };
  try {
    const response = await preproductionFetch(request(jwt, "/api/admin/discovery"), {
      ...env, BKE_PREPRODUCTION: "true", BKE_ACCESS_POLICY_VERIFIED: "true",
    });
    assert.equal(response.status, 200);
    const state = await response.json();
    assert.equal(state.total_visible, 1);
    assert.equal(state.repositories[0].full_name, "jan2xo/BKE_RENDER_DOCK");
    assert.doesNotMatch(JSON.stringify(state), /test-provider-credential/);
    assert.equal(state.credential.auto_rotation, false);
    const html = await preproductionFetch(request(jwt, "/admin"), {
      ...env, BKE_PREPRODUCTION: "true", BKE_ACCESS_POLICY_VERIFIED: "true",
    });
    assert.equal(html.status, 200);
    const text = await html.text();
    assert.match(text, /BKE_RENDER_DOCK/);
    assert.doesNotMatch(text, /test-provider-credential/);
    assert.equal(calls.length, 4); // Access JWKS + GitHub for each request.
  } finally {
    globalThis.fetch = originalFetch;
  }
});


test("Admin JWT denial stages never contain identity, token bytes, issuer or key detail", async () => {
  const jwt = await signedAccessToken();
  assert.equal(await inspectAdminAccess(request(""), env, jwksFetch, webcrypto), "EDGE_JWT_MISSING");
  assert.equal(await inspectAdminAccess(request("junk"), env, jwksFetch, webcrypto), "JWT_MALFORMED");
  assert.equal(await inspectAdminAccess(
    request(await signedAccessToken({email:"not-admin@example.test"})),
    env, jwksFetch, webcrypto), "JWT_CLAIMS_REJECTED");
  assert.equal(await inspectAdminAccess(request(jwt), env,
    async () => new Response("unauthorized", {status:403}), webcrypto), "JWKS_UNAVAILABLE");
  assert.equal(await inspectAdminAccess(request(jwt), env,
    async () => Response.json({keys:[]}), webcrypto), "JWKS_KEY_NOT_FOUND");
  assert.equal(await inspectAdminAccess(request(jwt), env,
    async () => Response.json({keys:[{...(await rsaFixture()).jwk, n:"invalid@"}]}),
    webcrypto), "JWKS_KEY_INVALID");
  const [header, body] = jwt.split(".");
  const tampered = header + "." + body + "." + enc(Buffer.from([1,2,3]));
  assert.equal(await inspectAdminAccess(request(tampered), env, jwksFetch, webcrypto),
    "JWT_SIGNATURE_INVALID");
  assert.equal(await inspectAdminAccess(request(jwt), env, jwksFetch, webcrypto), "AUTHORIZED");
});

test("Admin protected endpoint emits only coarse denial buckets, never allowlist or JWT", async () => {
  const originalFetch = globalThis.fetch;
  try {
    const preproductionEnv = {...env,BKE_PREPRODUCTION:"true",BKE_ACCESS_POLICY_VERIFIED:"true"};
    let response = await preproductionFetch(request("","/api/admin/discovery"), preproductionEnv);
    assert.equal(response.status,403);
    assert.deepEqual(await response.json(), {
      error:"ADMIN_ACCESS_DENIED",auth_stage:"EDGE_JWT_MISSING"
    });
    response = await preproductionFetch(request("junk","/api/admin/discovery"), preproductionEnv);
    assert.deepEqual(await response.json(), {
      error:"ADMIN_ACCESS_DENIED",auth_stage:"JWT_REJECTED"
    });
    const signed = await signedAccessToken();
    globalThis.fetch = async () => new Response("upstream denied",{status:403});
    response = await preproductionFetch(request(signed,"/api/admin/discovery"),preproductionEnv);
    assert.deepEqual(await response.json(), {
      error:"ADMIN_ACCESS_DENIED",auth_stage:"VERIFICATION_KEY_UNAVAILABLE"
    });
    globalThis.fetch = jwksFetch;
    const changedEmail = await signedAccessToken({ email: "other-identity@example.test" });
    response = await preproductionFetch(request(changedEmail,"/api/admin/discovery"),preproductionEnv);
    const body = JSON.stringify(await response.json());
    assert.match(body,/JWT_REJECTED/);
    assert.doesNotMatch(body,/admin@example\.test|other-identity|bke-test|ghs_|eyJh|trusted-kid/);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
