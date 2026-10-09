import test from "node:test";
import assert from "node:assert/strict";
import {
  validateSource, validateSnapshot, validateStage, stageWithToken, getSnapshot,
} from "../scripts/stage-scoped-cloudflare-version.mjs";

const live = "908f6f43-97ff-4621-9bcf-f13b4b679c16";
const deployment = "391149ba-0e1b-450f-8ba3-42fe787a51dc";
const staged = "22222222-2222-4222-8222-222222222222";
const sha = "8651e90652cb7197c03bb4d6389865b63c21c599";
const config = [
  'name = "bke-command-center"',
  '[env.preproduction]',
  'workers_dev = false',
  'preview_urls = false',
  'pattern = "cc.jl-bke.com"',
  'custom_domain = true',
  'BKE_PREPRODUCTION = "true"',
].join("\n");
const source = { branch: "main", dirty: "", localSha: sha, remoteSha: sha,
  origin: "https://github.com/jan2xo/bke-command-center.git", config };
const settings = { bindings: [
  { name: "BKE_ACCESS_POLICY_VERIFIED", type: "secret_text" },
  { name: "GITHUB_TOKEN", type: "secret_text" },
  { name: "BKE_PREPRODUCTION", type: "plain_text" },
] };
const subdomain = { enabled: false, previews_enabled: false };
const deployments = { deployments: [
  { id: deployment, versions: [{ version_id: live, percentage: 100 }] },
] };
const versions = { items: [{ id: live, metadata: { source: "api" } }] };
const before = validateSnapshot({ settings, subdomain, deployments, versions });
const after = validateSnapshot({
  settings, subdomain, deployments,
  versions: { items: [{ id: staged, metadata: { source: "wrangler" } }, ...versions.items] },
});

test("source is pinned to clean current main and named preproduction config", () => {
  assert.equal(validateSource(source), sha);
  for (const bad of [
    { branch: "fix/other" }, { dirty: " M src/index.js" },
    { localSha: "a".repeat(40) }, { remoteSha: "a".repeat(40) },
    { origin: "https://github.com/someone/other.git" },
    { config: config.replace('preview_urls = false', 'preview_urls = true') },
    { config: config.replace('pattern = "cc.jl-bke.com"', 'pattern = "airstack.jl-bke.com"') },
    { config: config.replace('BKE_PREPRODUCTION = "true"', 'BKE_PREPRODUCTION = "false"') },
  ]) {
    assert.throws(() => validateSource({ ...source, ...bad }), /SOURCE_|PREPRODUCTION_/u);
  }
});

test("snapshot refuses missing secrets, public URLs or ambiguous deployment", () => {
  assert.equal(before.activeVersion, live);
  assert.equal(before.deploymentId, deployment);
  assert.equal(before.versionIds.length, 1);
  const attempts = [
    { settings: { bindings: settings.bindings.filter(x => x.name !== "GITHUB_TOKEN") } },
    { settings: { bindings: [{ name: "GITHUB_TOKEN", type: "plain_text" }, ...settings.bindings.filter(x => x.name !== "GITHUB_TOKEN")] } },
    { subdomain: { enabled: true, previews_enabled: false } },
    { subdomain: { enabled: false, previews_enabled: true } },
    { deployments: { deployments: [{ id: deployment, versions: [
      { version_id: live, percentage: 50 }, { version_id: staged, percentage: 50 },
    ] }] } },
    { deployments: { deployments: [{ id: deployment, versions: [
      { version_id: live, percentage: 99 },
    ] }] } },
    { versions: { items: [{ id: staged }] } },
  ];
  for (const partial of attempts) {
    assert.throws(() => validateSnapshot({ settings, subdomain, deployments, versions, ...partial }),
      /PREPRODUCTION_|CURRENT_VERSION_/u);
  }
});

test("one new Wrangler version with unchanged serving deployment is accepted", () => {
  assert.deepEqual(validateStage(before, after), {
    newVersion: staged, activeVersion: live, activeDeployment: deployment,
  });
});

test("changed live deployment, missing or duplicate stage, unknown uploader all fail closed", () => {
  assert.throws(() => validateStage(before, before), /STAGED_VERSION_NOT_UNAMBIGUOUS/u);
  const twoNew = { ...after, versionIds: [staged, "33333333-3333-4333-8333-333333333333", live] };
  assert.throws(() => validateStage(before, twoNew), /STAGED_VERSION_NOT_UNAMBIGUOUS/u);
  assert.throws(() => validateStage(before, { ...after, deploymentId: staged }),
    /LIVE_DEPLOYMENT_CHANGED_FAIL_CLOSED/u);
  assert.throws(() => validateStage(before, { ...after, activeVersion: staged }),
    /LIVE_DEPLOYMENT_CHANGED_FAIL_CLOSED/u);
  assert.throws(() => validateStage(before, { ...after,
    versionItems: [{ id: staged, metadata: { source: "api" } }, ...versions.items] }),
  /STAGED_SOURCE_NOT_WRANGLER/u);
});

test("staging injects verified token only after source and scope checks, no traffic promotion", async () => {
  const calls = [];
  const result = await stageWithToken("fake-secret-token", {
    checkSource: () => { calls.push("source"); return sha; },
    verifyToken: async () => { calls.push("scope"); },
    snapshot: async () => { calls.push("snapshot"); return calls.filter(v => v === "snapshot").length === 1 ? before : after; },
    upload: async token => { assert.equal(token, "fake-secret-token"); calls.push("upload"); },
  });
  assert.deepEqual(calls, ["source", "scope", "snapshot", "source", "upload", "snapshot", "source"]);
  assert.equal(result.sha, sha);
  assert.equal(result.newVersion, staged);
});

test("staging never attempts upload when token verification or source check fails", async () => {
  let uploaded = false;
  await assert.rejects(stageWithToken("fake-secret-token", {
    checkSource: () => sha, verifyToken: async () => { throw Error("DENIED"); },
    snapshot: async () => before,
    upload: async () => { uploaded = true; },
  }), /DENIED/u);
  assert.equal(uploaded, false);
  await assert.rejects(stageWithToken("fake-secret-token", {
    checkSource: () => { throw Error("NO_MAIN"); },
    verifyToken: async () => {}, snapshot: async () => before,
    upload: async () => { uploaded = true; },
  }), /NO_MAIN/u);
  assert.equal(uploaded, false);
});

test("staging refuses source drift before upload or after upload", async () => {
  let uploaded = false;
  let count = 0;
  await assert.rejects(stageWithToken("fake-secret-token", {
    checkSource: () => { count++; return count === 1 ? sha : "a".repeat(40); },
    verifyToken: async () => {}, snapshot: async () => before,
    upload: async () => { uploaded = true; },
  }), /SOURCE_MOVED_BEFORE_UPLOAD/u);
  assert.equal(uploaded, false);
  count = 0;
  let snapshots = 0;
  await assert.rejects(stageWithToken("fake-secret-token", {
    checkSource: () => { count++; return count <= 2 ? sha : "a".repeat(40); },
    verifyToken: async () => {},
    snapshot: async () => { snapshots++; return snapshots === 1 ? before : after; },
    upload: async () => { uploaded = true; },
  }), /SOURCE_MOVED_DURING_UPLOAD/u);
  assert.equal(uploaded, true);
});

test("Cloudflare state queries are exactly four GETs with private bearer token", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    const payload = url.endsWith("/settings") ? settings
      : url.endsWith("/subdomain") ? subdomain
      : url.endsWith("/deployments") ? deployments
      : url.endsWith("/versions?per_page=10") ? versions : null;
    return new Response(JSON.stringify({ success: true, result: payload }), { status: 200 });
  };
  const result = await getSnapshot("mock-only", fetchImpl);
  assert.equal(result.activeVersion, live);
  assert.equal(calls.length, 4);
  assert.ok(calls.every(x => x.options.method === "GET" && x.options.redirect === "error" &&
    x.options.headers.Authorization === "Bearer mock-only"));
});

test("Cloudflare preflight rejects denied, malformed and transport failures", async () => {
  for (const fetchImpl of [
    async () => new Response("{}", { status: 403 }),
    async () => new Response("junk", { status: 200 }),
    async () => { throw new Error("sensitive upstream details"); },
  ]) {
    await assert.rejects(getSnapshot("mock-only", fetchImpl),
      /CLOUDFLARE_PREFLIGHT_(DENIED|INVALID|UNAVAILABLE)/u);
  }
});
