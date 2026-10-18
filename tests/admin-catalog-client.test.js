import test from "node:test";
import assert from "node:assert/strict";
import { discoverGitHubRepositories } from "../src/admin-discovery.js";
import { handleRequest } from "../src/index.js";

const repo = (id, name) => ({
  id, full_name: "jan2xo/" + name, default_branch: "main",
  private: true, archived: false, html_url: "https://github.com/jan2xo/" + name,
});
const payload = (repos) => ({
  principal: "github_app_installation",
  authority: "EXISTING_GITHUB_APP_INSTALLATION",
  repository_scope: "INSTALLATION_APPROVED_ONLY",
  total_visible: repos.length,
  repositories: repos,
});
function fixture(value = payload([repo(51, "bke-worker"), repo(52, "BKE_RENDER_DOCK")])) {
  const seen = [];
  const env = {
    GITHUB_DISCOVERY_AUTH_MODE: "catalog",
    GITHUB_TOKEN: "unused-legacy-fixture",
    BKE_GITHUB_READ_BROKER: {
      async listApprovedGitHubRepositories(request) {
        seen.push(request);
        return value;
      },
    },
  };
  return { env, seen };
}

test("catalog mode consumes private RPC metadata with no provider fetch or legacy token", async () => {
  const { env, seen } = fixture();
  const result = await discoverGitHubRepositories(env, async () => {
    throw Error("UNEXPECTED_DIRECT_PROVIDER_FETCH");
  });
  assert.deepEqual(seen, [{ purpose: "admin_installation_repository_catalog" }]);
  assert.deepEqual(result.repositories.map(x => x.full_name),
    ["jan2xo/BKE_RENDER_DOCK", "jan2xo/bke-worker"]);
  assert.equal(result.scope, "INSTALLATION_APPROVED_ONLY");
  assert.equal(result.credential.credential, "BROKER_CONNECTED");
  assert.equal(result.credential.auto_rotation, true);
  assert.doesNotMatch(JSON.stringify(result), /unused-legacy-fixture|ghs_|pem/i);
});

test("catalog fails closed without RPC even when legacy credentials exist", async () => {
  const { env } = fixture();
  delete env.BKE_GITHUB_READ_BROKER;
  await assert.rejects(() => discoverGitHubRepositories(env), /GITHUB_CATALOG_BROKER_UNAVAILABLE/);
  env.BKE_GITHUB_READ_BROKER = {
    async listApprovedGitHubRepositories() {
      throw Error("Upstream provider secrets or private details");
    },
  };
  await assert.rejects(() => discoverGitHubRepositories(env), /GITHUB_CATALOG_BROKER_UNAVAILABLE/);
});

test("catalog rejects malformed scope, ids, duplicate names and fabricated repository links", async () => {
  const base = repo(51, "bke-worker");
  const invalid = [
    { ...payload([base]), principal: "user" },
    { ...payload([base]), authority: "OTHER" },
    { ...payload([base]), total_visible: 2 },
    { ...payload([base]), total_visible: 501 },
    payload([base, base]),
    payload([base, { ...base, id: 52 }]),
    payload([{ ...base, id: 0 }]),
    payload([{ ...base, full_name: "jan2xo/../other" }]),
    payload([{ ...base, html_url: "https://untrusted.example/path" }]),
    payload([{ ...base, default_branch: "<unsafe>" }]),
    payload([{ ...base, private: "yes" }]),
    payload([{ ...base, archived: "false" }]),
  ];
  for (const item of invalid) {
    const { env } = fixture(item);
    await assert.rejects(() => discoverGitHubRepositories(env),
      /GITHUB_CATALOG_RESPONSE_INVALID|GITHUB_REPOSITORY_RESPONSE_INVALID/);
  }
});

test("catalog never accepts a worker wake, and unverified Admin cannot call private broker", async () => {
  let calls = 0;
  const { env } = fixture();
  env.BKE_GITHUB_READ_BROKER.listApprovedGitHubRepositories = async () => {
    calls++;
    return payload([repo(51, "bke-worker")]);
  };
  const noAdmin = await handleRequest(new Request("https://cc.jl-bke.com/api/admin/discovery"),
    { ...env, BKE_ADMIN_DISCOVERY_ENABLED: "true" }, () => ({}));
  assert.equal(noAdmin.status, 404);
  const notAuthenticated = await handleRequest(new Request("https://cc.jl-bke.com/api/admin/discovery"),
    { ...env, BKE_ADMIN_DISCOVERY_ENABLED: "true",
      BKE_ADMIN_ACCESS_ISSUER: "https://example.cloudflareaccess.com",
      BKE_ADMIN_ACCESS_AUD: "0123456789abcdef",
      BKE_ADMIN_EMAILS: "admin@example.test" }, () => ({}));
  assert.equal(notAuthenticated.status, 403);
  assert.equal(calls, 0);
});
