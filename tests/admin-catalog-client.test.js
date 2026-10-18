import test from "node:test";
import assert from "node:assert/strict";
import { discoverGitHubRepositories, safeCatalogBrokerFailure } from "../src/admin-discovery.js";
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

test("broker RPC reports only fixed non-sensitive upstream categories", async () => {
  const expected = [
    ["ADMIN_CATALOG_LOCKED", "GITHUB_CATALOG_DISABLED"],
    ["ADMIN_CATALOG_PURPOSE_INVALID", "GITHUB_CATALOG_REQUEST_REJECTED"],
    ["GITHUB_APP_ID_UNCONFIGURED", "GITHUB_CATALOG_APP_CONFIGURATION_UNAVAILABLE"],
    ["GITHUB_APP_PRIVATE_KEY_UNCONFIGURED", "GITHUB_CATALOG_APP_CONFIGURATION_UNAVAILABLE"],
    ["GITHUB_APP_INSTALLATION_RESOLUTION_FAILED:404", "GITHUB_CATALOG_INSTALLATION_UNAVAILABLE"],
    ["GITHUB_APP_PERMISSION_REQUIRED:contents=read;granted=none", "GITHUB_CATALOG_INSTALLATION_SCOPE_REJECTED"],
    ["ADMIN_CATALOG_TOKEN_REJECTED", "GITHUB_CATALOG_TOKEN_ISSUANCE_REJECTED"],
    ["ADMIN_CATALOG_APP_SIGNING_UNAVAILABLE", "GITHUB_CATALOG_APP_SIGNING_UNAVAILABLE"],
    ["ADMIN_CATALOG_INSTALLATION_LOOKUP_UNAVAILABLE", "GITHUB_CATALOG_INSTALLATION_RUNTIME_UNAVAILABLE"],
    ["ADMIN_CATALOG_TOKEN_TRANSPORT_UNAVAILABLE", "GITHUB_CATALOG_TOKEN_TRANSPORT_UNAVAILABLE"],
    ["ADMIN_CATALOG_REPOSITORIES_TRANSPORT_UNAVAILABLE", "GITHUB_CATALOG_REPOSITORIES_TRANSPORT_UNAVAILABLE"],
    ["ADMIN_CATALOG_TOKEN_SCOPE_INVALID", "GITHUB_CATALOG_TOKEN_PERMISSION_REJECTED"],
    ["ADMIN_CATALOG_TOKEN_BEARER_INVALID", "GITHUB_CATALOG_TOKEN_BEARER_REJECTED"],
    ["ADMIN_CATALOG_TOKEN_EXPIRY_INVALID", "GITHUB_CATALOG_TOKEN_EXPIRY_REJECTED"],
    ["ADMIN_CATALOG_TOKEN_GRANT_INVALID", "GITHUB_CATALOG_TOKEN_GRANT_REJECTED"],
    ["ADMIN_CATALOG_REPOSITORIES_UNAVAILABLE", "GITHUB_CATALOG_PROVIDER_UNAVAILABLE"],
    ["ADMIN_CATALOG_REPOSITORIES_INVALID", "GITHUB_CATALOG_PROVIDER_RESPONSE_INVALID"],
    ["ADMIN_CATALOG_DUPLICATE_REPOSITORY", "GITHUB_CATALOG_PROVIDER_RESPONSE_INVALID"],
    ["ADMIN_CATALOG_RESULT_INVALID", "GITHUB_CATALOG_PROVIDER_RESPONSE_INVALID"],
  ];
  for (const [error, safe] of expected) {
    assert.equal(safeCatalogBrokerFailure(new Error(error)), safe);
    const {env} = fixture();
    env.BKE_GITHUB_READ_BROKER.listApprovedGitHubRepositories = async () => {
      throw new Error(error);
    };
    await assert.rejects(() => discoverGitHubRepositories(env), e => {
      assert.equal(e.code, safe);
      assert.equal(e.message, safe);
      return true;
    });
  }
});

test("unexpected RPC errors, provider secrets and personal details are always hidden", async () => {
  const errors = [
    "GitHub ghs_fakeTOKEN admin@example.test \n /private/key",
    "ADMIN_CATALOG_LOCKED: ghs_fakeTOKEN",
    "Error: ADMIN_CATALOG_LOCKED\nrandom-private-data",
    "GITHUB_APP_INSTALLATION_RESOLUTION_FAILED:200",
    "GITHUB_APP_PERMISSION_REQUIRED:contents=write;granted=private",
    "ADMIN_CATALOG_TOKEN_SCOPE_INVALID " + "x".repeat(300),
    "ADMIN_CATALOG_TOKEN_BEARER_INVALID: ghs_fakeTOKEN",
    "ADMIN_CATALOG_APP_SIGNING_UNAVAILABLE: PRIVATE_KEY",
    "ADMIN_CATALOG_TOKEN_TRANSPORT_UNAVAILABLE\n X-github-token: ghs_fake",
    "ADMIN_CATALOG_INSTALLATION_LOOKUP_UNAVAILABLE " + "x".repeat(400),
    "ADMIN_CATALOG_REPOSITORIES_TRANSPORT_UNAVAILABLE: SECRET",
    "ADMIN_CATALOG_TOKEN_GRANT_INVALID\n metadata write",
    "ADMIN_CATALOG_TOKEN_EXPIRY_INVALID " + "x".repeat(301),
    null,
    {message: {private: "ghs_secret"}},
    {message: "GITHUB_CATALOG_PROVIDER_UNAVAILABLE: admin@example.test"},
  ];
  for (const thrown of errors) {
    const { env } = fixture();
    env.BKE_GITHUB_READ_BROKER.listApprovedGitHubRepositories = async () => { throw thrown; };
    await assert.rejects(() => discoverGitHubRepositories(env), e => {
      assert.equal(e.code, "GITHUB_CATALOG_BROKER_UNAVAILABLE");
      assert.doesNotMatch(e.message, /ghs_|@|private|\/key|secret|\n/);
      return true;
    });
  }
});

test("known RPC serialization prefix maps to fixed error code only", () => {
  assert.equal(safeCatalogBrokerFailure(new Error("Error: ADMIN_CATALOG_LOCKED")),
    "GITHUB_CATALOG_DISABLED");
  assert.equal(safeCatalogBrokerFailure({message:"ADMIN_CATALOG_TOKEN_SCOPE_INVALID"}),
    "GITHUB_CATALOG_TOKEN_PERMISSION_REJECTED");
  assert.equal(safeCatalogBrokerFailure({message:"ghs_sensitive_token"}),
    "GITHUB_CATALOG_BROKER_UNAVAILABLE");
});

test("three catalog token stages are safe fixed categories with no fallback to PAT", async () => {
  const errors = [
    ["ADMIN_CATALOG_TOKEN_BEARER_INVALID", "GITHUB_CATALOG_TOKEN_BEARER_REJECTED"],
    ["ADMIN_CATALOG_TOKEN_EXPIRY_INVALID", "GITHUB_CATALOG_TOKEN_EXPIRY_REJECTED"],
    ["ADMIN_CATALOG_TOKEN_GRANT_INVALID", "GITHUB_CATALOG_TOKEN_GRANT_REJECTED"],
  ];
  for (const [cause, expected] of errors) {
    const { env, seen } = fixture();
    let directCalls = 0;
    env.BKE_GITHUB_READ_BROKER.listApprovedGitHubRepositories = async request => {
      seen.push(request);
      throw new Error(cause);
    };
    await assert.rejects(
      () => discoverGitHubRepositories(env, async () => { directCalls++; throw Error("PAT forbidden"); }),
      error => {
        assert.equal(error.code, expected);
        assert.doesNotMatch(error.message, /ghs_|metadata|contents|expires_at|admin@example/);
        return true;
      },
    );
    assert.equal(directCalls, 0);
    assert.deepEqual(seen, [{ purpose: "admin_installation_repository_catalog" }]);
  }
});


test("runtime-stage codes are redacted, fixed and never turn into a token or auth fallback", async () => {
  const mappings = [
    ["ADMIN_CATALOG_APP_SIGNING_UNAVAILABLE","GITHUB_CATALOG_APP_SIGNING_UNAVAILABLE"],
    ["ADMIN_CATALOG_INSTALLATION_LOOKUP_UNAVAILABLE","GITHUB_CATALOG_INSTALLATION_RUNTIME_UNAVAILABLE"],
    ["ADMIN_CATALOG_TOKEN_TRANSPORT_UNAVAILABLE","GITHUB_CATALOG_TOKEN_TRANSPORT_UNAVAILABLE"],
    ["ADMIN_CATALOG_REPOSITORIES_TRANSPORT_UNAVAILABLE","GITHUB_CATALOG_REPOSITORIES_TRANSPORT_UNAVAILABLE"],
  ];
  for (const [privateCode,publicCode] of mappings) {
    const {env,seen} = fixture();
    let fallbackCalls = 0;
    env.BKE_GITHUB_READ_BROKER.listApprovedGitHubRepositories = async request => {
      seen.push(request);
      throw new Error(privateCode);
    };
    await assert.rejects(() => discoverGitHubRepositories(env,async()=>{
      fallbackCalls++;
      throw Error("BAD_PUBLIC_TOKEN_FALLBACK");
    }),error=>{
      assert.equal(error.code,publicCode);
      assert.equal(error.message,publicCode);
      assert.doesNotMatch(error.message,/ghs_|JWT|KEY|PRIVATE_KEY|SECRET|admin@example/i);
      return true;
    });
    assert.equal(fallbackCalls,0);
    assert.deepEqual(seen,[{purpose:"admin_installation_repository_catalog"}]);
  }
});
