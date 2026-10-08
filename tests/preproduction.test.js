import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import worker from "../src/index.js";

const root = new URL("../", import.meta.url);
const source = (name) => readFileSync(new URL(name, root), "utf8");

test("deployed entrypoint fails closed without explicit PREPRODUCTION environment", async () => {
  for (const env of [{}, { BKE_PREPRODUCTION: "false" }, { BKE_PREPRODUCTION: true }]) {
    const response = await worker.fetch(new Request("https://command.test/api/worker"), env);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), {
      error: "COMMAND_CENTER_PREPRODUCTION_ONLY",
      state: "LOCKED",
    });
  }
});

test("Access policy must be operator-verified before serving PREPRODUCTION data", async () => {
  for (const marker of [undefined, null, "", "false", "TRUE", true]) {
    const env = { BKE_PREPRODUCTION: "true", GITHUB_OWNER: "jan2xo", GITHUB_REPO: "bke-worker" };
    if (marker !== undefined) env.BKE_ACCESS_POLICY_VERIFIED = marker;
    const response = await worker.fetch(new Request("https://cc.jl-bke.com/api/overview"), env);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), {
      error: "COMMAND_CENTER_ACCESS_NOT_VERIFIED", state: "LOCKED",
    });
  }
});

test("both explicit PREPRODUCTION and verified-access markers enable route execution", async () => {
  // This is runtime plumbing only. In production the Access edge must be
  // independently tested; the marker is not an authentication mechanism.
  const response = await worker.fetch(new Request("https://cc.jl-bke.com/not-a-route"), {
    BKE_PREPRODUCTION: "true",
    BKE_ACCESS_POLICY_VERIFIED: "true",
    GITHUB_OWNER: "jan2xo",
    GITHUB_REPO: "bke-worker",
  });
  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { error: "ROUTE_NOT_FOUND" });
});

test("Wrangler config isolates marker in a named PREPRODUCTION environment", () => {
  const config = source("wrangler.toml");
  assert.match(config, /^name = "bke-command-center"$/m);
  assert.match(config, /^\[env\.preproduction\]$/m);
  assert.match(config, /^workers_dev = false$/m);
  assert.match(config, /^\[env\.preproduction\.vars\]$/m);
  const preprodVars = config.split("[env.preproduction.vars]")[1];
  assert.match(preprodVars, /^BKE_PREPRODUCTION = "true"$/m);
  assert.match(preprodVars, /^GITHUB_OWNER = "jan2xo"$/m);
  assert.match(preprodVars, /^GITHUB_REPO = "bke-worker"$/m);
  const beforeNamedEnv = config.split("[env.preproduction]")[0];
  assert.doesNotMatch(beforeNamedEnv, /^BKE_PREPRODUCTION\s*=/m);
  assert.doesNotMatch(config, /^\[env\.production(?:\.|\])|^\[env\.prod(?:\.|\])/m);
});

test("custom domain attaches only to the exact named PREPRODUCTION environment", () => {
  const config = source("wrangler.toml");
  const root = config.split("[env.preproduction]")[0];
  assert.doesNotMatch(root, /(^|\n)\s*(route\s*=|\[\[routes\]\]|\[\[env\.|BKE_ACCESS_POLICY_VERIFIED)/m);
  assert.equal((config.match(/\[\[env\.preproduction\.routes\]\]/g) || []).length, 1);
  const match = config.match(/\[\[env\.preproduction\.routes\]\]\s*\n([\s\S]*?)(?=\n\[|$)/);
  assert.ok(match, "named environment must define its own route");
  assert.match(match[1], /^pattern = "cc\.jl-bke\.com"$/m);
  assert.match(match[1], /^custom_domain = true$/m);
  assert.doesNotMatch(match[1], /\*/);
  assert.doesNotMatch(config, /\[\[env\.(?:prod|production)\.routes\]\]/);
  assert.match(config, /^workers_dev = false$/m);
  assert.match(config, /^preview_urls = false$/m);
  assert.doesNotMatch(config, /^BKE_ACCESS_POLICY_VERIFIED\s*=/m,
    "access verification marker must be an encrypted PREPRODUCTION secret");
  assert.doesNotMatch(config, /^GITHUB_TOKEN\s*=/m,
    "GitHub token must be an encrypted PREPRODUCTION secret");
});

test("NPM scripts never select the default Cloudflare deployment", () => {
  const { scripts } = JSON.parse(source("package.json"));
  for (const name of ["dev", "cloudflare:dry-run", "cloudflare:deploy:preproduction"]) {
    assert.match(scripts[name], /wrangler@4\.148\.0/);
    assert.match(scripts[name], /--env preproduction/);
    assert.doesNotMatch(scripts[name], /--env prod(?:uction)?\b/);
  }
  assert.match(scripts["cloudflare:dry-run"], /--dry-run/);
  assert.doesNotMatch(scripts["cloudflare:deploy:preproduction"], /--dry-run/);
  assert.equal(scripts["cloudflare:deploy"], undefined);
});

test("secret-like local files are ignored by git", () => {
  const ignore = source(".gitignore");
  for (const pattern of [".env", ".env.*", ".dev.vars", ".dev.vars.*"]) {
    assert.ok(ignore.split("\n").includes(pattern), `missing ignore rule: ${pattern}`);
  }
});
