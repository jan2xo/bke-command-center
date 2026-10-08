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

test("named PREPRODUCTION environment serves the read-first overview", async () => {
  const response = await worker.fetch(new Request("https://command.test/"), {
    BKE_PREPRODUCTION: "true",
    GITHUB_OWNER: "jan2xo",
    GITHUB_REPO: "bke-worker",
  });
  assert.equal(response.status, 200);
  assert.match(await response.text(), /BKE Command Center/);
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
