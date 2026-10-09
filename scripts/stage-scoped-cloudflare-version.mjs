#!/usr/bin/env node
// Human-only B1 proof: stage (never deploy) one named PREPRODUCTION Worker version.
// Never pass credentials in argv, put them in a file, or echo API/CLI responses.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { pathToFileURL } from "node:url";
import {
  B1_ACCOUNT_ID, B1_TARGET, verifyScopedToken, promptSecretFromTty,
} from "./verify-cloudflare-deploy-token.mjs";

const UUID = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/u;
const SHA = /^[a-f0-9]{40}$/u;
const BASE = "https://api.cloudflare.com/client/v4/accounts/" + B1_ACCOUNT_ID;
const SCRIPT = BASE + "/workers/scripts/" + B1_TARGET;
const REQUIRED_SECRETS = ["GITHUB_TOKEN", "BKE_ACCESS_POLICY_VERIFIED"];

function stop(reason) { throw new Error(reason); }

export function validateSource({ branch, dirty, localSha, remoteSha, origin, config }) {
  if (branch !== "main" || dirty !== "") stop("SOURCE_NOT_CLEAN_MAIN");
  if (!SHA.test(localSha) || localSha !== remoteSha ||
      !["https://github.com/jan2xo/bke-command-center.git",
        "git@github.com:jan2xo/bke-command-center.git"].includes(origin)) {
    stop("SOURCE_NOT_CURRENT_CANONICAL_MAIN");
  }
  for (const fragment of [
    'name = "bke-command-center"', '[env.preproduction]',
    'workers_dev = false', 'preview_urls = false',
    'pattern = "cc.jl-bke.com"', 'custom_domain = true',
    'BKE_PREPRODUCTION = "true"',
  ]) {
    if (!config.includes(fragment)) stop("PREPRODUCTION_CONFIG_LOCK_FAILED");
  }
  return localSha;
}

function git(...args) {
  try {
    return execFileSync("git", args, {
      encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 20000,
    }).trim();
  } catch { stop("SOURCE_GIT_READ_FAILED"); }
}

export function readSource() {
  let config;
  try { config = readFileSync("wrangler.toml", "utf8"); }
  catch { stop("PREPRODUCTION_CONFIG_UNAVAILABLE"); }
  const remote = git("ls-remote", "origin", "refs/heads/main").split(/\s+/u)[0] || "";
  return validateSource({
    branch: git("rev-parse", "--abbrev-ref", "HEAD"),
    dirty: git("status", "--porcelain"),
    localSha: git("rev-parse", "HEAD"),
    remoteSha: remote,
    origin: git("remote", "get-url", "origin"),
    config,
  });
}

async function api(token, path, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(path, {
      method: "GET",
      headers: { Authorization: "Bearer " + token, Accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
  } catch { stop("CLOUDFLARE_PREFLIGHT_UNAVAILABLE"); }
  if (response?.status !== 200) stop("CLOUDFLARE_PREFLIGHT_DENIED");
  try {
    const data = await response.json();
    if (data?.success !== true || !data.result) stop("CLOUDFLARE_PREFLIGHT_INVALID");
    return data.result;
  } catch { stop("CLOUDFLARE_PREFLIGHT_INVALID"); }
}

export function validateSnapshot({ settings, subdomain, deployments, versions }) {
  const bindings = Array.isArray(settings?.bindings) ? settings.bindings : [];
  for (const name of REQUIRED_SECRETS) {
    if (!bindings.some(b => b?.name === name && b.type === "secret_text")) {
      stop("PREPRODUCTION_SECRET_BINDING_MISSING");
    }
  }
  if (!bindings.some(b => b?.name === "BKE_PREPRODUCTION" && b.type === "plain_text")) {
    stop("PREPRODUCTION_RUNTIME_MARKER_MISSING");
  }
  if (subdomain?.enabled !== false || subdomain?.previews_enabled !== false) {
    stop("PREPRODUCTION_PUBLIC_ALIAS_UNSAFE");
  }
  const current = deployments?.deployments?.[0];
  if (!UUID.test(current?.id || "") || !Array.isArray(current.versions) ||
      current.versions.length !== 1 || current.versions[0].percentage !== 100 ||
      !UUID.test(current.versions[0].version_id || "")) {
    stop("PREPRODUCTION_DEPLOYMENT_AMBIGUOUS");
  }
  if (!Array.isArray(versions?.items) || versions.items.length < 1 ||
      versions.items.some(v => !UUID.test(v?.id || ""))) {
    stop("PREPRODUCTION_VERSIONS_AMBIGUOUS");
  }
  const ids = versions.items.map(v => v.id);
  if (!ids.includes(current.versions[0].version_id)) {
    stop("CURRENT_VERSION_NOT_IN_VERSION_SAMPLE");
  }
  return Object.freeze({
    deploymentId: current.id,
    activeVersion: current.versions[0].version_id,
    versionIds: ids,
    versionItems: versions.items,
  });
}

export async function getSnapshot(token, fetchImpl = fetch) {
  const [settings, subdomain, deployments, versions] = await Promise.all([
    api(token, SCRIPT + "/settings", fetchImpl),
    api(token, SCRIPT + "/subdomain", fetchImpl),
    api(token, SCRIPT + "/deployments", fetchImpl),
    api(token, SCRIPT + "/versions?per_page=10", fetchImpl),
  ]);
  return validateSnapshot({ settings, subdomain, deployments, versions });
}

export function validateStage(before, after) {
  if (after.deploymentId !== before.deploymentId ||
      after.activeVersion !== before.activeVersion) {
    stop("LIVE_DEPLOYMENT_CHANGED_FAIL_CLOSED");
  }
  const added = after.versionIds.filter(id => !before.versionIds.includes(id));
  if (added.length !== 1 || !UUID.test(added[0])) {
    stop("STAGED_VERSION_NOT_UNAMBIGUOUS");
  }
  const item = after.versionItems.find(v => v.id === added[0]);
  if (item?.metadata?.source !== "wrangler") stop("STAGED_SOURCE_NOT_WRANGLER");
  return Object.freeze({
    newVersion: added[0], activeVersion: before.activeVersion,
    activeDeployment: before.deploymentId,
  });
}

export async function stageWithToken(token, {
  fetchImpl = fetch,
  checkSource = readSource,
  verifyToken = verifyScopedToken,
  snapshot = getSnapshot,
  upload = uploadWithWrangler,
} = {}) {
  // Validate the source and independent token boundary before any write.
  const sha = checkSource();
  await verifyToken(token, { fetchImpl });
  const before = await snapshot(token, fetchImpl);
  // Recheck source/active version immediately before and after upload.
  if (checkSource() !== sha) stop("SOURCE_MOVED_BEFORE_UPLOAD");
  await upload(token);
  const after = await snapshot(token, fetchImpl);
  const proof = validateStage(before, after);
  if (checkSource() !== sha) stop("SOURCE_MOVED_DURING_UPLOAD");
  return { sha, ...proof };
}

export function uploadWithWrangler(token) {
  // Token is supplied to Wrangler only as a transient child environment value.
  // No shell, argv token, stdout/stderr echo, login or default-Worker command.
  const env = { ...process.env };
  for (const key of [
    "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL",
    "CF_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID",
  ]) delete env[key];
  env.CLOUDFLARE_API_TOKEN = token;
  env.CLOUDFLARE_ACCOUNT_ID = B1_ACCOUNT_ID;
  env.WRANGLER_SEND_METRICS = "false";
  try {
    execFileSync("npx", [
      "--yes", "wrangler@4.148.0", "versions", "upload",
      "--env", "preproduction", "--keep-vars",
    ], { env, stdio: ["ignore", "pipe", "pipe"], timeout: 180000, maxBuffer: 2 ** 20 });
  } catch {
    // Failed/ambiguous writes must NEVER be retried automatically.
    stop("VERSION_UPLOAD_FAILED_OR_UNKNOWN");
  }
}

async function confirmation() {
  if (!process.stdin.isTTY || !process.stderr.isTTY) stop("HUMAN_TTY_REQUIRED");
  process.stderr.write(
    "This UPLOADS one NON-LIVE version to bke-command-center-preproduction.\n" +
    "It does NOT deploy/promote traffic, change routes, or touch production.\n",
  );
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await rl.question("Type STAGE PREPRODUCTION to authorize upload: ");
    if (answer !== "STAGE PREPRODUCTION") stop("STAGE_NOT_AUTHORIZED");
  } finally { rl.close(); }
}

export async function main(args = process.argv.slice(2)) {
  if (args.length !== 0) stop("UNEXPECTED_ARGUMENTS");
  await confirmation();
  const token = await promptSecretFromTty();
  const proof = await stageWithToken(token);
  // Only safe, bounded structured evidence. Never echo token or API bodies.
  process.stdout.write([
    "BKE_B1_SCOPED_VERSION_UPLOAD=PASS",
    "TARGET_WORKER=" + B1_TARGET,
    "SOURCE_SHA=" + proof.sha,
    "STAGED_VERSION_ID=" + proof.newVersion,
    "PREVIOUS_ACTIVE_VERSION=" + proof.activeVersion,
    "ACTIVE_DEPLOYMENT_ID=" + proof.activeDeployment,
    "LIVE_DEPLOYMENT_CHANGED=NO",
    "PRODUCTION_CHANGED=NO",
    "UPLOAD_PRINCIPAL=OPERATOR_SCOPED_TOKEN",
    "ACTUAL_TRAFFIC_PROMOTION=NOT_PERFORMED",
  ].join("\n") + "\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    const safe = error instanceof Error && /^[A-Z0-9_]+$/u.test(error.message)
      ? error.message : "STAGING_UNAVAILABLE";
    process.stderr.write("BKE_B1_SCOPED_VERSION_UPLOAD=BLOCKED reason=" + safe + "\n");
    process.exitCode = 1;
  });
}
