#!/usr/bin/env node
// Human-only, pinned PREPRODUCTION version promotion; never production/default/route writes.
import { execFileSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { pathToFileURL } from "node:url";
import {
  B1_ACCOUNT_ID, B1_TARGET, promptSecretFromTty, verifyScopedToken,
} from "./verify-cloudflare-deploy-token.mjs";
import { readSource, getSnapshot } from "./stage-scoped-cloudflare-version.mjs";

export const B1_PROMOTION_LOCK = Object.freeze({
  target: "bke-command-center-preproduction",
  stagedVersion: "6cd1fcc5-8c44-43a5-9ef9-af23452f2a4a",
  // Version is from this audited, operator-uploaded source, not the later
  // PR containing this release tool.
  stagedSourceSha: "eb825653a25271149f0934746683a5f0bbeb87b8",
  previousVersion: "908f6f43-97ff-4621-9bcf-f13b4b679c16",
  previousDeployment: "391149ba-0e1b-450f-8ba3-42fe787a51dc",
  stagedCreatedOn: "2026-10-09T08:02:22.552953Z",
});
const UUID = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/u;

function fail(code) { throw new Error(code); }

export function validateBefore(snapshot, lock = B1_PROMOTION_LOCK) {
  if (!snapshot || snapshot.activeVersion !== lock.previousVersion ||
      snapshot.deploymentId !== lock.previousDeployment) {
    fail("ACTIVE_PREPRODUCTION_BASELINE_CHANGED");
  }
  const staged = snapshot.versionItems?.filter(x => x.id === lock.stagedVersion) || [];
  if (staged.length !== 1 ||
      staged[0].metadata?.source !== "wrangler" ||
      staged[0].metadata?.created_on !== lock.stagedCreatedOn) {
    fail("PINNED_STAGED_VERSION_NOT_VERIFIED");
  }
  if (snapshot.versionIds?.filter(v => v === lock.stagedVersion).length !== 1 ||
      lock.stagedVersion === lock.previousVersion ||
      lock.target !== B1_TARGET || !UUID.test(lock.stagedVersion)) {
    fail("PROMOTION_SCOPE_OR_VERSION_INVALID");
  }
  return lock;
}

export function validateAfter(before, after, lock = B1_PROMOTION_LOCK) {
  if (!after || before.deploymentId === after.deploymentId ||
      after.activeVersion !== lock.stagedVersion ||
      !UUID.test(after.deploymentId || "")) {
    fail("PROMOTION_RESULT_UNKNOWN_OR_WRONG_TARGET");
  }
  if (!after.versionIds?.includes(lock.previousVersion) ||
      !after.versionIds?.includes(lock.stagedVersion)) {
    fail("VERSION_HISTORY_CHANGED_DURING_PROMOTION");
  }
  return Object.freeze({
    oldDeployment: before.deploymentId,
    oldVersion: before.activeVersion,
    newDeployment: after.deploymentId,
    newVersion: after.activeVersion,
  });
}

export function promoteWithWrangler(token, lock = B1_PROMOTION_LOCK) {
  // Do not let existing broader Wrangler identity win; explicitly replace it
  // in the child only. No token in argv, shell commands, logs or files.
  const env = { ...process.env };
  for (const k of ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY",
    "CLOUDFLARE_EMAIL", "CF_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"]) delete env[k];
  env.CLOUDFLARE_API_TOKEN = token;
  env.CLOUDFLARE_ACCOUNT_ID = B1_ACCOUNT_ID;
  env.WRANGLER_SEND_METRICS = "false";
  try {
    execFileSync("npx", [
      "--yes", "wrangler@4.148.0", "versions", "deploy",
      lock.stagedVersion + "@100%", "--env", "preproduction", "-y",
    ], {
      env, stdio: ["ignore", "pipe", "pipe"], timeout: 180000,
      maxBuffer: 2 ** 20,
    });
  } catch {
    // A failed command may have partially changed traffic. NEVER retry blindly.
    fail("PROMOTION_COMMAND_FAILED_OR_AMBIGUOUS_DO_NOT_RETRY");
  }
}

export async function promoteScopedVersion(token, {
  checkSource = readSource,
  verifyToken = verifyScopedToken,
  snapshot = getSnapshot,
  promote = promoteWithWrangler,
  fetchImpl = fetch,
  lock = B1_PROMOTION_LOCK,
} = {}) {
  const commandSha = checkSource();
  await verifyToken(token, { fetchImpl });
  const before = await snapshot(token, fetchImpl);
  validateBefore(before, lock);
  if (checkSource() !== commandSha) fail("CANONICAL_SOURCE_MOVED_BEFORE_PROMOTION");
  // Sole write. No route/custom-domain changes. Versions API promotes existing version.
  await promote(token, lock);
  const after = await snapshot(token, fetchImpl);
  const proof = validateAfter(before, after, lock);
  if (checkSource() !== commandSha) fail("CANONICAL_SOURCE_MOVED_AFTER_PROMOTION");
  // Full B1 remains pending independent protected-host Access acceptance.
  return Object.freeze({ commandSha, stagedSourceSha: lock.stagedSourceSha, ...proof });
}

async function confirmExplicitPromotion(lock = B1_PROMOTION_LOCK) {
  if (!process.stdin.isTTY || !process.stderr.isTTY) fail("HUMAN_TTY_REQUIRED");
  const prompt = "PROMOTE " + lock.stagedVersion + " PREPRODUCTION 100%";
  process.stderr.write([
    "This changes LIVE traffic on cc.jl-bke.com to an already staged version.",
    "This affects ONLY bke-command-center-preproduction, NOT production/default/Air Stack.",
    "Before proceeding: confirm the protected Access policy remains in place.",
    "Rollback anchor: " + lock.previousVersion,
    "",
  ].join("\n"));
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await rl.question("Type exactly " + prompt + " to authorize: ");
    if (answer !== prompt) fail("PROMOTION_NOT_AUTHORIZED");
  } finally { rl.close(); }
}

export async function main(args = process.argv.slice(2)) {
  if (args.length) fail("UNEXPECTED_ARGUMENTS");
  await confirmExplicitPromotion();
  const token = await promptSecretFromTty();
  const proof = await promoteScopedVersion(token);
  // ONLY fixed fields: no upstream responses, secret material or CLI stdout.
  process.stdout.write([
    "BKE_B1_SCOPED_PROMOTION=PASS",
    "TARGET_WORKER=" + B1_TARGET,
    "DEPLOYMENT_COMMAND_SHA=" + proof.commandSha,
    "STAGED_SOURCE_SHA=" + proof.stagedSourceSha,
    "NEW_ACTIVE_VERSION=" + proof.newVersion,
    "NEW_DEPLOYMENT_ID=" + proof.newDeployment,
    "PREVIOUS_ACTIVE_VERSION=" + proof.oldVersion,
    "PREVIOUS_DEPLOYMENT_ID=" + proof.oldDeployment,
    "NEW_ACTIVE_TRAFFIC=100%",
    "DEPLOYMENT_PRINCIPAL=OPERATOR_SCOPED_TOKEN",
    "ROUTES_AND_PRODUCTION_NOT_MODIFIED_BY_COMMAND=YES",
    "ACCESS_AND_FUNCTIONAL_ACCEPTANCE=PENDING",
  ].join("\n") + "\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    const reason = error instanceof Error && /^[A-Z0-9_]+$/u.test(error.message)
      ? error.message : "PROMOTION_UNKNOWN";
    process.stderr.write("BKE_B1_SCOPED_PROMOTION=BLOCKED reason=" + reason + "\n");
    process.exitCode = 1;
  });
}
