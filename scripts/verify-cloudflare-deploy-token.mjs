#!/usr/bin/env node
/**
 * Human-only, read-only proof for the existing BKE Command Center Cloudflare API token.
 * Never paste or persist a token into GitHub, chat, shell arguments or a CI environment.
 */
import { Writable } from "node:stream";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

export const B1_ACCOUNT_ID = "9e39768c751719bfdfc4b915d2afd017";
export const B1_TARGET = "bke-command-center-preproduction";
// Existence of these other Workers was independently established by the account read.
export const B1_DENIED_WORKERS = Object.freeze([
  "bke-worker-relay-preproduction",
  "bke-air-stack-site",
]);

function reject(code) {
  throw new Error(code);
}

async function getApi(token, path, fetchImpl) {
  let response;
  try {
    response = await fetchImpl("https://api.cloudflare.com/client/v4" + path, {
      method: "GET",
      headers: { Authorization: "Bearer " + token, Accept: "application/json" },
      signal: AbortSignal.timeout(12000),
      redirect: "error",
    });
  } catch {
    reject("CLOUDFLARE_TRANSPORT_UNAVAILABLE");
  }
  if (!response || !Number.isInteger(response.status)) reject("CLOUDFLARE_RESPONSE_INVALID");
  return response;
}

async function jsonOrNull(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * Successful proof requires the very same operator-supplied bearer credential to:
 * (1) verify ACTIVE as an account-owned token,
 * (2) read the exact intended PREPRODUCTION Worker,
 * (3) be denied reads to independently known, unrelated Workers.
 *
 * This is not a write/deploy permission test and does not prove that a previous
 * Wrangler deployment or an app connector used the token.
 */
export async function verifyScopedToken(token, {
  fetchImpl = fetch,
  accountId = B1_ACCOUNT_ID,
  target = B1_TARGET,
  deniedWorkers = B1_DENIED_WORKERS,
} = {}) {
  if (typeof token !== "string" || token.length < 20 ||
      token.length > 4096 || /\s/u.test(token)) reject("TOKEN_INPUT_INVALID");
  if (!/^[a-f0-9]{32}$/u.test(accountId) || !/^[a-z0-9-]+$/u.test(target) ||
      !Array.isArray(deniedWorkers) || deniedWorkers.length < 1 ||
      deniedWorkers.some((name) => typeof name !== "string" ||
        !/^[a-z0-9-]+$/u.test(name) || name === target) ||
      new Set(deniedWorkers).size !== deniedWorkers.length) {
    reject("B1_SCOPE_CONFIGURATION_INVALID");
  }

  const base = "/accounts/" + accountId;
  const verification = await getApi(token, base + "/tokens/verify", fetchImpl);
  if (verification.status !== 200) reject("ACCOUNT_TOKEN_VERIFY_DENIED");
  const verified = await jsonOrNull(verification);
  if (verified?.success !== true || verified?.result?.status !== "active") {
    reject("ACCOUNT_TOKEN_NOT_ACTIVE");
  }

  const targetResponse = await getApi(
    token, base + "/workers/scripts/" + target + "/settings", fetchImpl,
  );
  if (targetResponse.status !== 200) reject("TARGET_WORKER_READ_DENIED");
  const targetPayload = await jsonOrNull(targetResponse);
  if (targetPayload?.success !== true || !targetPayload.result ||
      typeof targetPayload.result !== "object") {
    reject("TARGET_WORKER_PROOF_INVALID");
  }

  for (const name of deniedWorkers) {
    const response = await getApi(
      token, base + "/workers/scripts/" + name + "/settings", fetchImpl,
    );
    // Some Cloudflare Worker-scoped policies mask existence with 404.
    // Neither 401 (unrecognized token) nor 5xx counts as an authorization denial.
    if (response.status !== 403 && response.status !== 404) {
      reject("UNRELATED_WORKER_READ_NOT_DENIED");
    }
  }

  return Object.freeze({
    tokenStatus: "ACTIVE",
    targetWorker: target,
    targetRead: "PASS",
    unrelatedWorkerReads: "DENIED",
    verifiedDenials: deniedWorkers.length,
    deploymentPerformed: false,
    priorDeploymentPrincipal: "NOT_PROVEN",
    editorWritePermission: "OPERATOR_ATTESTED_NOT_API_PROVEN",
  });
}

async function promptSecretFromTty() {
  if (!process.stdin.isTTY || !process.stderr.isTTY) {
    reject("HUMAN_TTY_REQUIRED");
  }
  const muted = new Writable({
    write(_chunk, _encoding, callback) { callback(); },
  });
  const rl = createInterface({ input: process.stdin, output: muted, terminal: true });
  process.stderr.write("Existing Command Center Cloudflare API token (hidden, Enter to submit): ");
  try {
    return await new Promise((resolve, rejectInput) => {
      rl.once("SIGINT", () => rejectInput(new Error("TOKEN_INPUT_CANCELLED")));
      rl.question("", resolve);
    });
  } finally {
    rl.close();
    process.stderr.write("\n");
  }
}

export async function main() {
  const token = await promptSecretFromTty();
  const result = await verifyScopedToken(token);
  // Deliberately only whitelisted non-secret words; never echo API payload.
  process.stdout.write([
    "BKE_B1_SCOPED_TOKEN_PROOF=PASS",
    "ACCOUNT_TOKEN_STATUS=" + result.tokenStatus,
    "TARGET_WORKER=" + result.targetWorker,
    "TARGET_WORKER_READ=" + result.targetRead,
    "UNRELATED_WORKER_READS=" + result.unrelatedWorkerReads,
    "UNRELATED_WORKERS_CHECKED=" + result.verifiedDenials,
    "DEPLOYMENT_PERFORMED=NO",
    "PRIOR_DEPLOYMENT_PRINCIPAL=NOT_PROVEN",
    "EDITOR_WRITE_PERMISSION=OPERATOR_ATTESTED_NOT_API_PROVEN",
  ].join("\n") + "\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    // No upstream error, headers, token, response body, or stack trace can leak.
    const safe = error instanceof Error && /^[A-Z0-9_]+$/u.test(error.message)
      ? error.message : "B1_PROOF_UNAVAILABLE";
    process.stderr.write("BKE_B1_SCOPED_TOKEN_PROOF=BLOCKED reason=" + safe + "\n");
    process.exitCode = 1;
  });
}
