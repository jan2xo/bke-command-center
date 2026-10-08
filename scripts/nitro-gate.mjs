import { pathToFileURL } from "node:url";

const SHA = /^[a-f0-9]{40}$/;
const NITRO_BRANCH = /^nitro\/[a-z0-9][a-z0-9._/-]{0,95}$/;
const CI_SKIP = /\[skip ci\]/i;

// Validate metadata before any expensive certification job runs.
// This is a merge-gate preflight, NOT an automatic PR guard.
export function validateNitroGate({ repository, pr, commits, prNumber, expectedHead, runHead, runBranch }) {
  const faults = [];
  if (repository !== "jan2xo/bke-command-center") faults.push("UNEXPECTED_REPOSITORY");
  if (!Number.isSafeInteger(prNumber) || prNumber < 1) faults.push("INVALID_PR_NUMBER");
  if (!SHA.test(expectedHead || "") || !SHA.test(runHead || "")) faults.push("INVALID_SHA");
  if (!pr || pr.number !== prNumber || pr.state !== "open" || pr.merged) faults.push("PR_NOT_OPEN");
  if (pr?.base?.ref !== "main" || pr?.base?.repo?.full_name !== repository ||
      pr?.head?.repo?.full_name !== repository) faults.push("PR_REPOSITORY_OR_BASE_INVALID");
  if (!NITRO_BRANCH.test(pr?.head?.ref || "") ||
      pr?.head?.ref !== runBranch) faults.push("NITRO_HEAD_BRANCH_MISMATCH");
  if (pr?.head?.sha !== expectedHead || runHead !== expectedHead) faults.push("STALE_EXACT_HEAD");
  const modeLabels = (Array.isArray(pr?.labels) ? pr.labels : [])
    .map((v) => typeof v?.name === "string" ? v.name.toLowerCase() : "")
    .filter((name) => name.startsWith("bke-ci:"));
  if (modeLabels.length !== 1 || modeLabels[0] !== "bke-ci:nitro" ||
      !/\*\*Engineering mode:\*\*\s*`NITRO`/i.test(pr?.body || "")) {
    faults.push("NITRO_MODE_NOT_EXPLICIT");
  }
  if (!Array.isArray(commits) || commits.length < 1 || commits.length >= 100 ||
      commits.some((item) => !SHA.test(item?.sha || "") || !CI_SKIP.test(item?.commit?.message || "")) ||
      commits.at(-1)?.sha !== expectedHead) {
    faults.push("NITRO_SKIP_COMMIT_CHAIN_INVALID");
  }
  return { ok: faults.length === 0, faults };
}

async function githubJson(route, token) {
  const response = await fetch("https://api.github.com" + route, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: "Bearer " + token,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "bke-command-center-nitro-gate",
    },
  });
  if (!response.ok) throw new Error("GITHUB_EVIDENCE_UNAVAILABLE_HTTP_" + response.status);
  return response.json();
}

export async function runGate(env = process.env) {
  const numberText = String(env.NITRO_PR_NUMBER ?? "");
  const prNumber = /^[1-9][0-9]{0,8}$/.test(numberText) ? Number(numberText) : NaN;
  const expectedHead = String(env.NITRO_EXPECTED_HEAD || "");
  const runHead = String(env.NITRO_RUN_HEAD || "");
  const runBranch = String(env.NITRO_RUN_BRANCH || "");
  const repository = String(env.GITHUB_REPOSITORY || "");
  const token = String(env.GITHUB_TOKEN || "");
  if (!token || !Number.isSafeInteger(prNumber) || !SHA.test(expectedHead) ||
      !SHA.test(runHead) || !NITRO_BRANCH.test(runBranch) ||
      repository !== "jan2xo/bke-command-center") {
    throw new Error("NITRO_GATE_INPUT_INVALID");
  }
  const [pr, commits] = await Promise.all([
    githubJson("/repos/" + repository + "/pulls/" + prNumber, token),
    githubJson("/repos/" + repository + "/pulls/" + prNumber + "/commits?per_page=100", token),
  ]);
  const result = validateNitroGate({ repository, pr, commits, prNumber, expectedHead, runHead, runBranch });
  if (!result.ok) throw new Error("NITRO_GATE_REJECTED: " + result.faults.join(","));
  process.stdout.write("NITRO_GATE_ACCEPTED pr=" + prNumber + " exact_head=" + expectedHead + "\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runGate().catch((error) => {
    process.stderr.write("NITRO_GATE_FAILED: " + String(error?.message || "UNKNOWN") + "\n");
    process.exitCode = 1;
  });
}
