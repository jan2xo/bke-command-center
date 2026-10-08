import { readFileSync, appendFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { validateNitroGate } from "./nitro-gate.mjs";

const REPOSITORY = "jan2xo/bke-command-center";
const SHA = /^[a-f0-9]{40}$/;
const COMMAND = /^\/nitro-certify ([a-f0-9]{40})$/;
const API = "https://api.github.com";

export function parseNitroComment(event) {
  if (event?.action !== "created" ||
      event?.repository?.full_name !== REPOSITORY ||
      !Number.isSafeInteger(event?.issue?.number) || event.issue.number < 1 ||
      !event?.issue?.pull_request ||
      event?.comment?.user?.login !== "jan2xo" ||
      event?.comment?.author_association !== "OWNER") {
    throw new Error("NITRO_COMMENT_NOT_AUTHORIZED");
  }
  const match = COMMAND.exec(event?.comment?.body || "");
  if (!match) throw new Error("NITRO_COMMENT_FORMAT_INVALID");
  return { prNumber: event.issue.number, expectedHead: match[1] };
}

async function readGitHub(path, token, fetcher) {
  const response = await fetcher(API + path, {
    headers: {
      Authorization: "Bearer " + token,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "bke-command-center-nitro-comment-gate",
    },
  });
  if (!response.ok) throw new Error("GITHUB_GATE_EVIDENCE_HTTP_" + response.status);
  return response.json();
}

export async function runNitroCommentGate(env = process.env, fetcher = globalThis.fetch) {
  if (env.GITHUB_EVENT_NAME !== "issue_comment" ||
      env.GITHUB_REPOSITORY !== REPOSITORY ||
      env.GITHUB_REF !== "refs/heads/main" ||
      !SHA.test(env.GITHUB_SHA || "") ||
      !env.GITHUB_TOKEN || !env.GITHUB_EVENT_PATH ||
      !["preflight", "postflight"].includes(env.NITRO_PHASE)) {
    throw new Error("NITRO_COMMENT_GATE_ENV_INVALID");
  }
  const event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8"));
  const { prNumber, expectedHead } = parseNitroComment(event);
  if (env.NITRO_PHASE === "postflight" && env.NITRO_CERTIFIED_HEAD !== expectedHead) {
    throw new Error("NITRO_COMMENT_POSTFLIGHT_STALE");
  }
  const [pr, commits] = await Promise.all([
    readGitHub("/repos/" + REPOSITORY + "/pulls/" + prNumber, env.GITHUB_TOKEN, fetcher),
    readGitHub("/repos/" + REPOSITORY + "/pulls/" + prNumber + "/commits?per_page=100", env.GITHUB_TOKEN, fetcher),
  ]);
  const gate = validateNitroGate({
    repository: REPOSITORY, pr, commits, prNumber, expectedHead,
    runHead: expectedHead, runBranch: pr?.head?.ref,
  });
  if (!gate.ok) throw new Error("NITRO_COMMENT_GATE_REJECTED:" + gate.faults.join(","));
  if (env.NITRO_PHASE === "preflight") {
    if (!env.GITHUB_OUTPUT) throw new Error("NITRO_COMMENT_OUTPUT_UNAVAILABLE");
    appendFileSync(env.GITHUB_OUTPUT, "source_sha=" + expectedHead + "\npr_number=" + prNumber + "\n");
  }
  process.stdout.write("NITRO_COMMENT_" + env.NITRO_PHASE.toUpperCase() +
    "_PASS pr=" + prNumber + " exact_head=" + expectedHead + "\n");
  return { prNumber, expectedHead };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runNitroCommentGate().catch((err) => {
    process.stderr.write("NITRO_COMMENT_GATE_FAILED:" +
      String(err?.message || "UNKNOWN") + "\n");
    process.exitCode = 1;
  });
}
