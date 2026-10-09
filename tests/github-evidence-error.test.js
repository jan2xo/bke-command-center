import test from "node:test";
import assert from "node:assert/strict";
import { createGitHubAdapter } from "../src/github.js";
import { handleRequest } from "../src/index.js";
import { GitHubEvidenceError, statusFailure, evidenceFailure } from "../src/github-evidence-error.js";

test("only direct GitHub status evidence can identify the rate limit", () => {
  assert.deepEqual(evidenceFailure(statusFailure(429, null, "PR_DETAIL")),
    { failure_class: "RATE_LIMIT", boundary: "PR_DETAIL" });
  assert.deepEqual(evidenceFailure(statusFailure(403, "0", "OPEN_PRS")),
    { failure_class: "RATE_LIMIT", boundary: "OPEN_PRS" });
  assert.equal(statusFailure(403, null, "PR_DETAIL").category, "ACCESS_DENIED");
  assert.equal(statusFailure(401, "50", "REPOSITORY").category, "ACCESS_DENIED");
  assert.equal(statusFailure(404, null, "PR_DETAIL").category, "NOT_FOUND");
  assert.equal(statusFailure(502, null, "WORKFLOW_JOBS").category, "UPSTREAM_5XX");
  assert.equal(statusFailure(418, null, "PR_DETAIL").category, "UPSTREAM_REJECTED");
});
test("untrusted upstream names and exceptions cannot escape allowlists", () => {
  assert.deepEqual(evidenceFailure(new GitHubEvidenceError(
    "Bearer SECRET-DO-NOT-LEAK", "https://private.example/user")),
    { failure_class: "UNKNOWN", boundary: "UNKNOWN" });
  assert.deepEqual(evidenceFailure(new Error("Bearer SECRET-DO-NOT-LEAK")),
    { failure_class: "UNKNOWN", boundary: "UNKNOWN" });
});
test("GitHub adapter classifies real HTTP status without echoing body or headers", async () => {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, opts) => {
    calls.push({ url: String(url), opts });
    return new Response(
      JSON.stringify({ message: "Bearer HIDDEN private installation name" }),
      { status: 403, headers: { "x-ratelimit-remaining": "0" } },
    );
  };
  try {
    const adapter = createGitHubAdapter({ GITHUB_TOKEN: "HIDDEN", GITHUB_OWNER: "jan2xo", GITHUB_REPO: "bke-worker" });
    await assert.rejects(adapter.pullRequest(82), (error) =>
      error instanceof GitHubEvidenceError &&
      error.category === "RATE_LIMIT" && error.boundary === "PR_DETAIL" &&
      !JSON.stringify(error).includes("HIDDEN"));
    assert.equal(calls.length, 1);
    assert.match(calls[0].url, /\/pulls\/82$/);
  } finally { globalThis.fetch = original; }
});
test("transport and malformed JSON remain distinct unknown evidence classes", async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => { throw new Error("Bearer CREDENTIALS"); };
    await assert.rejects(createGitHubAdapter({}).repo(), (err) =>
      err.category === "TRANSPORT" && err.boundary === "REPOSITORY" && !err.message.includes("CREDENTIALS"));
    globalThis.fetch = async () => new Response("not-json", { status: 200 });
    await assert.rejects(createGitHubAdapter({}).repo(), (err) =>
      err.category === "INVALID_RESPONSE" && err.boundary === "REPOSITORY");
  } finally { globalThis.fetch = original; }
});
test("HTML PR errors use a safe explanatory 502 page, not raw JSON or upstream secrets", async () => {
  const gh = {
    pullRequest: async () => { throw new GitHubEvidenceError("RATE_LIMIT", "PR_DETAIL"); },
  };
  const response = await handleRequest(new Request("https://cc.jl-bke.com/pr/82"), {}, () => gh);
  assert.equal(response.status, 502);
  assert.match(response.headers.get("content-type"), /text\/html/);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.text();
  assert.match(body, /GitHub evidence temporarily unavailable/);
  assert.match(body, /RATE_LIMIT/);
  assert.match(body, /PR_DETAIL/);
  assert.match(body, /Evidence state:<\/b> UNKNOWN/);
  assert.doesNotMatch(body, /Bearer|password|secret_text/);
});
test("API PR errors remain machine-readable and no-store", async () => {
  const gh = { pullRequest: async () => { throw new GitHubEvidenceError("ACCESS_DENIED", "PR_DETAIL"); } };
  const res = await handleRequest(new Request("https://cc.jl-bke.com/api/pr/82"), {}, () => gh);
  assert.equal(res.status, 502);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.deepEqual(await res.json(), {
    error: "GITHUB_EVIDENCE_UNAVAILABLE",
    state: "UNKNOWN",
    failure_class: "ACCESS_DENIED",
    boundary: "PR_DETAIL",
  });
});
test("homepage upstream faults do not masquerade as healthy PR assignment", async () => {
  const gh = { repo: async () => { throw new Error("AUTHORIZATION: Bearer DO-NOT-LEAK"); },
    openPullRequests: async () => [], recentClosedPullRequests: async () => [] };
  const res = await handleRequest(new Request("https://cc.jl-bke.com/"), {}, () => gh);
  assert.equal(res.status, 502);
  const body = await res.text();
  assert.match(body, /UNKNOWN/);
  assert.match(body, /GitHub evidence temporarily unavailable/);
  assert.doesNotMatch(body, /DO-NOT-LEAK|AUTHORIZATION/);
  assert.doesNotMatch(body, /IDLE|BUSY|CERTIFIED/);
});
