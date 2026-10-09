import { GitHubEvidenceError } from "./github-evidence-error.js";

const PROBE = "RATE_LIMIT_PROBE";
const invalid = () => { throw new GitHubEvidenceError("INVALID_RESPONSE", PROBE); };

// A read-only observation of the primary REST quota. This is NOT a PR,
 // worker-liveness, certification, permission-scope or token-ownership verdict.
export function normalizeGitHubQuota(payload, credentialConfigured = false) {
  const core = payload?.resources?.core;
  if (!core || typeof core !== "object") invalid();
  const { limit, remaining, used, reset } = core;
  if (![limit, remaining, used, reset].every(Number.isSafeInteger) ||
      limit <= 0 || limit > 1000000000 ||
      remaining < 0 || remaining > limit ||
      used < 0 || used > limit ||
      reset <= 0 || reset > 10000000000 ||
      !Number.isFinite(reset * 1000)) invalid();
  const resetAt = new Date(reset * 1000);
  if (Number.isNaN(resetAt.getTime())) invalid();
  return {
    source: "GITHUB_REST_RATE_LIMIT",
    state: "OBSERVED",
    credential: credentialConfigured ? "CONFIGURED" : "ABSENT",
    permission_scopes: "NOT_VERIFIED",
    core: {
      limit,
      remaining,
      used,
      resets_at: resetAt.toISOString(),
    },
    runtime_liveness: "UNKNOWN",
  };
}

export async function githubQuotaState(gh, env = {}) {
  const payload = await gh.rateLimit();
  return normalizeGitHubQuota(payload, typeof env?.GITHUB_TOKEN === "string" &&
    env.GITHUB_TOKEN.length > 0);
}
