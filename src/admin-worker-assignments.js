// PREPRODUCTION-only, on-demand Admin read-side consumer for BKE Worker #104.
// No browser-controlled repository, installation, PR or worker parameters.
// NON_ATOMIC_ENUMERATION is evidence observed, NEVER a dispatch or pairing lease.
import { inspectAdminRuntimeAccess } from "./admin-access.js";

const PURPOSE = Object.freeze({ purpose: "admin_worker_assignment_inventory" });
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const WORKER_LABEL = /^bke-worker:([a-z0-9][a-z0-9-]{0,62})$/u;
const HEAD = /^[a-f0-9]{40}$/u;
const ID = /^[1-9][0-9]{0,19}$/u;
const fail = (code) => { throw new AdminWorkerAssignmentError(code); };
const exactKeys = (obj, keys) => obj && typeof obj === "object" &&
  !Array.isArray(obj) && Object.keys(obj).sort().join(",") === keys;

export class AdminWorkerAssignmentError extends Error {
  constructor(code) {
    super(code);
    this.name = "AdminWorkerAssignmentError";
    this.code = code;
  }
}

export async function readAdminWorkerAssignments(env, executionCtx) {
  // A separate opt-in latch, not the existing discovery or pairing-action flag.
  if (env?.BKE_ADMIN_PR_INVENTORY_ENABLED !== "true" ||
      env?.BKE_PREPRODUCTION !== "true" ||
      env?.BKE_ACCESS_POLICY_VERIFIED !== "true") {
    fail("ADMIN_ASSIGNMENT_READ_DISABLED");
  }
  // Human-only Access identity is a Cloudflare platform context. Never use
  // caller-provided JWT headers or caller-supplied booleans for this check.
  if (await inspectAdminRuntimeAccess(executionCtx, env) !== "AUTHORIZED") {
    fail("ADMIN_ASSIGNMENT_ACCESS_DENIED");
  }
  const rpc = env?.BKE_GITHUB_READ_BROKER?.listVerifiedWorkerAssignments;
  if (typeof rpc !== "function") fail("ADMIN_ASSIGNMENT_BROKER_UNAVAILABLE");
  let payload;
  try {
    payload = await env.BKE_GITHUB_READ_BROKER.listVerifiedWorkerAssignments(PURPOSE);
  } catch {
    // No upstream exception, token, GitHub URL or credential bytes in response.
    fail("ADMIN_ASSIGNMENT_BROKER_UNAVAILABLE");
  }
  if (!exactKeys(payload,
    "authority,consistency,enumerated_open_pull_requests,installation_id,principal,repository_scope,total_visible_repositories,worker_assignments") ||
      payload.authority !== "EXISTING_GITHUB_APP_INSTALLATION" ||
      payload.principal !== "github_app_installation" ||
      payload.repository_scope !== "INSTALLATION_APPROVED_ONLY" ||
      payload.consistency !== "NON_ATOMIC_ENUMERATION" ||
      typeof payload.installation_id !== "string" ||
      !ID.test(payload.installation_id) ||
      !Number.isSafeInteger(payload.total_visible_repositories) ||
      payload.total_visible_repositories < 1 ||
      payload.total_visible_repositories > 100 ||
      !Number.isSafeInteger(payload.enumerated_open_pull_requests) ||
      payload.enumerated_open_pull_requests < 0 ||
      payload.enumerated_open_pull_requests > 2000 ||
      !Array.isArray(payload.worker_assignments) ||
      payload.worker_assignments.length > 500 ||
      payload.worker_assignments.length > payload.enumerated_open_pull_requests ||
      payload.worker_assignments.length > payload.total_visible_repositories * 400) {
    fail("ADMIN_ASSIGNMENT_RESPONSE_INVALID");
  }
  const seenWorkers = new Set();
  const seenPrs = new Set();
  const repoIds = new Map();
  const repoNames = new Map();
  const claims = [];
  for (const item of payload.worker_assignments) {
    if (!exactKeys(item, "head_sha,labels,number,repository,repository_id,state") ||
        typeof item.repository !== "string" || !REPO.test(item.repository) ||
        item.repository.split("/").some(p => p === "." || p === ".." || p.includes("..")) ||
        !Number.isSafeInteger(item.repository_id) || item.repository_id <= 0 ||
        !Number.isSafeInteger(item.number) || item.number <= 0 ||
        item.state !== "open" || !HEAD.test(item.head_sha) ||
        !Array.isArray(item.labels) || item.labels.length !== 1 ||
        typeof item.labels[0] !== "string") {
      fail("ADMIN_ASSIGNMENT_RESPONSE_INVALID");
    }
    const match = WORKER_LABEL.exec(item.labels[0]);
    if (!match) fail("ADMIN_ASSIGNMENT_RESPONSE_INVALID");
    const workerId = match[1];
    const repo = item.repository.toLowerCase();
    const prKey = repo + "#" + item.number;
    if (seenWorkers.has(workerId) || seenPrs.has(prKey) ||
        (repoIds.has(item.repository_id) && repoIds.get(item.repository_id) !== repo) ||
        (repoNames.has(repo) && repoNames.get(repo) !== item.repository_id)) {
      fail("ADMIN_ASSIGNMENT_RESPONSE_INVALID");
    }
    seenWorkers.add(workerId);
    seenPrs.add(prKey);
    repoIds.set(item.repository_id, repo);
    repoNames.set(repo, item.repository_id);
    claims.push({
      repository: item.repository, repository_id: item.repository_id,
      pr_number: item.number, head_sha: item.head_sha, worker_id: workerId,
    });
  }
  if (repoIds.size > payload.total_visible_repositories) {
    fail("ADMIN_ASSIGNMENT_RESPONSE_INVALID");
  }
  // This internal projection retains server-only installation identity for
  // future independent binding validation. NEVER pass it through the API.
  return Object.freeze({
    state: "OBSERVED_ONLY",
    source: "GITHUB_APP_INSTALLATION",
    consistency: "NON_ATOMIC_ENUMERATION",
    dispatch_authority: "NONE",
    trusted_installation_id: payload.installation_id,
    approved_repository_count: payload.total_visible_repositories,
    enumerated_open_pr_count: payload.enumerated_open_pull_requests,
    worker_claims: Object.freeze(claims),
  });
}

// Browser-safe, strictly rebuilt Admin diagnostics. Drops installation ID.
export function publicWorkerAssignmentProjection(snapshot) {
  if (!snapshot || snapshot.state !== "OBSERVED_ONLY" ||
      snapshot.consistency !== "NON_ATOMIC_ENUMERATION" ||
      snapshot.dispatch_authority !== "NONE" ||
      !Array.isArray(snapshot.worker_claims)) {
    fail("ADMIN_ASSIGNMENT_RESPONSE_INVALID");
  }
  return {
    state: "OBSERVED_ONLY",
    source: "GITHUB_APP_INSTALLATION",
    consistency: "NON_ATOMIC_ENUMERATION",
    dispatch_authority: "NONE",
    total_visible_repositories: snapshot.approved_repository_count,
    enumerated_open_pull_requests: snapshot.enumerated_open_pr_count,
    assignments: snapshot.worker_claims.map(row => ({
      repository: row.repository,
      pr_number: row.pr_number,
      head_sha: row.head_sha,
      worker_id: row.worker_id,
    })),
    warning: "GitHub PR observations are not an atomic lease or worker-liveness proof.",
  };
}
