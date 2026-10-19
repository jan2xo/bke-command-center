// Inert, server-only decision-time pairing safety assessment.
// It consumes a one-use human ticket between TWO independent on-demand
// GitHub installation PR inventories, not an atomic cross-repo claim.
// CHECKED_NOT_RESERVED is NOT permission to pair, wake, lease or dispatch.
import { inspectAdminRuntimeAccess } from "./admin-access.js";
import { readAdminWorkerAssignments } from "./admin-worker-assignments.js";

const WORKER_ID = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const INSTALLATION_ID = /^[1-9][0-9]{0,19}$/u;
const HEX32 = /^[a-f0-9]{32}$/u;
const HEX64 = /^[a-f0-9]{64}$/u;
const HEAD = /^[a-f0-9]{40}$/u;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const MAX_RECHECK_MS = 30_000;
const deny = code => Object.freeze({ state: "BLOCKED", code });
const keys = (value, expected) =>
  value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === expected;

function normalizedObservation(snapshot, installationId, workerId) {
  if (!keys(snapshot, "approved_repository_count,consistency,dispatch_authority,enumerated_open_pr_count,source,state,trusted_installation_id,worker_claims") ||
      snapshot.state !== "OBSERVED_ONLY" ||
      snapshot.source !== "GITHUB_APP_INSTALLATION" ||
      snapshot.consistency !== "NON_ATOMIC_ENUMERATION" ||
      snapshot.dispatch_authority !== "NONE" ||
      typeof snapshot.trusted_installation_id !== "string" ||
      !INSTALLATION_ID.test(snapshot.trusted_installation_id) ||
      snapshot.trusted_installation_id !== installationId ||
      !Number.isSafeInteger(snapshot.approved_repository_count) ||
      snapshot.approved_repository_count < 1 ||
      snapshot.approved_repository_count > 100 ||
      !Number.isSafeInteger(snapshot.enumerated_open_pr_count) ||
      snapshot.enumerated_open_pr_count < 0 ||
      snapshot.enumerated_open_pr_count > 2000 ||
      !Array.isArray(snapshot.worker_claims) ||
      snapshot.worker_claims.length > 500 ||
      snapshot.worker_claims.length > snapshot.enumerated_open_pr_count) {
    return null;
  }
  const claims = [];
  const prSet = new Set();
  const workerSet = new Set();
  const repoIds = new Map();
  const nameIds = new Map();
  for (const item of snapshot.worker_claims) {
    if (!keys(item, "head_sha,pr_number,repository,repository_id,worker_id") ||
        typeof item.repository !== "string" || !REPO.test(item.repository) ||
        item.repository.split("/").some(p => p === "." || p === ".." || p.includes("..")) ||
        !Number.isSafeInteger(item.repository_id) || item.repository_id < 1 ||
        !Number.isSafeInteger(item.pr_number) || item.pr_number < 1 ||
        typeof item.worker_id !== "string" || !WORKER_ID.test(item.worker_id) ||
        typeof item.head_sha !== "string" || !HEAD.test(item.head_sha)) {
      return null;
    }
    const name = item.repository.toLowerCase();
    const pr = name + "#" + item.pr_number;
    if (prSet.has(pr) || workerSet.has(item.worker_id) ||
        (repoIds.has(item.repository_id) && repoIds.get(item.repository_id) !== name) ||
        (nameIds.has(name) && nameIds.get(name) !== item.repository_id)) {
      return null;
    }
    prSet.add(pr);
    workerSet.add(item.worker_id);
    repoIds.set(item.repository_id, name);
    nameIds.set(name, item.repository_id);
    claims.push([name, item.repository_id, item.pr_number, item.head_sha, item.worker_id]);
  }
  if (repoIds.size > snapshot.approved_repository_count) return null;
  return {
    claimed: workerSet.has(workerId),
    signature: JSON.stringify([
      snapshot.trusted_installation_id,
      snapshot.approved_repository_count,
      snapshot.enumerated_open_pr_count,
      claims.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    ]),
  };
}

// This function MUST be called only by a trusted server-side orchestrator
// with a platform-authenticated Access context, an installation-ID-bound
// ticket manager (same installation), and an unmodified live broker reader.
// Do not forward a browser-supplied "verified" or adapter object.
export async function inspectDecisionTimePairingPreflight({
  env, executionCtx, trustedInstallationId, workerId, ticket,
  ticketManager, readAssignments = readAdminWorkerAssignments,
  clock = () => Date.now(),
} = {}) {
  if (env?.BKE_PREPRODUCTION !== "true" ||
      env?.BKE_ACCESS_POLICY_VERIFIED !== "true" ||
      env?.BKE_ADMIN_PR_INVENTORY_ENABLED !== "true" ||
      env?.BKE_ADMIN_PAIRING_ACTIONS_ENABLED !== "true" ||
      env?.BKE_ADMIN_DECISION_RECHECK_ENABLED !== "true") {
    return deny("DECISION_PREFLIGHT_LOCKED");
  }
  if (typeof trustedInstallationId !== "string" ||
      !INSTALLATION_ID.test(trustedInstallationId) ||
      typeof workerId !== "string" || !WORKER_ID.test(workerId) ||
      !keys(ticket, "challenge_id,one_time_nonce") ||
      typeof ticket.challenge_id !== "string" || !HEX32.test(ticket.challenge_id) ||
      typeof ticket.one_time_nonce !== "string" || !HEX64.test(ticket.one_time_nonce) ||
      typeof ticketManager?.consume !== "function" ||
      typeof readAssignments !== "function" || typeof clock !== "function") {
    return deny("DECISION_PREFLIGHT_INPUT_INVALID");
  }
  if (await inspectAdminRuntimeAccess(executionCtx, env) !== "AUTHORIZED") {
    return deny("DECISION_PREFLIGHT_ADMIN_DENIED");
  }
  let start;
  try { start = clock(); } catch { return deny("DECISION_PREFLIGHT_CLOCK_INVALID"); }
  if (!Number.isSafeInteger(start) || start < 0) return deny("DECISION_PREFLIGHT_CLOCK_INVALID");

  let before, after;
  try { before = await readAssignments(env, executionCtx); }
  catch { return deny("DECISION_PREFLIGHT_EVIDENCE_UNAVAILABLE"); }
  const initial = normalizedObservation(before, trustedInstallationId, workerId);
  if (!initial) return deny("DECISION_PREFLIGHT_EVIDENCE_INVALID");
  if (initial.claimed) return deny("DECISION_PREFLIGHT_WORKER_CLAIMED");

  // The token is consumed BEFORE the second fresh read; a later error burns
  // this ticket and forces new human approval. Fail closed on uncertainty.
  let result;
  try {
    result = await ticketManager.consume({
      action: "pair", worker_id: workerId,
      challenge_id: ticket.challenge_id, one_time_nonce: ticket.one_time_nonce,
      admin_context: executionCtx,
    });
  } catch { return deny("DECISION_PREFLIGHT_TICKET_UNAVAILABLE"); }
  if (!keys(result, "code,state") ||
      result.state !== "CONSUMED_FOR_PREFLIGHT" ||
      result.code !== "ADMIN_ACTION_SINGLE_USE_OK") {
    return deny("DECISION_PREFLIGHT_TICKET_REJECTED");
  }
  try { after = await readAssignments(env, executionCtx); }
  catch { return deny("DECISION_PREFLIGHT_EVIDENCE_UNAVAILABLE"); }
  const final = normalizedObservation(after, trustedInstallationId, workerId);
  if (!final) return deny("DECISION_PREFLIGHT_EVIDENCE_INVALID");
  if (final.claimed) return deny("DECISION_PREFLIGHT_WORKER_CLAIMED");
  if (final.signature !== initial.signature) {
    return deny("DECISION_PREFLIGHT_GITHUB_CHANGED");
  }
  let end;
  try { end = clock(); } catch { return deny("DECISION_PREFLIGHT_CLOCK_INVALID"); }
  if (!Number.isSafeInteger(end) || end < start || end - start > MAX_RECHECK_MS) {
    return deny("DECISION_PREFLIGHT_WINDOW_EXPIRED");
  }
  // Negative conflict evidence only; still no atomic GitHub label lock and
  // NO authority to proceed with protected pairing or worker dispatch.
  return Object.freeze({
    state: "CHECKED_NOT_RESERVED",
    code: "DECISION_PREFLIGHT_NON_ATOMIC",
    dispatch_authority: "NONE",
    pairing_authority: "NONE",
  });
}
