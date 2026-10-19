// Internal, side-effect-free PREPRODUCTION enrollment eligibility preflight.
// NEVER proof of device-key possession, human approval, or an active lease.
// No public endpoint or credential/wake issuance is wired to this module.
const WORKER_ID = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_CHALLENGE_MS = 5 * 60 * 1000;
const RESOURCE_KEYS = Object.freeze([
  "identity_public_key_sha256",
  "chatgpt_target_sha256",
  "browser_profile_sha256",
  "bridge_identity_sha256",
  "nonce_sha256",
]);
const BLOCKED = (code) => Object.freeze({ state: "BLOCKED", code });

function validIdentity(item) {
  return item && typeof item === "object" && !Array.isArray(item) &&
    typeof item.worker_id === "string" && WORKER_ID.test(item.worker_id) &&
    RESOURCE_KEYS.every((key) => typeof item[key] === "string" && SHA256.test(item[key]));
}

// READY_FOR_HUMAN_REVIEW is NOT authorization, pairing, or an active lease.
// Inventories and verified flags MUST be supplied by a trusted server-side caller
// after complete independently authorized reads; never accept client inventories.
export function evaluateWorkerEnrollment(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      input.inventoryVerified !== true || input.prSnapshotVerified !== true ||
      !Array.isArray(input.pairedWorkers) || !Array.isArray(input.openPullRequests)) {
    return BLOCKED("ENROLLMENT_EVIDENCE_UNAVAILABLE");
  }
  const { candidate, pairedWorkers, openPullRequests, nowMs } = input;
  if (!validIdentity(candidate) || !Number.isSafeInteger(nowMs) || nowMs < 0 ||
      !Number.isSafeInteger(candidate.expires_at_ms) ||
      candidate.expires_at_ms <= nowMs ||
      candidate.expires_at_ms > nowMs + MAX_CHALLENGE_MS ||
      candidate.dispatch_state !== "IDLE") {
    return BLOCKED("ENROLLMENT_CANDIDATE_INVALID_OR_BUSY");
  }
  const knownIds = new Set();
  const knownResources = new Set();
  for (const existing of pairedWorkers) {
    if (!validIdentity(existing) || knownIds.has(existing.worker_id)) {
      return BLOCKED("ENROLLMENT_REGISTRY_AMBIGUOUS");
    }
    knownIds.add(existing.worker_id);
    for (const key of RESOURCE_KEYS) {
      const resource = key + ":" + existing[key];
      if (knownResources.has(resource)) return BLOCKED("ENROLLMENT_REGISTRY_AMBIGUOUS");
      knownResources.add(resource);
    }
  }
  if (knownIds.has(candidate.worker_id)) return BLOCKED("ENROLLMENT_ID_ALREADY_PAIRED");
  for (const key of RESOURCE_KEYS) {
    if (knownResources.has(key + ":" + candidate[key])) {
      return BLOCKED("ENROLLMENT_RESOURCE_ALREADY_PAIRED");
    }
  }
  const seenPrs = new Set();
  for (const pr of openPullRequests) {
    if (!pr || typeof pr !== "object" || !Number.isSafeInteger(pr.number) ||
        pr.number < 1 || typeof pr.repository !== "string" ||
        !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(pr.repository) ||
        pr.state !== "open" || !Array.isArray(pr.labels)) {
      return BLOCKED("ENROLLMENT_PR_SNAPSHOT_AMBIGUOUS");
    }
    const prKey = pr.repository + "#" + pr.number;
    if (seenPrs.has(prKey)) return BLOCKED("ENROLLMENT_PR_SNAPSHOT_AMBIGUOUS");
    seenPrs.add(prKey);
    const labels = [];
    for (const label of pr.labels) {
      if (typeof label !== "string") return BLOCKED("ENROLLMENT_PR_SNAPSHOT_AMBIGUOUS");
      if (label.startsWith("bke-worker:")) {
        if (!WORKER_ID.test(label.slice("bke-worker:".length))) {
          return BLOCKED("ENROLLMENT_PR_SNAPSHOT_AMBIGUOUS");
        }
        labels.push(label);
      }
    }
    if (labels.length > 1 || new Set(labels).size !== labels.length) {
      return BLOCKED("ENROLLMENT_PR_ASSIGNMENT_CONFLICT");
    }
    if (labels.includes("bke-worker:" + candidate.worker_id)) {
      return BLOCKED("ENROLLMENT_ACTIVE_PR_REQUIRES_RECOVERY");
    }
  }
  return Object.freeze({ state: "READY_FOR_HUMAN_REVIEW", code: "ENROLLMENT_PREFLIGHT_OK" });
}
