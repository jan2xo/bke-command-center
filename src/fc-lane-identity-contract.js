// Pure versioned F/C lane and review-evidence contract.
// This module validates shape/classifies caller-supplied records only. It does not
// authenticate a session, verify a witness signature, read GitHub, or grant authority.
// Only a private server adapter may call these helpers with server-verified projections.

export const FC_LANE_CONTRACT_VERSION = "bke.fc-lane.v1";
export const FC_REVIEW_CONTRACT_VERSION = "bke.fc-review.v1";
export const FC_ACTOR_WITNESS_AUDIENCE = "bke.fc.review-admission.v1";
export const MAX_ACTOR_WITNESS_TTL_MS = 5 * 60 * 1000;

const LANE_ID = /^(F|C)([1-9][0-9]*)$/u;
const WORKER_ID = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const GITHUB_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const SHA = /^[a-f0-9]{40}$/u;
const OPAQUE = /^[^\u0000-\u001f\u007f]{1,200}$/u;
const SECRET_LIKE = /^(?:gh[opsu]_|eyJ[A-Za-z0-9_-]{8,}\.|-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----|Bearer\s)/iu;

const LANE_KINDS = new Set(["EXECUTION", "REVIEW"]);
const LIFECYCLE_STATES = new Set([
  "PROPOSED", "AVAILABLE", "RESERVED", "ACTIVE", "PAUSED", "BLOCKED", "RETIRED",
]);
const BINDING_STATES = new Set([
  "VERIFIED", "CLAIMED", "MISSING", "REVOKED", "EXPIRED", "UNCERTAIN",
]);
const DEVICE_STATES = new Set([
  "VERIFIED", "CLAIMED", "MISSING", "REVOKED", "UNCERTAIN", "NOT_APPLICABLE",
]);
const PRINCIPAL_STATES = new Set(["VERIFIED", "CLAIMED", "MISSING", "UNCERTAIN"]);
const RESOURCE_STATES = new Set([
  "VERIFIED", "CLAIMED", "MISSING", "REVOKED", "EXPIRED", "UNCERTAIN", "NOT_APPLICABLE",
]);
const PROVIDERS = new Set(["CHATGPT", "OTHER", "NONE"]);
const TARGET_KINDS = new Set(["IMPLEMENTATION", "REVIEW"]);
const ASSIGNMENT_STATES = new Set(["ASSIGNED", "UNASSIGNED", "CONFLICT", "UNKNOWN"]);
const DECISIONS = new Set(["ACCEPT", "REMEDIATE", "BLOCKED"]);
const EVIDENCE_KINDS = new Set(["TECHNICAL_CHECKPOINT", "GITHUB_NATIVE_REVIEW"]);
const EVIDENCE_CATEGORIES = new Set([
  "SELF_AUDIT", "CROSS_WORKER_AUDIT", "INDEPENDENCE_UNVERIFIED",
]);

export class FCLaneContractError extends Error {
  constructor(code) {
    super(code);
    this.name = "FCLaneContractError";
    this.code = code;
  }
}

function fail(code) {
  throw new FCLaneContractError("FC_CONTRACT_" + code);
}

function exactObject(value, keys, code) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) {
    fail(code);
  }
}

function safeOpaque(value, code) {
  if (typeof value !== "string" || !OPAQUE.test(value) ||
      value.trim() !== value || SECRET_LIKE.test(value)) {
    fail(code);
  }
  return value;
}

function nullableOpaque(value, code) {
  return value === null ? null : safeOpaque(value, code);
}

function timestamp(value, code) {
  if (!Number.isSafeInteger(value) || value < 0) fail(code);
  return value;
}

function validRepository(value) {
  if (typeof value !== "string" || !REPOSITORY.test(value) ||
      value.split("/").some((part) => part === "." || part === ".." || part.includes(".."))) {
    fail("REPOSITORY_INVALID");
  }
  return value;
}

function validSha(value, code = "SHA_INVALID") {
  if (typeof value !== "string" || !SHA.test(value)) fail(code);
  return value;
}

function validLaneId(value, expectedKind = null) {
  if (typeof value !== "string") fail("LANE_ID_INVALID");
  const match = LANE_ID.exec(value);
  if (!match || (expectedKind && (match[1] === "F" ? "EXECUTION" : "REVIEW") !== expectedKind)) {
    fail("LANE_ID_INVALID");
  }
  return value;
}

// A VERIFIED value must originate in the future authenticated private server verifier.
// This function checks only schema, audience binding and the bounded freshness shape.
export function validateActorBindingShape(value, { nowMs } = {}) {
  timestamp(nowMs, "NOW_INVALID");
  exactObject(value, ["status", "actor_instance_id", "witness"], "ACTOR_BINDING_SCHEMA_INVALID");
  if (!BINDING_STATES.has(value.status)) fail("ACTOR_BINDING_STATUS_INVALID");

  const actorId = nullableOpaque(value.actor_instance_id, "ACTOR_INSTANCE_ID_INVALID");
  if (value.status === "MISSING" && actorId !== null) fail("MISSING_ACTOR_ID_PRESENT");

  if (value.status !== "VERIFIED") {
    if (value.witness !== null) fail("UNVERIFIED_BINDING_HAS_WITNESS");
    return { status: value.status, actor_instance_id: actorId, witness: null };
  }

  if (actorId === null) fail("VERIFIED_ACTOR_ID_MISSING");
  const witness = value.witness;
  exactObject(witness,
    ["audience", "expires_at_ms", "issued_at_ms", "verifier_id", "witness_id"],
    "ACTOR_WITNESS_SCHEMA_INVALID");
  if (witness.audience !== FC_ACTOR_WITNESS_AUDIENCE) fail("ACTOR_WITNESS_AUDIENCE_INVALID");
  const issuedAt = timestamp(witness.issued_at_ms, "ACTOR_WITNESS_ISSUED_AT_INVALID");
  const expiresAt = timestamp(witness.expires_at_ms, "ACTOR_WITNESS_EXPIRES_AT_INVALID");
  if (issuedAt > nowMs) fail("ACTOR_WITNESS_FROM_FUTURE");
  if (expiresAt <= nowMs) fail("ACTOR_WITNESS_EXPIRED");
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_ACTOR_WITNESS_TTL_MS) {
    fail("ACTOR_WITNESS_TTL_INVALID");
  }
  return {
    status: "VERIFIED",
    actor_instance_id: actorId,
    witness: {
      audience: witness.audience,
      expires_at_ms: expiresAt,
      issued_at_ms: issuedAt,
      verifier_id: safeOpaque(witness.verifier_id, "ACTOR_WITNESS_VERIFIER_INVALID"),
      witness_id: safeOpaque(witness.witness_id, "ACTOR_WITNESS_ID_INVALID"),
    },
  };
}

function validateWorkerDevice(value) {
  exactObject(value, ["registration_ref", "status", "worker_id"], "WORKER_DEVICE_SCHEMA_INVALID");
  if (!DEVICE_STATES.has(value.status)) fail("WORKER_DEVICE_STATUS_INVALID");
  const workerId = value.worker_id === null ? null : value.worker_id;
  if (workerId !== null && (typeof workerId !== "string" || !WORKER_ID.test(workerId))) {
    fail("WORKER_DEVICE_ID_INVALID");
  }
  const registrationRef = nullableOpaque(value.registration_ref, "WORKER_REGISTRATION_REF_INVALID");
  if (value.status === "VERIFIED" && (!workerId || !registrationRef)) {
    fail("VERIFIED_WORKER_DEVICE_INCOMPLETE");
  }
  if (value.status === "NOT_APPLICABLE" && (workerId !== null || registrationRef !== null)) {
    fail("NOT_APPLICABLE_WORKER_DEVICE_HAS_IDENTITY");
  }
  if (value.status === "MISSING" && (workerId !== null || registrationRef !== null)) {
    fail("MISSING_WORKER_DEVICE_HAS_IDENTITY");
  }
  return { status: value.status, worker_id: workerId, registration_ref: registrationRef };
}

function validateGitHubPrincipal(value) {
  exactObject(value, ["evidence_ref", "login", "status"], "GITHUB_PRINCIPAL_SCHEMA_INVALID");
  if (!PRINCIPAL_STATES.has(value.status)) fail("GITHUB_PRINCIPAL_STATUS_INVALID");
  const login = value.login === null ? null : value.login;
  if (login !== null && (typeof login !== "string" || !GITHUB_LOGIN.test(login))) {
    fail("GITHUB_PRINCIPAL_LOGIN_INVALID");
  }
  const evidenceRef = nullableOpaque(value.evidence_ref, "GITHUB_PRINCIPAL_EVIDENCE_REF_INVALID");
  if (value.status === "VERIFIED" && (!login || !evidenceRef)) {
    fail("VERIFIED_GITHUB_PRINCIPAL_INCOMPLETE");
  }
  if (value.status === "MISSING" && (login !== null || evidenceRef !== null)) {
    fail("MISSING_GITHUB_PRINCIPAL_HAS_IDENTITY");
  }
  return { status: value.status, login, evidence_ref: evidenceRef };
}

function validateProviderContext(value) {
  exactObject(value, [
    "account_ref", "browser_profile_ref", "chatgpt_target_ref", "evidence_ref",
    "model_ref", "provider", "resource_status",
  ], "PROVIDER_CONTEXT_SCHEMA_INVALID");
  if (!PROVIDERS.has(value.provider) || !RESOURCE_STATES.has(value.resource_status)) {
    fail("PROVIDER_CONTEXT_STATUS_INVALID");
  }
  const context = {
    provider: value.provider,
    model_ref: nullableOpaque(value.model_ref, "MODEL_REF_INVALID"),
    account_ref: nullableOpaque(value.account_ref, "ACCOUNT_REF_INVALID"),
    browser_profile_ref: nullableOpaque(value.browser_profile_ref, "BROWSER_PROFILE_REF_INVALID"),
    chatgpt_target_ref: nullableOpaque(value.chatgpt_target_ref, "CHATGPT_TARGET_REF_INVALID"),
    resource_status: value.resource_status,
    evidence_ref: nullableOpaque(value.evidence_ref, "RESOURCE_EVIDENCE_REF_INVALID"),
  };
  if (context.resource_status === "VERIFIED" &&
      (context.provider === "NONE" || !context.model_ref || !context.account_ref ||
       !context.browser_profile_ref || !context.chatgpt_target_ref || !context.evidence_ref)) {
    fail("VERIFIED_PROVIDER_CONTEXT_INCOMPLETE");
  }
  if (context.resource_status === "NOT_APPLICABLE" &&
      (context.provider !== "NONE" || context.model_ref !== null || context.account_ref !== null ||
       context.browser_profile_ref !== null || context.chatgpt_target_ref !== null ||
       context.evidence_ref !== null)) {
    fail("NOT_APPLICABLE_PROVIDER_CONTEXT_HAS_RESOURCES");
  }
  if (context.provider === "NONE" && context.resource_status !== "NOT_APPLICABLE") {
    fail("NONE_PROVIDER_STATUS_MISMATCH");
  }
  return context;
}

function validateActiveTarget(value, laneKind) {
  if (value === null) return null;
  exactObject(value, [
    "assignment_state", "evidence_ref", "head_sha", "kind", "pr_number",
    "repository", "worker_id",
  ], "ACTIVE_TARGET_SCHEMA_INVALID");
  if (!TARGET_KINDS.has(value.kind) || value.kind !== (laneKind === "EXECUTION" ? "IMPLEMENTATION" : "REVIEW")) {
    fail("ACTIVE_TARGET_KIND_MISMATCH");
  }
  if (!ASSIGNMENT_STATES.has(value.assignment_state)) fail("ASSIGNMENT_STATE_INVALID");

  const target = {
    kind: value.kind,
    assignment_state: value.assignment_state,
    repository: value.repository === null ? null : validRepository(value.repository),
    pr_number: value.pr_number === null ? null : value.pr_number,
    head_sha: value.head_sha === null ? null : validSha(value.head_sha),
    worker_id: value.worker_id === null ? null : value.worker_id,
    evidence_ref: nullableOpaque(value.evidence_ref, "ASSIGNMENT_EVIDENCE_REF_INVALID"),
  };
  if (target.pr_number !== null && (!Number.isSafeInteger(target.pr_number) || target.pr_number < 1)) {
    fail("PR_NUMBER_INVALID");
  }
  if (target.worker_id !== null && (typeof target.worker_id !== "string" || !WORKER_ID.test(target.worker_id))) {
    fail("ASSIGNED_WORKER_ID_INVALID");
  }
  if (target.assignment_state === "ASSIGNED" &&
      (!target.repository || !target.pr_number || !target.head_sha || !target.worker_id || !target.evidence_ref)) {
    fail("ASSIGNED_TARGET_INCOMPLETE");
  }
  if (target.assignment_state !== "ASSIGNED" &&
      [target.repository, target.pr_number, target.head_sha, target.worker_id].some((item) => item !== null)) {
    fail("NONASSIGNED_TARGET_HAS_SINGLE_OWNER");
  }
  return target;
}

export function validateLaneIdentityRecord(value, { nowMs } = {}) {
  timestamp(nowMs, "NOW_INVALID");
  exactObject(value, [
    "active_target", "actor_binding", "github_write_principal", "lane_id", "lane_kind",
    "lifecycle_state", "provider_context", "version", "worker_device",
  ], "LANE_RECORD_SCHEMA_INVALID");
  if (value.version !== FC_LANE_CONTRACT_VERSION) fail("LANE_VERSION_UNSUPPORTED");
  if (!LANE_KINDS.has(value.lane_kind) || !LIFECYCLE_STATES.has(value.lifecycle_state)) {
    fail("LANE_KIND_OR_LIFECYCLE_INVALID");
  }

  const laneId = validLaneId(value.lane_id, value.lane_kind);
  const actorBinding = validateActorBindingShape(value.actor_binding, { nowMs });
  const workerDevice = validateWorkerDevice(value.worker_device);
  const githubPrincipal = validateGitHubPrincipal(value.github_write_principal);
  const providerContext = validateProviderContext(value.provider_context);
  const activeTarget = validateActiveTarget(value.active_target, value.lane_kind);

  if (["AVAILABLE", "RESERVED", "ACTIVE"].includes(value.lifecycle_state)) {
    if (actorBinding.status !== "VERIFIED") fail("LANE_ACTOR_NOT_VERIFIED");
    if (providerContext.resource_status !== "VERIFIED") fail("LANE_RESOURCES_NOT_VERIFIED");
  }
  if (["RESERVED", "ACTIVE"].includes(value.lifecycle_state) &&
      (!activeTarget || activeTarget.assignment_state !== "ASSIGNED")) {
    fail("LANE_TARGET_NOT_ASSIGNED");
  }
  if (value.lifecycle_state === "ACTIVE" && githubPrincipal.status !== "VERIFIED") {
    fail("ACTIVE_GITHUB_PRINCIPAL_NOT_VERIFIED");
  }

  return {
    version: value.version,
    lane_id: laneId,
    lane_kind: value.lane_kind,
    lifecycle_state: value.lifecycle_state,
    actor_binding: actorBinding,
    worker_device: workerDevice,
    github_write_principal: githubPrincipal,
    provider_context: providerContext,
    active_target: activeTarget,
  };
}

function bindingUsable(value, nowMs) {
  try {
    return validateActorBindingShape(value, { nowMs }).status === "VERIFIED";
  } catch {
    return false;
  }
}

// Call only after a private server-side verifier has produced both bindings.
// This pure classifier is not itself proof that the provided witness is authentic.
export function classifyReviewIndependence({
  implementingActorBinding,
  reviewerActorBinding,
  nowMs,
} = {}) {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 ||
      !bindingUsable(implementingActorBinding, nowMs) ||
      !bindingUsable(reviewerActorBinding, nowMs)) {
    return "INDEPENDENCE_UNVERIFIED";
  }
  return implementingActorBinding.actor_instance_id === reviewerActorBinding.actor_instance_id
    ? "SELF_AUDIT"
    : "CROSS_WORKER_AUDIT";
}

function validateReviewTarget(value) {
  exactObject(value, ["pr_number", "repository", "reviewed_head_sha"], "REVIEW_TARGET_SCHEMA_INVALID");
  if (!Number.isSafeInteger(value.pr_number) || value.pr_number < 1) fail("REVIEW_PR_NUMBER_INVALID");
  return {
    repository: validRepository(value.repository),
    pr_number: value.pr_number,
    reviewed_head_sha: validSha(value.reviewed_head_sha, "REVIEWED_HEAD_SHA_INVALID"),
  };
}

// Classification remains advisory until the backend verifies session witnesses and
// reads the current GitHub PR/head/review state. It never claims native GitHub approval.
export function assessReviewEvidence(value, { nowMs, currentHeadSha } = {}) {
  timestamp(nowMs, "NOW_INVALID");
  exactObject(value, [
    "decision", "evidence_kind", "evidence_ref", "implementation_actor_binding",
    "implementation_lane_id", "review_id", "review_lane_id", "reviewed_at_ms", "target",
    "version", "reviewer_actor_binding",
  ], "REVIEW_RECORD_SCHEMA_INVALID");
  if (value.version !== FC_REVIEW_CONTRACT_VERSION) fail("REVIEW_VERSION_UNSUPPORTED");
  if (!DECISIONS.has(value.decision) || !EVIDENCE_KINDS.has(value.evidence_kind)) {
    fail("REVIEW_DECISION_OR_EVIDENCE_KIND_INVALID");
  }
  const reviewId = safeOpaque(value.review_id, "REVIEW_ID_INVALID");
  const implementationLaneId = validLaneId(value.implementation_lane_id, "EXECUTION");
  const reviewLaneId = validLaneId(value.review_lane_id, "REVIEW");
  const target = validateReviewTarget(value.target);
  const evidenceRef = safeOpaque(value.evidence_ref, "REVIEW_EVIDENCE_REF_INVALID");
  const reviewedAt = timestamp(value.reviewed_at_ms, "REVIEWED_AT_INVALID");
  if (reviewedAt > nowMs) fail("REVIEW_FROM_FUTURE");

  const evidenceCategory = classifyReviewIndependence({
    implementingActorBinding: value.implementation_actor_binding,
    reviewerActorBinding: value.reviewer_actor_binding,
    nowMs,
  });
  const headKnown = typeof currentHeadSha === "string" && SHA.test(currentHeadSha);
  const headStatus = !headKnown ? "UNKNOWN" :
    currentHeadSha === target.reviewed_head_sha ? "CURRENT" : "SUPERSEDED";
  let presentationStatus;
  if (headStatus === "SUPERSEDED") presentationStatus = "SUPERSEDED";
  else if (headStatus === "UNKNOWN" || value.decision === "BLOCKED" ||
      evidenceCategory === "INDEPENDENCE_UNVERIFIED") presentationStatus = "BLOCKED";
  else if (evidenceCategory === "SELF_AUDIT") presentationStatus = "FINDINGS_ONLY";
  else if (value.decision === "REMEDIATE") presentationStatus = "REMEDIATION_FINDINGS";
  else presentationStatus = "CROSS_WORKER_REVIEW_CANDIDATE";

  return {
    version: FC_REVIEW_CONTRACT_VERSION,
    review_id: reviewId,
    implementation_lane_id: implementationLaneId,
    review_lane_id: reviewLaneId,
    target,
    decision: value.decision,
    evidence_kind: value.evidence_kind,
    evidence_ref: evidenceRef,
    reviewed_at_ms: reviewedAt,
    evidence_category: evidenceCategory,
    head_status: headStatus,
    presentation_status: presentationStatus,
    independence_gate_status: evidenceCategory === "CROSS_WORKER_AUDIT" && headStatus === "CURRENT"
      ? "SATISFIED_BY_CONTRACT_CLASSIFICATION"
      : "NOT_SATISFIED",
    native_github_review_status: "NOT_CHECKED",
    authority: "NONE",
  };
}

export const FC_CONTRACT_ENUMS = Object.freeze({
  laneKinds: Object.freeze([...LANE_KINDS]),
  lifecycleStates: Object.freeze([...LIFECYCLE_STATES]),
  bindingStates: Object.freeze([...BINDING_STATES]),
  evidenceCategories: Object.freeze([...EVIDENCE_CATEGORIES]),
  decisions: Object.freeze([...DECISIONS]),
});
