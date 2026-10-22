import test from "node:test";
import assert from "node:assert/strict";
import {
  FC_ACTOR_WITNESS_AUDIENCE,
  FC_LANE_CONTRACT_VERSION,
  FC_REVIEW_CONTRACT_VERSION,
  assessReviewEvidence,
  classifyReviewIndependence,
  validateActorBindingShape,
  validateLaneIdentityRecord,
} from "../src/fc-lane-identity-contract.js";

const NOW = 1_800_000_000_000;
const HEAD_A = "a".repeat(40);
const HEAD_B = "b".repeat(40);

function verifiedActor(actorId, suffix = actorId, overrides = {}) {
  return {
    status: "VERIFIED",
    actor_instance_id: actorId,
    witness: {
      audience: FC_ACTOR_WITNESS_AUDIENCE,
      verifier_id: "private-session-verifier-v1",
      witness_id: "witness-" + suffix,
      issued_at_ms: NOW - 1_000,
      expires_at_ms: NOW + 60_000,
      ...overrides,
    },
  };
}

function unverifiedActor(status = "MISSING", actorId = null) {
  return { status, actor_instance_id: actorId, witness: null };
}

function providerContext(overrides = {}) {
  return {
    provider: "CHATGPT",
    model_ref: "model-reference-1",
    account_ref: "account-reference-1",
    browser_profile_ref: "isolated-profile-1",
    chatgpt_target_ref: "chatgpt-target-1",
    resource_status: "VERIFIED",
    evidence_ref: "resource-witness-ref-1",
    ...overrides,
  };
}

function emptyTarget(kind = "IMPLEMENTATION", assignmentState = "UNASSIGNED") {
  return {
    kind,
    assignment_state: assignmentState,
    repository: null,
    pr_number: null,
    head_sha: null,
    worker_id: null,
    evidence_ref: "assignment-inventory-snapshot-1",
  };
}

function lane(overrides = {}) {
  return {
    version: FC_LANE_CONTRACT_VERSION,
    lane_id: "F1",
    lane_kind: "EXECUTION",
    lifecycle_state: "PROPOSED",
    actor_binding: unverifiedActor(),
    worker_device: {
      status: "NOT_APPLICABLE",
      worker_id: null,
      registration_ref: null,
    },
    github_write_principal: {
      status: "MISSING",
      login: null,
      evidence_ref: null,
    },
    provider_context: {
      provider: "NONE",
      model_ref: null,
      account_ref: null,
      browser_profile_ref: null,
      chatgpt_target_ref: null,
      resource_status: "NOT_APPLICABLE",
      evidence_ref: null,
    },
    active_target: null,
    ...overrides,
  };
}

function assignedTarget(kind = "IMPLEMENTATION") {
  return {
    kind,
    assignment_state: "ASSIGNED",
    repository: "jan2xo/bke-command-center",
    pr_number: 72,
    head_sha: HEAD_A,
    worker_id: "android-worker-a",
    evidence_ref: "verified-github-assignment-snapshot-1",
  };
}

function review(overrides = {}) {
  return {
    version: FC_REVIEW_CONTRACT_VERSION,
    review_id: "review-1",
    implementation_lane_id: "F1",
    review_lane_id: "C2",
    target: {
      repository: "jan2xo/bke-command-center",
      pr_number: 72,
      reviewed_head_sha: HEAD_A,
    },
    decision: "ACCEPT",
    evidence_kind: "TECHNICAL_CHECKPOINT",
    evidence_ref: "https://github.com/jan2xo/bke-command-center/pull/72#issuecomment-1",
    reviewed_at_ms: NOW - 500,
    implementation_actor_binding: verifiedActor("actor-F1", "impl"),
    reviewer_actor_binding: verifiedActor("actor-C2", "reviewer"),
    ...overrides,
  };
}

test("accepts a proposed lane while clearly retaining unverified identity", () => {
  const result = validateLaneIdentityRecord(lane(), { nowMs: NOW });
  assert.equal(result.lane_id, "F1");
  assert.equal(result.lifecycle_state, "PROPOSED");
  assert.equal(result.actor_binding.status, "MISSING");
  assert.equal(result.github_write_principal.status, "MISSING");
});

test("lane IDs must be canonical and lane kind must match their prefix", () => {
  assert.throws(() => validateLaneIdentityRecord(lane({ lane_id: "F01" }), { nowMs: NOW }),
    { code: "FC_CONTRACT_LANE_ID_INVALID" });
  assert.throws(() => validateLaneIdentityRecord(lane({ lane_id: "F0" }), { nowMs: NOW }),
    { code: "FC_CONTRACT_LANE_ID_INVALID" });
  assert.throws(() => validateLaneIdentityRecord(lane({ lane_id: "C1" }), { nowMs: NOW }),
    { code: "FC_CONTRACT_LANE_ID_INVALID" });
});

test("rejects unknown lane schema versions and surprise trust fields", () => {
  assert.throws(() => validateLaneIdentityRecord(lane({ version: "bke.fc-lane.v999" }), { nowMs: NOW }),
    { code: "FC_CONTRACT_LANE_VERSION_UNSUPPORTED" });
  assert.throws(() => validateLaneIdentityRecord({ ...lane(), trusted: true }, { nowMs: NOW }),
    { code: "FC_CONTRACT_LANE_RECORD_SCHEMA_INVALID" });
});

test("an AVAILABLE lane cannot claim readiness without a fresh verified actor and resources", () => {
  assert.throws(() => validateLaneIdentityRecord(lane({ lifecycle_state: "AVAILABLE" }), { nowMs: NOW }),
    { code: "FC_CONTRACT_LANE_ACTOR_NOT_VERIFIED" });
  const good = lane({
    lifecycle_state: "AVAILABLE",
    actor_binding: verifiedActor("actor-F1"),
    provider_context: providerContext(),
  });
  assert.equal(validateLaneIdentityRecord(good, { nowMs: NOW }).lifecycle_state, "AVAILABLE");
});

test("ACTIVE execution lane must have verified GitHub principal and assigned exact-head target", () => {
  const active = lane({
    lifecycle_state: "ACTIVE",
    actor_binding: verifiedActor("actor-F1"),
    provider_context: providerContext(),
    active_target: assignedTarget(),
    github_write_principal: { status: "MISSING", login: null, evidence_ref: null },
  });
  assert.throws(() => validateLaneIdentityRecord(active, { nowMs: NOW }),
    { code: "FC_CONTRACT_ACTIVE_GITHUB_PRINCIPAL_NOT_VERIFIED" });
  assert.throws(() => validateLaneIdentityRecord({
    ...active,
    github_write_principal: { status: "VERIFIED", login: "jan2xo", evidence_ref: "github-api-read-1" },
    active_target: emptyTarget(),
  }, { nowMs: NOW }), { code: "FC_CONTRACT_LANE_TARGET_NOT_ASSIGNED" });
});

test("a purported VERIFIED actor binding rejects missing, wrong-audience, expired, future and overlong witnesses", () => {
  assert.throws(() => validateActorBindingShape(unverifiedActor("VERIFIED", "actor"), { nowMs: NOW }),
    { code: "FC_CONTRACT_ACTOR_WITNESS_SCHEMA_INVALID" });
  const wrongAudience = verifiedActor("actor", "x", { audience: "other-purpose" });
  assert.throws(() => validateActorBindingShape(wrongAudience, { nowMs: NOW }),
    { code: "FC_CONTRACT_ACTOR_WITNESS_AUDIENCE_INVALID" });
  assert.throws(() => validateActorBindingShape(verifiedActor("actor", "x", { expires_at_ms: NOW }), { nowMs: NOW }),
    { code: "FC_CONTRACT_ACTOR_WITNESS_EXPIRED" });
  assert.throws(() => validateActorBindingShape(verifiedActor("actor", "x", { issued_at_ms: NOW + 1 }), { nowMs: NOW }),
    { code: "FC_CONTRACT_ACTOR_WITNESS_FROM_FUTURE" });
  assert.throws(() => validateActorBindingShape(verifiedActor("actor", "x", { expires_at_ms: NOW + 400_000 }), { nowMs: NOW }),
    { code: "FC_CONTRACT_ACTOR_WITNESS_TTL_INVALID" });
});

test("actor separation uses verified actor-instance IDs, never lane labels", () => {
  const sameActor = classifyReviewIndependence({
    implementingActorBinding: verifiedActor("same-actor", "impl"),
    reviewerActorBinding: verifiedActor("same-actor", "review"),
    nowMs: NOW,
  });
  assert.equal(sameActor, "SELF_AUDIT");
  const distinctActors = classifyReviewIndependence({
    implementingActorBinding: verifiedActor("actor-a", "a"),
    reviewerActorBinding: verifiedActor("actor-b", "b"),
    nowMs: NOW,
  });
  assert.equal(distinctActors, "CROSS_WORKER_AUDIT");
});

test("different actor instances may share one GitHub principal without becoming the same actor", () => {
  const fLane = lane({
    lane_id: "F1",
    actor_binding: verifiedActor("actor-instance-1", "impl"),
    github_write_principal: { status: "VERIFIED", login: "jan2xo", evidence_ref: "github-api-1" },
  });
  const cLane = lane({
    lane_id: "C1",
    lane_kind: "REVIEW",
    actor_binding: verifiedActor("actor-instance-2", "review"),
    github_write_principal: { status: "VERIFIED", login: "jan2xo", evidence_ref: "github-api-2" },
  });
  const validatedF = validateLaneIdentityRecord(fLane, { nowMs: NOW });
  const validatedC = validateLaneIdentityRecord(cLane, { nowMs: NOW });
  assert.equal(validatedF.github_write_principal.login, validatedC.github_write_principal.login);
  assert.equal(classifyReviewIndependence({
    implementingActorBinding: validatedF.actor_binding,
    reviewerActorBinding: validatedC.actor_binding,
    nowMs: NOW,
  }), "CROSS_WORKER_AUDIT");
});

test("missing, claimed, revoked, uncertain and expired actors never become independent", () => {
  for (const binding of [
    unverifiedActor("MISSING"),
    unverifiedActor("CLAIMED", "claimed-actor"),
    unverifiedActor("REVOKED", "revoked-actor"),
    unverifiedActor("UNCERTAIN", "uncertain-actor"),
    verifiedActor("expired", "expired", { expires_at_ms: NOW - 1 }),
  ]) {
    assert.equal(classifyReviewIndependence({
      implementingActorBinding: verifiedActor("actor-a", "a"),
      reviewerActorBinding: binding,
      nowMs: NOW,
    }), "INDEPENDENCE_UNVERIFIED");
  }
});

test("raw extra witness fields and secret-like references are rejected", () => {
  assert.throws(() => validateActorBindingShape({
    ...verifiedActor("actor"),
    witness: { ...verifiedActor("actor").witness, client_says_trusted: true },
  }, { nowMs: NOW }), { code: "FC_CONTRACT_ACTOR_WITNESS_SCHEMA_INVALID" });
  assert.throws(() => validateLaneIdentityRecord(lane({
    github_write_principal: { status: "VERIFIED", login: "jan2xo", evidence_ref: "ghs_secret-value" },
  }), { nowMs: NOW }), { code: "FC_CONTRACT_GITHUB_PRINCIPAL_EVIDENCE_REF_INVALID" });
});

test("review evidence is classified as a candidate only on the current exact head", () => {
  const result = assessReviewEvidence(review(), { nowMs: NOW, currentHeadSha: HEAD_A });
  assert.equal(result.evidence_category, "CROSS_WORKER_AUDIT");
  assert.equal(result.head_status, "CURRENT");
  assert.equal(result.presentation_status, "CROSS_WORKER_REVIEW_CANDIDATE");
  assert.equal(result.independence_gate_status, "SATISFIED_BY_CONTRACT_CLASSIFICATION");
  assert.equal(result.native_github_review_status, "NOT_CHECKED");
  assert.equal(result.authority, "NONE");
});

test("self-audit ACCEPT remains findings-only and cannot satisfy independence", () => {
  const value = review({
    implementation_lane_id: "F1",
    review_lane_id: "C1",
    implementation_actor_binding: verifiedActor("same-actor", "impl"),
    reviewer_actor_binding: verifiedActor("same-actor", "review"),
  });
  const result = assessReviewEvidence(value, { nowMs: NOW, currentHeadSha: HEAD_A });
  assert.equal(result.evidence_category, "SELF_AUDIT");
  assert.equal(result.presentation_status, "FINDINGS_ONLY");
  assert.equal(result.independence_gate_status, "NOT_SATISFIED");
});

test("unverified reviewer evidence blocks despite an ACCEPT claim", () => {
  const result = assessReviewEvidence(review({
    reviewer_actor_binding: unverifiedActor("CLAIMED", "claimed-reviewer"),
  }), { nowMs: NOW, currentHeadSha: HEAD_A });
  assert.equal(result.evidence_category, "INDEPENDENCE_UNVERIFIED");
  assert.equal(result.presentation_status, "BLOCKED");
  assert.equal(result.independence_gate_status, "NOT_SATISFIED");
});

test("a changed PR head supersedes the old review and unknown head blocks", () => {
  const stale = assessReviewEvidence(review(), { nowMs: NOW, currentHeadSha: HEAD_B });
  assert.equal(stale.head_status, "SUPERSEDED");
  assert.equal(stale.presentation_status, "SUPERSEDED");
  const unknown = assessReviewEvidence(review(), { nowMs: NOW, currentHeadSha: "not-a-sha" });
  assert.equal(unknown.head_status, "UNKNOWN");
  assert.equal(unknown.presentation_status, "BLOCKED");
});

test("malformed review schema, noncanonical lane pair, secret evidence and future time fail closed", () => {
  assert.throws(() => assessReviewEvidence({ ...review(), extra: "untrusted" }, {
    nowMs: NOW, currentHeadSha: HEAD_A,
  }), { code: "FC_CONTRACT_REVIEW_RECORD_SCHEMA_INVALID" });
  assert.throws(() => assessReviewEvidence(review({ implementation_lane_id: "C1" }), {
    nowMs: NOW, currentHeadSha: HEAD_A,
  }), { code: "FC_CONTRACT_LANE_ID_INVALID" });
  assert.throws(() => assessReviewEvidence(review({ evidence_ref: "eyJabcdefghi.payload" }), {
    nowMs: NOW, currentHeadSha: HEAD_A,
  }), { code: "FC_CONTRACT_REVIEW_EVIDENCE_REF_INVALID" });
  assert.throws(() => assessReviewEvidence(review({ reviewed_at_ms: NOW + 1 }), {
    nowMs: NOW, currentHeadSha: HEAD_A,
  }), { code: "FC_CONTRACT_REVIEW_FROM_FUTURE" });
});

test("conflicting and ambiguous implementation assignment cannot make an ACTIVE lane valid", () => {
  const base = lane({
    lifecycle_state: "ACTIVE",
    actor_binding: verifiedActor("actor-F1"),
    provider_context: providerContext(),
    github_write_principal: { status: "VERIFIED", login: "jan2xo", evidence_ref: "github-api-1" },
    active_target: {
      kind: "IMPLEMENTATION",
      assignment_state: "CONFLICT",
      repository: null,
      pr_number: null,
      head_sha: null,
      worker_id: null,
      evidence_ref: "conflicting-inventory-snapshot",
    },
  });
  assert.throws(() => validateLaneIdentityRecord(base, { nowMs: NOW }),
    { code: "FC_CONTRACT_LANE_TARGET_NOT_ASSIGNED" });
});
