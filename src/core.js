export const SYSTEM_REGISTRY = Object.freeze({
  worker: Object.freeze({
    slug: "worker",
    repo: "jan2xo/bke-worker",
    label: "BKE Worker",
  }),
});

const FAILURE_ORDER = ["queued", "in_progress", "failure", "cancelled", "timed_out", "action_required"];

export function normalizeStatus(value) {
  return String(value || "").toLowerCase().replaceAll(" ", "_");
}

export function certificationSummary({ exactHead, checks = [], workflowRuns = [] }) {
  const relevantChecks = checks.filter((check) => !check.sha || check.sha === exactHead);
  const relevantRuns = workflowRuns.filter((run) => !run.head_sha || run.head_sha === exactHead);
  const failures = [...relevantChecks, ...relevantRuns].filter((item) => {
    const state = normalizeStatus(item.conclusion || item.status);
    return ["failure", "cancelled", "timed_out", "action_required"].includes(state);
  });
  const pending = [...relevantChecks, ...relevantRuns].filter((item) => {
    const state = normalizeStatus(item.conclusion || item.status);
    return ["queued", "in_progress", "waiting", "requested", "pending"].includes(state);
  });
  return {
    exact_head: exactHead,
    checks_seen: relevantChecks.length,
    workflow_runs_seen: relevantRuns.length,
    failures: failures.length,
    pending: pending.length,
    state: failures.length ? "FAILED" : pending.length ? "PENDING" : "PASSED",
  };
}

function failureRank(item) {
  const stage = String(item.stage || "").toLowerCase();
  const state = normalizeStatus(item.conclusion || item.status);
  const stageRank = stage === "test" ? 0 : stage === "build" ? 1 : 2;
  const stateRank = Math.max(0, FAILURE_ORDER.indexOf(state));
  return stageRank * 10 + stateRank;
}

export function reduceFirstCausalFailure(evidence = []) {
  const failures = evidence.filter((item) => {
    const state = normalizeStatus(item.conclusion || item.status);
    return ["failure", "cancelled", "timed_out", "action_required"].includes(state);
  });
  if (!failures.length) return { causal: null, downstream: [], unaffected: [] };

  const ordered = [...failures].sort((a, b) =>
    String(a.occurred_at || "").localeCompare(String(b.occurred_at || "")) ||
    failureRank(a) - failureRank(b)
  );
  const causal = ordered.find((item) => item.causal !== false) || ordered[0];
  const downstream = ordered.filter((item) => item !== causal).map((item) => ({
    ...item,
    classification: "DOWNSTREAM",
  }));
  return {
    causal: { ...causal, classification: "CAUSAL" },
    downstream,
    unaffected: evidence.filter((item) => {
      const state = normalizeStatus(item.conclusion || item.status);
      return ["success", "passed", "neutral", "skipped"].includes(state);
    }).map((item) => item.boundary).filter(Boolean),
  };
}

export function buildPostRunSummary(state) {
  const failure = state.first_causal_failure?.causal;
  if (failure) {
    return `First causal failure: ${failure.summary}. Next: ${failure.next_action || "inspect the causal evidence"}`;
  }
  if (state.certification?.state === "PENDING") return "Certification is still in progress.";
  if (state.certification?.state === "PASSED") return "Required observed checks passed for the exact PR head.";
  return "Current engineering state is UNKNOWN.";
}

export function buildFailureCapsule({ repo, pr_number, exact_head, worker_id, evidence }) {
  const reduced = reduceFirstCausalFailure(evidence);
  const causal = reduced.causal;
  return {
    repo, pr_number, exact_head, worker_id: worker_id || null,
    occurred_at: causal?.occurred_at || null,
    host: causal?.host || null,
    boundary: causal?.boundary || null,
    stage: causal?.stage || null,
    classification: causal ? "CAUSAL" : null,
    summary: causal?.summary || null,
    evidence_run_ids: causal?.evidence_run_ids || [],
    unaffected_boundaries: reduced.unaffected,
    next_owner: causal?.next_owner || null,
    next_action: causal?.next_action || null,
  };
}
