export const SYSTEM_REGISTRY = Object.freeze({
  worker: Object.freeze({
    slug: "worker",
    repo: "jan2xo/bke-worker",
    label: "BKE Worker",
    worker_id: "android-worker-a",
    certification_workflow: "Intent Certification",
    required_certification_job: "Required certification",
  }),
});

const FAILURE_STATES = new Set(["failure", "cancelled", "timed_out", "action_required"]);
const PENDING_STATES = new Set(["queued", "in_progress", "waiting", "requested", "pending"]);
const POSITIVE_STATES = new Set(["success", "passed", "neutral"]);

export function normalizeStatus(value) {
  return String(value || "").toLowerCase().replaceAll(" ", "_");
}

export function evidenceMatchesHead(item, exactHead) {
  if (!exactHead) return false;
  const heads = [
    item?.sha,
    item?.head_sha,
    item?.source_sha,
    item?.resolved_sha,
    item?.pr_head_sha,
    item?.exact_head,
    item?.pull_request?.head?.sha,
    ...(Array.isArray(item?.pull_requests) ? item.pull_requests.map((x) => x?.head?.sha) : []),
  ].filter(Boolean);
  return heads.includes(exactHead);
}

export function certificationSummary({ exactHead, requiredEvidence = [], observedChecks = [] }) {
  const required = requiredEvidence.filter((x) => evidenceMatchesHead(x, exactHead));
  const observed = observedChecks.filter((x) => evidenceMatchesHead(x, exactHead));
  const observedSummary = {
    total: observed.length,
    failures: observed.filter((x) => FAILURE_STATES.has(normalizeStatus(x.conclusion || x.status))).length,
    pending: observed.filter((x) => PENDING_STATES.has(normalizeStatus(x.conclusion || x.status))).length,
    positive: observed.filter((x) => POSITIVE_STATES.has(normalizeStatus(x.conclusion || x.status))).length,
  };

  if (!required.length) {
    return {
      exact_head: exactHead,
      required_evidence_seen: 0,
      observed_checks: observedSummary,
      state: "UNKNOWN",
      reason: "NO_REQUIRED_CERTIFICATION_EVIDENCE",
    };
  }

  const failures = required.filter((x) => FAILURE_STATES.has(normalizeStatus(x.conclusion || x.status)));
  const pending = required.filter((x) => PENDING_STATES.has(normalizeStatus(x.conclusion || x.status)));
  const positive = required.filter((x) => POSITIVE_STATES.has(normalizeStatus(x.conclusion || x.status)));

  return {
    exact_head: exactHead,
    required_evidence_seen: required.length,
    observed_checks: observedSummary,
    failures: failures.length,
    pending: pending.length,
    positive: positive.length,
    state: failures.length ? "FAILED" : pending.length ? "PENDING" : positive.length ? "PASSED" : "UNKNOWN",
    reason: failures.length || pending.length || positive.length ? null : "NO_DECISIVE_REQUIRED_PROOF",
  };
}

export function boundaryFromJobName(name) {
  const value = String(name || "").toLowerCase();
  if (value.includes("cloudflare") && value.includes("relay")) return "cloudflare-relay";
  if (value.includes("required certification")) return "certification";
  if (value.includes("android")) return "android";
  if (value.includes("core")) return "core";
  if (value.includes("server")) return "server";
  if (value.includes("chatgpt")) return "chatgpt";
  return String(name || "github-actions").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "github-actions";
}

export function stageFromStep(stepName, jobName = "") {
  const value = `${stepName || ""} ${jobName || ""}`.toLowerCase();
  if (/test|verify|probe|contract|assert|smoke/.test(value)) return "test";
  if (/build|compile|publish/.test(value)) return "build";
  if (/deploy|release/.test(value)) return "deploy";
  return "workflow";
}

export function reduceFirstCausalFailure(evidence = []) {
  const failures = evidence.filter((x) => FAILURE_STATES.has(normalizeStatus(x.conclusion || x.status)));
  const positives = evidence.filter((x) => POSITIVE_STATES.has(normalizeStatus(x.conclusion || x.status)));
  if (!failures.length) {
    return {
      causal: null,
      downstream: [],
      unaffected: [...new Set(positives.map((x) => x.boundary).filter(Boolean))],
    };
  }

  const ordered = [...failures].sort((a, b) =>
    String(a.occurred_at || "").localeCompare(String(b.occurred_at || "")) ||
    Number(Boolean(a.causal === false)) - Number(Boolean(b.causal === false))
  );
  const causal = ordered.find((x) => x.causal !== false) || ordered[0];
  return {
    causal: { ...causal, classification: "CAUSAL" },
    downstream: ordered.filter((x) => x !== causal).map((x) => ({ ...x, classification: "DOWNSTREAM" })),
    unaffected: [...new Set(positives.map((x) => x.boundary).filter(Boolean))],
  };
}

export function buildFailureCapsule({ repo, pr_number, exact_head, worker_id, evidence }) {
  const reduced = reduceFirstCausalFailure(evidence);
  const causal = reduced.causal;
  return {
    repo,
    pr_number,
    exact_head,
    worker_id: worker_id || null,
    occurred_at: causal?.occurred_at || null,
    host: causal?.host || null,
    boundary: causal?.boundary || null,
    stage: causal?.stage || null,
    classification: causal ? "CAUSAL" : null,
    summary: causal?.summary || null,
    evidence_run_ids: causal?.evidence_run_ids || [],
    evidence: causal?.evidence || [],
    downstream: reduced.downstream,
    unaffected_boundaries: reduced.unaffected,
    next_owner: causal?.next_owner || null,
    next_action: causal?.next_action || null,
  };
}

export function buildPostRunSummary(state) {
  const failure = state.first_causal_failure?.causal || (state.first_causal_failure?.classification === "CAUSAL" ? state.first_causal_failure : null);
  if (failure?.summary) return `First causal failure: ${failure.summary}. Next: ${failure.next_action || "inspect the causal evidence"}`;
  if (state.certification?.state === "PENDING") return "Required certification is still in progress.";
  if (state.certification?.state === "PASSED") return "Required certification passed for the exact PR head.";
  if (state.certification?.state === "FAILED") return "Required certification failed for the exact PR head.";
  return "Required certification state is UNKNOWN.";
}

export function redactSensitive(text) {
  return String(text || "")
    .replace(/github_pat_[A-Za-z0-9_]+/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/gh[pousr]_[A-Za-z0-9]+/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/(authorization\s*[:=]\s*)(?:bearer\s+)?([^\s]+)/gi, "$1[REDACTED]")
    .replace(/(bearer\s+)([A-Za-z0-9._~+\/-]+)/gi, "$1[REDACTED]");
}

export function extractFailureExcerpt(logText, maxLines = 12) {
  const lines = redactSensitive(logText).replace(/\x1B\[[0-?]*[ -\/]*[@-~]/g, "").split(/\r?\n/);
  const strong = /(AssertionError|not ok\b|expected\b.*actual|FAIL-CLOSED|\berror\b|\bfail(?:ed|ure)?\b)/i;
  let index = lines.findIndex((line) => strong.test(line) && !/Process completed with exit code/i.test(line));
  if (index < 0) index = lines.findIndex((line) => /Process completed with exit code/i.test(line));
  if (index < 0) return { excerpt: [], found: false };
  const before = 2;
  const start = Math.max(0, index - before);
  return { excerpt: lines.slice(start, start + maxLines), found: true };
}
