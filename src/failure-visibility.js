const MAX_RUNS = 30;
const SHA = /^[0-9a-f]{40}$/;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const BAD = new Set(["failure", "timed_out"]);
const INTERRUPTED = new Set(["cancelled"]);
const BLOCKED = new Set(["action_required"]);
const IN_PROGRESS = new Set(["queued", "in_progress", "waiting", "requested", "pending"]);
const CONCLUSIONS = new Set([...BAD, ...INTERRUPTED, ...BLOCKED, "success", "neutral", "skipped", null]);
const escape = (x) => String(x ?? "")
  .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;").replaceAll('"', "&quot;")
  .replaceAll("'", "&#39;");

export function unknownFailureVisibility() {
  return {
    source: "github_actions", status: "UNKNOWN",
    scope: "latest_30_workflow_runs", fetched_run_count: null,
    failed_run_count: null, interrupted_run_count: null,
    blocked_run_count: null, pending_run_count: null,
    failures: [], observations: [], cloudflare_runtime: "UNKNOWN",
    reason: "RUN_EVIDENCE_UNAVAILABLE",
  };
}

export function normalizeFailureVisibility(payload, fullName) {
  const runs = payload?.workflow_runs;
  if (!REPO.test(fullName || "") || !Array.isArray(runs) || runs.length > MAX_RUNS) {
    throw new Error("GITHUB_FAILURE_WINDOW_AMBIGUOUS");
  }
  // An empty history is not evidence that CI is healthy.
  if (runs.length === 0) {
    return { ...unknownFailureVisibility(), fetched_run_count: 0,
      reason: "NO_WORKFLOW_RUNS_OBSERVED" };
  }
  const ids = new Set();
  const normalized = runs.map((run) => {
    if (!run || !Number.isSafeInteger(run.id) || run.id <= 0 ||
        ids.has(run.id) || typeof run.name !== "string" || !run.name.trim() ||
        !SHA.test(run.head_sha || "") ||
        !["completed", ...IN_PROGRESS].includes(run.status) ||
        !CONCLUSIONS.has(run.conclusion) ||
        (run.status !== "completed" && run.conclusion != null) ||
        (run.status === "completed" && run.conclusion == null)) {
      throw new Error("GITHUB_FAILURE_RUN_INVALID");
    }
    ids.add(run.id);
    return {
      id: run.id, name: run.name, status: run.status,
      conclusion: run.conclusion, sha: run.head_sha,
      observed_at: typeof run.updated_at === "string" ? run.updated_at : null,
      url: "https://github.com/" + fullName + "/actions/runs/" + run.id,
    };
  });
  const noteworthy = normalized.filter((x) => BAD.has(x.conclusion) || INTERRUPTED.has(x.conclusion) || BLOCKED.has(x.conclusion));
  const failures = noteworthy.map((x) => ({
    ...x,
    kind: BAD.has(x.conclusion) ? "FAILED" : INTERRUPTED.has(x.conclusion) ? "INTERRUPTED" : "BLOCKED",
    boundary: /cloudflare|relay/i.test(x.name) ? "Relay / Cloudflare integration CI" : "GitHub Actions workflow",
    causal_state: "UNVERIFIED",
    details_path: "/failures/" + x.id,
  }));
  const pending = normalized.filter((x) => IN_PROGRESS.has(x.status)).length;
  const failed = failures.filter(x => x.kind === "FAILED").length;
  const interrupted = failures.filter(x => x.kind === "INTERRUPTED").length;
  const blocked = failures.filter(x => x.kind === "BLOCKED").length;
  return {
    source: "github_actions",
    status: failed ? "FAILURES_OBSERVED" :
      interrupted ? "INTERRUPTIONS_OBSERVED" : blocked ? "BLOCKED_RUNS" :
      pending ? "PENDING_RUNS" : "NO_FAILURES_IN_SAMPLE",
    scope: "latest_30_workflow_runs",
    fetched_run_count: normalized.length,
    failed_run_count: failed,
    interrupted_run_count: interrupted,
    blocked_run_count: blocked,
    pending_run_count: pending,
    failures,
    observations: normalized,
    cloudflare_runtime: "UNKNOWN",
    reason: null,
  };
}

export function renderFailureVisibility(state) {
  const f = state || unknownFailureVisibility();
  const status = {
    FAILURES_OBSERVED: "Recent CI failures detected",
    INTERRUPTIONS_OBSERVED: "Recent CI cancellations detected",
    BLOCKED_RUNS: "Recent CI runs require action",
    PENDING_RUNS: "No reported failures; some runs are pending",
    NO_FAILURES_IN_SAMPLE: "No reportable incidents in sampled recent CI",
    UNKNOWN: "Failure evidence unavailable",
  }[f.status] || "Failure state UNKNOWN";
  const rows = f.failures.map((x) =>
    '<li><a href="' + escape(x.url) +
    '" target="_blank" rel="noopener noreferrer">' +
    escape(x.name) + " · GitHub run #" + escape(x.id) + "</a>" +
    " · " + escape(x.boundary) +
    " · " + escape(x.kind) +
    " · " + escape(x.observed_at || "time unknown") +
    " · <code>" + escape(x.sha.slice(0, 12)) +
    '</code> · <a href="' + escape(x.details_path) + '">Inspect failing steps</a></li>'
  ).join("");
  return '<section aria-label="Failure visibility"><h2>Failure visibility</h2>' +
    '<p><b>' + escape(status) + '</b></p>' +
    '<p class="muted">Source: GitHub Actions · Window: latest 30 workflow runs · No raw logs fetched.</p>' +
    (rows ? '<ul>' + rows + '</ul>' : "") +
    '<p class="muted">GitHub Actions connection: <b>' +
      (f.status === "UNKNOWN" ? "UNKNOWN" : "OBSERVED") + '</b> · ' +
      'Cloudflare account/Worker runtime: <b>UNKNOWN</b> · ' +
      'Relay connection health: <b>NOT MEASURED</b>. ' +
      'A failed GitHub relay integration check is not proof of a Cloudflare outage. ' +
      'No incidents in the sampled window does not establish system-wide health.</p>' +
    '</section>';
}
