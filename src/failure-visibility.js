const MAX_RUNS = 8;
const SHA = /^[0-9a-f]{40}$/;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const BAD = new Set(["failure", "cancelled", "timed_out", "action_required"]);
const IN_PROGRESS = new Set(["queued", "in_progress", "waiting", "requested", "pending"]);
const CONCLUSIONS = new Set([...BAD, "success", "neutral", "skipped", null]);
const escape = (x) => String(x ?? "")
  .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;").replaceAll('"', "&quot;")
  .replaceAll("'", "&#39;");

export function unknownFailureVisibility() {
  return {
    source: "github_actions", status: "UNKNOWN",
    scope: "latest_8_workflow_runs", fetched_run_count: null,
    failed_run_count: null, pending_run_count: null,
    failures: [], cloudflare_runtime: "UNKNOWN",
    reason: "RUN_EVIDENCE_UNAVAILABLE",
  };
}

export function normalizeFailureVisibility(payload, fullName) {
  const runs = payload?.workflow_runs;
  if (!REPO.test(fullName || "") || !Array.isArray(runs) || runs.length > MAX_RUNS) {
    throw new Error("GITHUB_FAILURE_WINDOW_AMBIGUOUS");
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
  const failures = normalized.filter((x) => BAD.has(x.conclusion)).map((x) => ({
    ...x,
    boundary: /cloudflare|relay/i.test(x.name) ? "Relay / Cloudflare integration CI" : "GitHub Actions workflow",
    causal_state: "UNVERIFIED",
  }));
  const pending = normalized.filter((x) => IN_PROGRESS.has(x.status)).length;
  return {
    source: "github_actions",
    status: failures.length ? "FAILURES_OBSERVED" :
      pending ? "PENDING_RUNS" : "NO_FAILURES_IN_SAMPLE",
    scope: "latest_8_workflow_runs",
    fetched_run_count: normalized.length,
    failed_run_count: failures.length,
    pending_run_count: pending,
    failures,
    cloudflare_runtime: "UNKNOWN",
    reason: null,
  };
}

export function renderFailureVisibility(state) {
  const f = state || unknownFailureVisibility();
  const status = {
    FAILURES_OBSERVED: "Recent CI failures detected",
    PENDING_RUNS: "No reported failures; some runs are pending",
    NO_FAILURES_IN_SAMPLE: "No failures in sampled recent CI",
    UNKNOWN: "Failure evidence unavailable",
  }[f.status] || "Failure state UNKNOWN";
  const rows = f.failures.map((x) =>
    '<li><a href="' + escape(x.url) +
    '" target="_blank" rel="noopener noreferrer">' +
    escape(x.name) + " · GitHub run #" + escape(x.id) + "</a>" +
    " · " + escape(x.boundary) +
    " · " + escape(x.conclusion.toUpperCase()) +
    " · " + escape(x.observed_at || "time unknown") +
    " · <code>" + escape(x.sha.slice(0, 12)) +
    "</code></li>"
  ).join("");
  return '<section aria-label="Failure visibility"><h2>Failure visibility</h2>' +
    '<p><b>' + escape(status) + '</b></p>' +
    '<p class="muted">Source: GitHub Actions · Window: latest 8 workflow runs · No raw logs fetched.</p>' +
    (rows ? '<ul>' + rows + '</ul>' : "") +
    '<p class="muted">Cloudflare runtime: <b>UNKNOWN</b>. A failed GitHub relay integration check is not proof that Cloudflare is down. Inspect the linked run for job-level root cause. No failures in the sample does not establish system-wide health.</p>' +
    '</section>';
}
