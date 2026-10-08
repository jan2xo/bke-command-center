import { normalizeFailureVisibility } from "./failure-visibility.js";
import { redactSensitive } from "./core.js";

const BAD = new Set(["failure", "timed_out", "cancelled", "action_required"]);
const MAX_JOBS = 40;
const MAX_STEPS = 70;
const escape = (v) => String(v ?? "").replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;").replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
const label = (s) => redactSensitive(String(s ?? "")).slice(0, 220);
const status = (x) => x === "failure" || x === "timed_out" ? "FAILED"
  : x === "cancelled" ? "INTERRUPTED"
  : x === "action_required" ? "BLOCKED" : "UNKNOWN";
const isDownstreamGate = (name) => /required certification|aggregate|summary gate/i.test(name);
const priorityKey = (j) => Date.parse(j.completed_at || j.started_at || "") || Infinity;

export function selectRecentIncident(payload, repo, runId) {
  const observed = normalizeFailureVisibility(payload, repo);
  const found = observed.observations?.find(x => x.id === runId);
  if (!found || !BAD.has(found.conclusion)) return null;
  return found;
}

export function summarizeFailureJobs(run, payload, repo) {
  const jobs = payload?.jobs;
  if (!Array.isArray(jobs) || jobs.length >= MAX_JOBS ||
      (Number.isFinite(payload?.total_count) && payload.total_count > jobs.length)) {
    throw new Error("GITHUB_FAILURE_JOB_WINDOW_AMBIGUOUS");
  }
  const seen = new Set();
  const detail = jobs.map(j => {
    if (!j || !Number.isSafeInteger(j.id) || j.id <= 0 || seen.has(j.id) ||
        typeof j.name !== "string" || !j.name.trim() ||
        !["success", "failure", "timed_out", "cancelled", "action_required", "neutral", "skipped", null].includes(j.conclusion) ||
        !(Array.isArray(j.steps) || j.steps == null) ||
        (Array.isArray(j.steps) && j.steps.length > MAX_STEPS)) {
      throw new Error("GITHUB_FAILURE_JOB_INVALID");
    }
    seen.add(j.id);
    // Skipped/cancelled jobs often omit steps altogether.
    const firstFailed = (j.steps || []).find(s =>
      s && (s.conclusion === "failure" || s.conclusion === "timed_out"));
    return {
      id: j.id,
      name: label(j.name),
      conclusion: j.conclusion || "UNKNOWN",
      downstream_gate: isDownstreamGate(j.name),
      first_failed_step: firstFailed?.name ? label(firstFailed.name) : null,
      completed_at: typeof j.completed_at === "string" ? j.completed_at : null,
      url: "https://github.com/" + repo + "/actions/runs/" + run.id + "/job/" + j.id,
    };
  });
  const failed = detail.filter(j => j.conclusion === "failure" || j.conclusion === "timed_out");
  const independent = failed.filter(j => !j.downstream_gate);
  const candidates = independent.length ? independent : failed;
  // We can identify the first OBSERVED failed job, not assert a true
  // underlying external-service root cause without logs or telemetry.
  const first = [...candidates].sort((a,b) =>
    priorityKey(a) - priorityKey(b) || a.id - b.id)[0] || null;
  const diagnostic = jobs.length === 0 ? "NO_JOBS_REPORTED"
    : !first ? "NO_FAILED_JOB_REPORTED"
    : candidates.length > 1 ? "MULTIPLE_FAILED_JOBS_CAUSE_UNVERIFIED"
    : !first.first_failed_step ? "JOB_FAILED_STEP_UNAVAILABLE"
    : "FIRST_OBSERVED_FAILED_STEP";
  // A required gate is downstream only when an independent failed job is
  // actually observed. An isolated gate failure has UNKNOWN cause.
  const downstream = independent.length
    ? detail.filter(j => j.downstream_gate && j.conclusion === "failure")
    : [];
  const succeeded = detail.filter(j => j.conclusion === "success").slice(0, 8);
  return {
    source: "github_actions", run_id: run.id,
    workflow: label(run.name),
    run_conclusion: run.conclusion, classification: status(run.conclusion),
    observed_at: run.observed_at, head_sha: run.sha,
    run_url: run.url,
    detail_status: diagnostic,
    first_observed_failure: first,
    downstream_gate_failures: downstream,
    unaffected_successful_jobs: succeeded,
    failed_job_count: failed.length,
    reported_job_count: jobs.length,
    cloudflare_runtime: "UNKNOWN",
    claim_boundary: "GitHub Actions job and step evidence only; first observed failure is not a confirmed external-service root cause.",
  };
}

export function unavailableFailureJobs(run) {
  return {
    source:"github_actions", run_id:run.id, workflow:label(run.name),
    run_conclusion:run.conclusion, classification:status(run.conclusion),
    observed_at:run.observed_at, head_sha:run.sha, run_url:run.url,
    detail_status:"JOB_EVIDENCE_UNAVAILABLE", first_observed_failure:null,
    downstream_gate_failures:[], unaffected_successful_jobs:[],
    failed_job_count:null, reported_job_count:null, cloudflare_runtime:"UNKNOWN",
    claim_boundary:"GitHub Actions job evidence unavailable; do not infer external-service failure.",
  };
}

export async function failureDetailState(gh, runId) {
  if (!Number.isSafeInteger(runId) || runId <= 0) return null;
  const repository = await gh.repo();
  const sample = await gh.recentWorkflowRuns();
  const incident = selectRecentIncident(sample, repository.full_name, runId);
  if (!incident) return null;
  try {
    return summarizeFailureJobs(incident, await gh.workflowJobs(runId), repository.full_name);
  } catch {
    return unavailableFailureJobs(incident);
  }
}

export function renderFailureDetail(data) {
  const main = data.first_observed_failure;
  const jobLink = j => '<a href="' + escape(j.url) +
    '" rel="noopener noreferrer" target="_blank">' + escape(j.name) + '</a>';
  const details = main
    ? '<p><b>First observed failed job:</b> ' + jobLink(main) +
      '</p><p><b>First failing step:</b> ' + escape(main.first_failed_step || "UNKNOWN") + '</p>'
    : '<p>Failed job/step: UNKNOWN from available evidence.</p>';
  const list = (xs) => xs.length
    ? '<ul>' + xs.map(j => '<li>' + jobLink(j) +
      ' · ' + escape(j.conclusion) + '</li>').join("") + '</ul>'
    : '<p class="muted">None established in the bounded evidence.</p>';
  return '<h1>Failure diagnosis · GitHub run #' + escape(data.run_id) + '</h1>' +
    '<section><p><b>Workflow:</b> ' + escape(data.workflow) +
    ' · ' + escape(data.classification) + '</p><p><b>Evidence state:</b> ' +
    escape(data.detail_status) + '</p>' + details +
    '<p><a href="' + escape(data.run_url) +
    '" rel="noopener noreferrer" target="_blank">Open authoritative GitHub Actions run</a></p>' +
    '<p class="muted">Source SHA: <code>' + escape(data.head_sha) +
    '</code> · Observed: ' + escape(data.observed_at || "UNKNOWN") + '</p></section>' +
    '<section><h2>Downstream certification/gate failures</h2>' +
    list(data.downstream_gate_failures) +
    '<h2>Successful jobs (not proof of other services)</h2>' +
    list(data.unaffected_successful_jobs) + '</section>' +
    '<section><h2>Attribution boundary</h2><p>' +
    escape(data.claim_boundary) + '</p><p>Cloudflare runtime health: <b>UNKNOWN</b>. ' +
    'This page does not read production Cloudflare credentials or raw logs.</p>' +
    '<p><a href="/">Back to overview</a></p></section>';
}
