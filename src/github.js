import { GitHubEvidenceError, statusFailure } from "./github-evidence-error.js";
import { boundaryFromJobName, stageFromStep, extractFailureExcerpt, normalizeStatus } from "./core.js";
import { cloudflarePublicStatus } from "./cloudflare-status.js";

const API = "https://api.github.com";
const MAX_LOG_BYTES = 262144;
const CERTIFY_RUN_WINDOW_MS = 120000;

function headers(env) {
  const value = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "bke-command-center-preproduction",
  };
  if (env.GITHUB_TOKEN) value.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  return value;
}

async function github(path, env, boundary = "UNKNOWN") {
  let response;
  try {
    response = await fetch(`${API}${path}`, { headers: headers(env) });
  } catch {
    throw new GitHubEvidenceError("TRANSPORT", boundary);
  }
  if (!response.ok) {
    throw statusFailure(
      response.status,
      response.headers?.get("x-ratelimit-remaining"),
      boundary,
    );
  }
  try {
    return await response.json();
  } catch {
    throw new GitHubEvidenceError("INVALID_RESPONSE", boundary);
  }
}

async function readBoundedText(response, maxBytes = MAX_LOG_BYTES) {
  if (!response.body) {
    const text = await response.text();
    return { text: text.slice(0, maxBytes), truncated: text.length > maxBytes };
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    const room = maxBytes - total;
    if (room <= 0) {
      truncated = true;
      await reader.cancel();
      break;
    }
    const chunk = value.slice(0, room);
    chunks.push(chunk);
    total += chunk.length;
    if (value.length > room || total >= maxBytes) {
      truncated = true;
      await reader.cancel();
      break;
    }
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return { text: new TextDecoder().decode(merged), truncated };
}

export function createGitHubAdapter(env) {
  const owner = env.GITHUB_OWNER || "jan2xo";
  const repo = env.GITHUB_REPO || "bke-worker";
  return {
    async repo() { return github(`/repos/${owner}/${repo}`, env, "REPOSITORY"); },
    async rateLimit() { return github("/rate_limit", env, "RATE_LIMIT_PROBE"); },
    async pullRequest(number) { return github(`/repos/${owner}/${repo}/pulls/${number}`, env, "PR_DETAIL"); },
    async openPullRequests() { return github(`/repos/${owner}/${repo}/pulls?state=open&per_page=100`, env, "OPEN_PRS"); },
    async recentClosedPullRequests() { return github(`/repos/${owner}/${repo}/pulls?state=closed&sort=updated&direction=desc&per_page=12`, env, "CLOSED_PRS"); },
    async recentWorkflowRuns() { return github(`/repos/${owner}/${repo}/actions/runs?per_page=30`, env, "RECENT_WORKFLOWS"); },
    async cloudflarePlatformStatus() { return cloudflarePublicStatus(); },
    async pullCommits(number) { return github(`/repos/${owner}/${repo}/pulls/${number}/commits?per_page=100`, env, "PR_COMMITS"); },
    async checks(ref) { return github(`/repos/${owner}/${repo}/commits/${ref}/check-runs?per_page=100`, env, "COMMIT_CHECKS"); },
    async workflowRuns(event = null) { return github(`/repos/${owner}/${repo}/actions/runs?per_page=100${event ? `&event=${encodeURIComponent(event)}` : ""}`, env, "WORKFLOW_RUNS"); },
    async workflowJobs(runId) { return github(`/repos/${owner}/${repo}/actions/runs/${runId}/jobs?per_page=100`, env, "WORKFLOW_JOBS"); },
    async issueComments(number) { return github(`/repos/${owner}/${repo}/issues/${number}/comments?per_page=100`, env, "PR_COMMENTS"); },
    async jobFailureExcerpt(jobId) {
      const first = await fetch(`${API}/repos/${owner}/${repo}/actions/jobs/${jobId}/logs`, {
        headers: headers(env),
        redirect: "manual",
      });
      let response = first;
      if ([301, 302, 303, 307, 308].includes(first.status)) {
        const location = first.headers.get("location");
        if (!location) throw new Error("GitHub job log redirect missing location");
        response = await fetch(location, { headers: { Range: `bytes=0-${MAX_LOG_BYTES - 1}` } });
      }
      if (!response.ok) throw new Error(`GitHub job log ${response.status}`);
      const { text, truncated } = await readBoundedText(response);
      return { ...extractFailureExcerpt(text), truncated };
    },
  };
}

export function assignmentFromPullRequest(pr) {
  const labels = (pr.labels || []).map((x) => x.name).filter((name) => name.startsWith("bke-worker:"));
  if (labels.length > 1) {
    return {
      worker_id: null,
      assignment_state: "CONFLICT",
      pr_state: String(pr.state || "UNKNOWN").toUpperCase(),
      pr_number: pr.number,
      exact_head: pr.head?.sha || null,
      branch: pr.head?.ref || null,
    };
  }
  return {
    worker_id: labels.length === 1 ? labels[0].slice("bke-worker:".length) : null,
    assignment_state: labels.length === 1 ? "ASSIGNED" : "UNASSIGNED",
    pr_state: String(pr.state || "UNKNOWN").toUpperCase(),
    pr_number: pr.number,
    exact_head: pr.head?.sha || null,
    branch: pr.head?.ref || null,
  };
}

function timestamp(value) {
  const n = Date.parse(value || "");
  return Number.isFinite(n) ? n : null;
}

function commentAuthor(comment) {
  return comment.user?.login || comment.author?.login || null;
}

function latestHeadBeforeComment(comments, commits, certifyComment) {
  const cutoff = timestamp(certifyComment.created_at);
  if (cutoff === null) return null;
  const commitHeads = new Set((commits || []).map((c) => c.sha).filter(Boolean));
  const ledgerCandidates = (comments || [])
    .filter((comment) => timestamp(comment.created_at) !== null && timestamp(comment.created_at) <= cutoff)
    .map((comment) => {
      const matches = [...String(comment.body || "").matchAll(/(?:exact_head=|head=|\`)([0-9a-f]{40})(?:\`|\b)/gi)];
      const candidate = matches.map((m) => m[1]).reverse().find((sha) => commitHeads.has(sha));
      return candidate ? { sha: candidate, at: timestamp(comment.created_at) } : null;
    })
    .filter(Boolean)
    .sort((a, b) => b.at - a.at);
  if (ledgerCandidates.length) return ledgerCandidates[0].sha;

  const commitCandidates = (commits || [])
    .map((commit) => ({
      sha: commit.sha,
      at: timestamp(commit.commit?.committer?.date || commit.commit?.author?.date),
    }))
    .filter((x) => x.sha && x.at !== null && x.at <= cutoff)
    .sort((a, b) => b.at - a.at);
  return commitCandidates[0]?.sha || null;
}

export function correlateCertificationRuns({ pr, comments = [], commits = [], runs = [], exactHead }) {
  const commands = comments.filter((comment) => /^\s*\/certify\b/i.test(String(comment.body || "")));
  const correlated = [];
  const used = new Set();
  for (const comment of commands) {
    const sourceSha = latestHeadBeforeComment(comments, commits, comment);
    if (sourceSha !== exactHead) continue;
    const commentAt = timestamp(comment.created_at);
    const actor = commentAuthor(comment);
    const candidate = runs
      .filter((run) => !used.has(run.id))
      .filter((run) => run.event === "issue_comment")
      .filter((run) => !pr.title || run.display_title === pr.title)
      .filter((run) => !actor || run.actor?.login === actor)
      .map((run) => ({ run, delta: timestamp(run.created_at) - commentAt }))
      .filter((x) => Number.isFinite(x.delta) && x.delta >= 0 && x.delta <= CERTIFY_RUN_WINDOW_MS)
      .sort((a, b) => a.delta - b.delta)[0]?.run;
    if (!candidate) continue;
    used.add(candidate.id);
    correlated.push({ ...candidate, source_sha: sourceSha, command_comment_url: comment.html_url || comment.url || null });
  }
  return correlated.sort((a, b) => (timestamp(a.created_at) || 0) - (timestamp(b.created_at) || 0));
}

export function evidenceFromJob(job, run, sourceSha, prNumber) {
  const failedStep = (job.steps || []).find((step) => normalizeStatus(step.conclusion || step.status) === "failure") || null;
  const boundary = boundaryFromJobName(job.name || run.name);
  const stage = stageFromStep(failedStep?.name, job.name);
  const requiredGate = /required certification/i.test(String(job.name || ""));
  return {
    status: job.conclusion || job.status,
    conclusion: job.conclusion,
    source_sha: sourceSha,
    occurred_at: failedStep?.completed_at || job.completed_at || failedStep?.started_at || job.started_at || run.updated_at || run.created_at,
    host: "github_actions",
    boundary,
    stage,
    summary: failedStep ? `${boundary}: ${failedStep.name}` : `${boundary}: ${job.conclusion || job.status}`,
    evidence_run_ids: [String(run.id)],
    evidence: [{
      type: "job",
      id: String(job.id),
      url: job.html_url || run.html_url,
      failure_excerpt_url: job.conclusion === "failure" ? `/api/pr/${prNumber}/evidence/job/${job.id}` : null,
    }],
    run_id: run.id,
    job_id: job.id,
    run_url: run.html_url,
    job_url: job.html_url,
    failed_step: failedStep?.name || null,
    causal: !requiredGate,
    required_certification: requiredGate,
  };
}

function runRequiredFallback(run) {
  const status = normalizeStatus(run.conclusion || run.status);
  if (["queued", "in_progress", "waiting", "requested", "pending"].includes(status)) {
    return {
      source_sha: run.source_sha,
      status: run.status || "in_progress",
      conclusion: run.conclusion,
      boundary: "certification",
      stage: "workflow",
      summary: "Intent Certification: in progress",
      required_certification: true,
      causal: false,
      occurred_at: run.updated_at || run.created_at,
      evidence_run_ids: [String(run.id)],
      evidence: [{ type: "run", id: String(run.id), url: run.html_url }],
    };
  }
  if (["failure", "cancelled", "timed_out", "action_required"].includes(status)) {
    return {
      source_sha: run.source_sha,
      status: run.status,
      conclusion: run.conclusion,
      boundary: "certification",
      stage: "workflow",
      summary: `Intent Certification: ${run.conclusion || run.status}`,
      required_certification: true,
      causal: false,
      occurred_at: run.updated_at || run.created_at,
      evidence_run_ids: [String(run.id)],
      evidence: [{ type: "run", id: String(run.id), url: run.html_url }],
    };
  }
  return null;
}

export async function collectEvidence(gh, pr, exactHead) {
  const [checkData, comments, commits, issueCommentRunData] = await Promise.all([
    gh.checks(exactHead),
    gh.issueComments(pr.number),
    gh.pullCommits(pr.number),
    gh.workflowRuns("issue_comment"),
  ]);
  const checks = checkData.check_runs || [];
  const correlatedRuns = correlateCertificationRuns({
    pr,
    comments,
    commits,
    runs: issueCommentRunData.workflow_runs || [],
    exactHead,
  });
  const run = correlatedRuns.at(-1) || null;
  let jobs = [];
  if (run) {
    try {
      const data = await gh.workflowJobs(run.id);
      jobs = (data.jobs || []).map((job) => evidenceFromJob(job, run, run.source_sha, pr.number));
    } catch {
      jobs = [];
    }
  }
  let required = jobs.filter((job) => job.required_certification);
  if (!required.length && run) {
    const fallback = runRequiredFallback(run);
    if (fallback) required = [fallback];
  }
  return {
    checks,
    certificationRuns: run ? [run] : [],
    jobs,
    required,
    all: [...checks, ...jobs],
  };
}
