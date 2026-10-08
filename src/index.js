import { createGitHubAdapter, assignmentFromPullRequest, collectEvidence } from "./github.js";
import { SYSTEM_REGISTRY, certificationSummary, buildFailureCapsule, buildPostRunSummary } from "./core.js";
import { dashboardState, renderDashboard } from "./dashboard.js";

const esc = (v) => String(v ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
const link = (url, label) => url ? `<a href="${esc(url)}" target="_blank" rel="noreferrer">${esc(label)}</a>` : esc(label);
const shellCss = [
  "<style>",
  "body{font:15px system-ui,-apple-system,sans-serif;margin:0;background:#0c1424;color:#eff5ff}",
  "main{max-width:1200px;margin:auto;padding:22px 24px 48px}",
  "nav{max-width:1200px;margin:auto;display:flex;gap:22px;padding:22px 24px;border-bottom:1px solid #293750}",
  "nav a{font-weight:700;color:#c6d6f0;text-decoration:none}",
  "nav a:hover,a:hover{color:#fff}",
  "a{color:#a8c4ff}",
  "section{background:#142033;border:1px solid #2a3b55;border-radius:16px;padding:22px;margin:18px 0;min-width:0}",
  "li{margin:7px 0}.pill{display:inline-block;border:1px solid #50627d;border-radius:999px;padding:4px 10px}",
  ".muted{color:#adbdd1}code,pre{background:#233249;padding:3px 5px;border-radius:4px;overflow-wrap:anywhere}",
  "pre{padding:12px;overflow:auto}h1,h2,h3{line-height:1.25}",
  "@media(max-width:600px){main{padding:16px 14px 30px}nav{padding:16px 14px}section{padding:16px}}",
  "</style>",
].join("");
const html = (title, body) => '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1"><title>' +
  esc(title) + ' · BKE Command Center</title>' + shellCss +
  '</head><body><nav><a href="/">BKE Command Center</a><a href="/">Overview</a>' +
  '<a href="/worker">Worker</a></nav><main>' + body + '</main></body></html>';
const noStoreHeaders = { "content-type": "text/html;charset=utf-8", "Cache-Control": "no-store" };
const noStoreJson = (value, status = 200) => Response.json(value, {
  status, headers: { "Cache-Control": "no-store" },
});
const page = (title, body) => new Response(html(title, body), { headers: noStoreHeaders });
const list = (items, render) => items?.length ? `<ul>${items.map(render).join("")}</ul>` : "<p class='muted'>None.</p>";

export async function workerState(env, gh = createGitHubAdapter(env)) {
  const repository = await gh.repo();
  const open = await gh.openPullRequests();
  const workerId = SYSTEM_REGISTRY.worker.worker_id;
  const assignments = open
    .map(assignmentFromPullRequest)
    .filter((assignment) => assignment.worker_id === workerId || assignment.assignment_state === "CONFLICT");
  const conflict = assignments.some((x) => x.assignment_state === "CONFLICT") || assignments.filter((x) => x.worker_id === workerId).length > 1;
  return {
    system: SYSTEM_REGISTRY.worker,
    repository: { full_name: repository.full_name, default_branch: repository.default_branch },
    worker_state: conflict ? "CONFLICT" : assignments.length ? "BUSY" : "IDLE",
    assignments,
  };
}

export async function prState(env, number, gh = createGitHubAdapter(env)) {
  const pr = await gh.pullRequest(number);
  const exactHead = pr.head?.sha || null;
  const evidence = await collectEvidence(gh, pr, exactHead);
  const certification = certificationSummary({
    exactHead,
    requiredEvidence: evidence.required,
    observedChecks: evidence.checks,
  });
  const assignment = assignmentFromPullRequest(pr);
  const first_causal_failure = buildFailureCapsule({
    repo: pr.base?.repo?.full_name || SYSTEM_REGISTRY.worker.repo,
    pr_number: number,
    exact_head: exactHead,
    worker_id: assignment.worker_id,
    evidence: evidence.jobs,
  });
  const state = {
    pr: { number: pr.number, title: pr.title, state: pr.state, draft: pr.draft, html_url: pr.html_url },
    assignment,
    certification,
    first_causal_failure,
  };
  return { ...state, post_run_summary: buildPostRunSummary(state) };
}

export function renderPr(state) {
  const f = state.first_causal_failure;
  const assignment = state.assignment;
  return `<h1>PR ${esc(state.pr.number)} — ${esc(state.pr.title)}</h1>
<section><p><b>Exact head:</b> <code>${esc(assignment.exact_head)}</code></p><p><b>Worker:</b> ${esc(assignment.worker_id || "UNKNOWN")} · <b>Assignment:</b> ${esc(assignment.assignment_state)}</p><p><b>PR:</b> ${esc(assignment.pr_state)} · <b>Certification:</b> <span class="pill">${esc(state.certification.state)}</span></p><p class="muted">${esc(state.certification.reason || "required certification evidence resolved")}</p><p>${esc(state.post_run_summary)}</p></section>
<section><h2>First causal failure</h2>${f.boundary ? `<p><b>${esc(f.classification)}</b> · ${esc(f.boundary)} · ${esc(f.stage)}</p><p>${esc(f.summary)}</p>` : "<p class='muted'>No causal failure established.</p>"}<h3>Downstream</h3>${list(f.downstream, (x) => `<li><b>${esc(x.classification)}</b> · ${esc(x.boundary || "unknown")} — ${esc(x.summary)}</li>`)}<h3>Unaffected / positive observed boundaries</h3>${list(f.unaffected_boundaries, (x) => `<li>${esc(x)}</li>`)}</section>
<section><h2>Evidence</h2>${list(f.evidence, (x) => `<li>${link(x.url, `GitHub job ${x.id || "evidence"}`)}${x.failure_excerpt_url ? ` · <a href="${esc(x.failure_excerpt_url)}">failure excerpt</a>` : ""}</li>`)}</section>`;
}

function failureJobIds(state) {
  const ids = new Set();
  for (const item of [state.first_causal_failure, ...(state.first_causal_failure?.downstream || [])]) {
    for (const evidence of item?.evidence || []) {
      if (evidence.type === "job" && /^\d+$/.test(String(evidence.id || ""))) ids.add(Number(evidence.id));
    }
  }
  return ids;
}

export async function handleRequest(request, env, createAdapter = createGitHubAdapter) {
  const url = new URL(request.url);
  const gh = createAdapter(env);
  try {
    const evidenceMatch = url.pathname.match(/^\/api\/pr\/(\d+)\/evidence\/job\/(\d+)$/);
    if (evidenceMatch) {
      const prNumber = Number(evidenceMatch[1]);
      const jobId = Number(evidenceMatch[2]);
      if (!Number.isSafeInteger(prNumber) || prNumber <= 0 || !Number.isSafeInteger(jobId) || jobId <= 0) {
        return noStoreJson({ error: "invalid evidence address" }, 400);
      }
      const state = await prState(env, prNumber, gh);
      if (!failureJobIds(state).has(jobId)) return noStoreJson({ error: "job is not failure evidence for this exact PR state" }, 404);
      return noStoreJson(await gh.jobFailureExcerpt(jobId));
    }
    if (url.pathname === "/api/overview") return noStoreJson(await dashboardState(gh));
    if (url.pathname === "/api/worker") return noStoreJson(await workerState(env, gh));
    if (/^\/api\/pr\/\d+$/.test(url.pathname)) return noStoreJson(await prState(env, Number(url.pathname.split("/").pop()), gh));
    if (url.pathname === "/worker") {
      const state = await workerState(env, gh);
      return page("Worker", `<h1>Worker assignment</h1><section><p>Repository: <code>${esc(state.repository.full_name)}</code></p><p><b>GitHub ownership:</b> ${esc(state.worker_state)}</p><p class="muted">This is PR label ownership, not proof of a running worker process. Runtime liveness: UNKNOWN.</p>${list(state.assignments, (x) => `<li>PR ${esc(x.pr_number)} · ${esc(x.worker_id || "UNKNOWN")} · ${esc(x.assignment_state)} · <a href="/pr/${esc(x.pr_number)}">detail</a></li>`)}</section>`);
    }
    if (/^\/pr\/\d+$/.test(url.pathname)) {
      const state = await prState(env, Number(url.pathname.split("/").pop()), gh);
      return page("PR", renderPr(state));
    }
    if (url.pathname === "/") return page("Overview", renderDashboard(await dashboardState(gh)));
    return noStoreJson({ error: "ROUTE_NOT_FOUND" }, 404);
  } catch {
    // Upstream error text can contain private GitHub information; do not
    // reflect it into a public response when the protected ingress is absent.
    return noStoreJson({ error: "GITHUB_EVIDENCE_UNAVAILABLE", state: "UNKNOWN" }, 502);
  }
}

// The named PREPRODUCTION deployment sets this flag. Any accidental default
// deployment or incomplete environment configuration must not serve GitHub
// observability, including on-demand job failure evidence.
export function preproductionFetch(request, env) {
  if (env?.BKE_PREPRODUCTION !== "true") {
    return Response.json(
      { error: "COMMAND_CENTER_PREPRODUCTION_ONLY", state: "LOCKED" },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
  return handleRequest(request, env);
}

export default { fetch: preproductionFetch };
