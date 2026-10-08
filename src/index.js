import { createGitHubAdapter, assignmentFromPullRequest, collectEvidence } from "./github.js";
import { SYSTEM_REGISTRY, certificationSummary, buildFailureCapsule, buildPostRunSummary } from "./core.js";

const esc = (v) => String(v ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
const link = (url, label) => url ? `<a href="${esc(url)}" target="_blank" rel="noreferrer">${esc(label)}</a>` : esc(label);
const html = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · BKE Command Center</title><style>body{font:15px system-ui,sans-serif;margin:0;background:#f6f7f9;color:#17181a}main{max-width:1100px;margin:auto;padding:28px}nav a{margin-right:16px}section{background:#fff;border:1px solid #ddd;border-radius:10px;padding:18px;margin:18px 0}li{margin:6px 0}.pill{display:inline-block;border:1px solid #ccc;border-radius:999px;padding:3px 9px}.muted{color:#667085}code,pre{background:#f0f1f3;padding:2px 5px;border-radius:4px}pre{padding:12px;overflow:auto}</style></head><body><main><nav><a href="/">Overview</a><a href="/worker">Worker</a></nav>${body}</main></body></html>`;
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
        return Response.json({ error: "invalid evidence address" }, { status: 400 });
      }
      const state = await prState(env, prNumber, gh);
      if (!failureJobIds(state).has(jobId)) return Response.json({ error: "job is not failure evidence for this exact PR state" }, { status: 404 });
      return Response.json(await gh.jobFailureExcerpt(jobId));
    }
    if (url.pathname === "/api/worker") return Response.json(await workerState(env, gh));
    if (/^\/api\/pr\/\d+$/.test(url.pathname)) return Response.json(await prState(env, Number(url.pathname.split("/").pop()), gh));
    if (url.pathname === "/worker") {
      const state = await workerState(env, gh);
      return new Response(html("Worker", `<h1>worker</h1><section><p>Repository: <code>${esc(state.repository.full_name)}</code></p><p><b>Worker state:</b> ${esc(state.worker_state)}</p>${list(state.assignments, (x) => `<li>PR ${esc(x.pr_number)} · ${esc(x.worker_id || "UNKNOWN")} · ${esc(x.assignment_state)} · <a href="/pr/${esc(x.pr_number)}">open</a></li>`)}</section>`), { headers: { "content-type": "text/html;charset=utf-8" } });
    }
    if (/^\/pr\/\d+$/.test(url.pathname)) {
      const state = await prState(env, Number(url.pathname.split("/").pop()), gh);
      return new Response(html("PR", renderPr(state)), { headers: { "content-type": "text/html;charset=utf-8" } });
    }
    return new Response(html("Overview", "<h1>BKE Command Center</h1><section><p>Read-first, preproduction observability for BKE engineering.</p><p><a href='/worker'>worker</a></p></section>"), { headers: { "content-type": "text/html;charset=utf-8" } });
  } catch (error) {
    return Response.json({ error: error.message, state: "UNKNOWN" }, { status: 502 });
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
