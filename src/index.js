import { createGitHubAdapter, assignmentFromPullRequest } from "./github.js";
import { SYSTEM_REGISTRY, certificationSummary, buildFailureCapsule, buildPostRunSummary } from "./core.js";

const html = (title, body) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · BKE Command Center</title><style>
body{font:15px system-ui,sans-serif;margin:0;background:#f6f7f9;color:#17181a}main{max-width:1000px;margin:0 auto;padding:28px}
nav a{margin-right:16px}section{background:#fff;border:1px solid #ddd;border-radius:10px;padding:18px;margin:18px 0}
code,pre{background:#f0f1f3;padding:2px 5px;border-radius:4px}pre{padding:12px;overflow:auto}
</style></head><body><main><nav><a href="/">Overview</a><a href="/worker">Worker</a></nav>${body}</main></body></html>`;

async function workerState(env) {
  const gh = createGitHubAdapter(env);
  const repository = await gh.repo();
  const prs = await Promise.all((await fetch(`https://api.github.com/repos/${env.GITHUB_OWNER || "jan2xo"}/${env.GITHUB_REPO || "bke-worker"}/pulls?state=open&per_page=100`, {headers:{Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"bke-command-center-preproduction",...(env.GITHUB_TOKEN?{Authorization:`Bearer ${env.GITHUB_TOKEN}`}:{})}})).json().then(list => list.filter(pr => (pr.labels||[]).some(l => l.name === "bke-worker:android-worker-a")).map(pr => gh.pullRequest(pr.number))));
  return {
    system: SYSTEM_REGISTRY.worker,
    repository: { full_name: repository.full_name, default_branch: repository.default_branch },
    assignments: prs.map(assignmentFromPullRequest),
  };
}

async function prState(env, number) {
  const gh = createGitHubAdapter(env);
  const pr = await gh.pullRequest(number);
  const exactHead = pr.head?.sha || null;
  const checks = exactHead ? (await gh.checks(exactHead)).check_runs || [] : [];
  const runs = (await gh.workflowRuns()).workflow_runs || [];
  const workflowEvidence = runs.filter(r => r.head_sha === exactHead);
  const certification = certificationSummary({exactHead, checks, workflowRuns: workflowEvidence});
  const assignment = assignmentFromPullRequest(pr);
  const evidence = workflowEvidence.filter(r => ["failure","cancelled","timed_out","action_required"].includes(String(r.conclusion||"").toLowerCase())).map(r => ({
    occurred_at:r.updated_at||r.created_at, host:"github_actions", boundary:"github_actions", stage:"workflow",
    conclusion:r.conclusion, summary:r.name + " " + (r.conclusion||"failed"), evidence_run_ids:[String(r.id)],
    next_action:"Inspect the earliest failing job for this exact head."
  }));
  const first_causal_failure = buildFailureCapsule({repo:pr.base?.repo?.full_name || "jan2xo/bke-worker",pr_number:number,exact_head:exactHead,worker_id:assignment.worker_id,evidence});
  return {pr:{number:pr.number,title:pr.title,state:pr.state,draft:pr.draft,html_url:pr.html_url},assignment,certification,first_causal_failure,post_run_summary:buildPostRunSummary({certification,first_causal_failure})};
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/worker") return Response.json(await workerState(env));
      if (url.pathname.startsWith("/api/pr/")) return Response.json(await prState(env, Number(url.pathname.split("/").pop())));
      if (url.pathname === "/worker") return new Response(html("Worker", "<h1>worker</h1><section><p>Live state is derived from GitHub.</p><p><a href='/api/worker'>Open worker JSON</a></p></section>"), {headers:{"content-type":"text/html;charset=utf-8"}});
      if (url.pathname.startsWith("/pr/")) return new Response(html("PR", `<h1>PR ${url.pathname.split("/").pop()}</h1><section><a href="/api/pr/${url.pathname.split("/").pop()}">Open live JSON</a></section>`), {headers:{"content-type":"text/html;charset=utf-8"}});
      return new Response(html("Overview", "<h1>BKE Command Center</h1><section><p>Read-first, preproduction observability for BKE engineering.</p><p><a href='/worker'>worker</a></p></section>"), {headers:{"content-type":"text/html;charset=utf-8"}});
    } catch (error) {
      return Response.json({error:error.message, state:"UNKNOWN"}, {status:502});
    }
  }
};
