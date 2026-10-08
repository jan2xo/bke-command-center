import {createGitHubAdapter,assignmentFromPullRequest,collectEvidence} from "./github.js";
import {SYSTEM_REGISTRY,certificationSummary,buildFailureCapsule,buildPostRunSummary,evidenceMatchesHead} from "./core.js";

const esc=v=>String(v??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;");
const link=(url,label)=>url?`<a href="${esc(url)}" target="_blank" rel="noreferrer">${esc(label)}</a>`:esc(label);
const html=(title,body)=>`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · BKE Command Center</title><style>body{font:15px system-ui,sans-serif;margin:0;background:#f6f7f9;color:#17181a}main{max-width:1100px;margin:auto;padding:28px}nav a{margin-right:16px}section{background:#fff;border:1px solid #ddd;border-radius:10px;padding:18px;margin:18px 0}li{margin:6px 0}.pill{display:inline-block;border:1px solid #ccc;border-radius:999px;padding:3px 9px}.muted{color:#667085}code{background:#f0f1f3;padding:2px 5px}</style></head><body><main><nav><a href="/">Overview</a><a href="/worker">Worker</a></nav>${body}</main></body></html>`;
const list=(items,render)=>items?.length?`<ul>${items.map(render).join("")}</ul>`:"<p class='muted'>None.</p>";

export async function workerState(env){
  const gh=createGitHubAdapter(env),repository=await gh.repo(),open=await gh.openPullRequests();
  const assignments=open.map(assignmentFromPullRequest).filter(x=>x.worker_id==="android-worker-a" || x.state==="UNKNOWN");
  return {system:SYSTEM_REGISTRY.worker,repository:{full_name:repository.full_name,default_branch:repository.default_branch},assignments};
}

export async function prState(env,number){
  const gh=createGitHubAdapter(env),pr=await gh.pullRequest(number),exactHead=pr.head?.sha||null,evidence=await collectEvidence(gh,pr,exactHead);
  const proof=evidence.comments.filter(x=>x.status==="success"||x.status==="failure");
  const requiredProof=[...evidence.jobs.filter(x=>x.required),...proof.filter(x=>x.required)];
  const certification=certificationSummary({exactHead,checks:evidence.checks,workflowRuns:evidence.workflowRuns,proof,requiredProof});
  const assignment=assignmentFromPullRequest(pr);
  const matching=evidence.jobs.filter(x=>evidenceMatchesHead(x,exactHead));
  const failures=matching.filter(x=>["failure","cancelled","timed_out","action_required"].includes(String(x.conclusion||x.status).toLowerCase()));
  const observed=matching.filter(x=>["success","passed","neutral"].includes(String(x.conclusion||x.status).toLowerCase()));
  const first_causal_failure=buildFailureCapsule({repo:pr.base?.repo?.full_name||"jan2xo/bke-worker",pr_number:number,exact_head:exactHead,worker_id:assignment.worker_id,evidence:[...failures,...observed]});
  return {pr:{number:pr.number,title:pr.title,state:pr.state,draft:pr.draft,html_url:pr.html_url},assignment,certification,first_causal_failure,observed_boundaries:[...new Set(observed.map(x=>x.boundary).filter(Boolean))],post_run_summary:buildPostRunSummary({certification,first_causal_failure})};
}

export function renderPr(state){
  const f=state.first_causal_failure;
  return `<h1>PR ${esc(state.pr.number)} — ${esc(state.pr.title)}</h1><section><p><b>Exact head:</b> <code>${esc(state.assignment.exact_head)}</code></p><p><b>Worker:</b> ${esc(state.assignment.worker_id||"UNKNOWN")} · <b>Assignment:</b> ${esc(state.assignment.state)}</p><p><b>Certification:</b> <span class="pill">${esc(state.certification.state)}</span> · required proof ${esc(state.certification.required_seen)}</p><p>${esc(state.post_run_summary)}</p></section><section><h2>First causal failure</h2>${f.boundary?`<p><b>${esc(f.classification)}</b> · ${esc(f.boundary)} · ${esc(f.stage)}</p><p>${esc(f.summary)}</p>`:"<p class='muted'>No causal failure established.</p>"}<h3>Downstream</h3>${list(f.downstream,x=>`<li><b>${esc(x.classification)}</b> · ${esc(x.boundary||"unknown")} — ${esc(x.summary)}</li>`)}<h3>Unaffected / observed positive</h3>${list(f.unaffected_boundaries,x=>`<li>${esc(x)}</li>`)}</section><section><h2>Evidence</h2>${list(f.evidence,x=>`<li>${link(x.url,x.id||"evidence")}</li>`)}<p class='muted'>Raw logs remain at GitHub and are fetched on demand; they are not mirrored here.</p></section>`;
}

export default {async fetch(request,env){
  const url=new URL(request.url);
  try{
    if(url.pathname==="/api/worker") return Response.json(await workerState(env));
    if(url.pathname.startsWith("/api/pr/")) return Response.json(await prState(env,Number(url.pathname.split("/").pop())));
    if(url.pathname==="/worker"){const s=await workerState(env);return new Response(html("Worker",`<h1>worker</h1><section><p>Repository: <code>${esc(s.repository.full_name)}</code></p>${list(s.assignments,x=>`<li>PR ${esc(x.pr_number)} · ${esc(x.worker_id||"UNKNOWN")} · ${esc(x.state)} · <a href="/pr/${esc(x.pr_number)}">open</a></li>`)}</section>`),{headers:{"content-type":"text/html;charset=utf-8"}});}
    if(url.pathname.startsWith("/pr/")){const s=await prState(env,Number(url.pathname.split("/").pop()));return new Response(html("PR",renderPr(s)),{headers:{"content-type":"text/html;charset=utf-8"}});}
    return new Response(html("Overview","<h1>BKE Command Center</h1><section><p>Read-first, preproduction observability for BKE engineering.</p><p><a href='/worker'>worker</a></p></section>"),{headers:{"content-type":"text/html;charset=utf-8"}});
  }catch(error){return Response.json({error:error.message,state:"UNKNOWN"},{status:502});}
}};
