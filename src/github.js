const API="https://api.github.com";

async function github(path,env){
  const headers={Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"bke-command-center-preproduction"};
  if(env.GITHUB_TOKEN) headers.Authorization=`Bearer ${env.GITHUB_TOKEN}`;
  const response=await fetch(`${API}${path}`,{headers});
  const body=await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(`GitHub ${response.status}: ${body.message||"request failed"}`);
  return body;
}

export function createGitHubAdapter(env){
  const owner=env.GITHUB_OWNER||"jan2xo",repo=env.GITHUB_REPO||"bke-worker";
  return {
    async repo(){return github(`/repos/${owner}/${repo}`,env);},
    async pullRequest(number){return github(`/repos/${owner}/${repo}/pulls/${number}`,env);},
    async openPullRequests(){return github(`/repos/${owner}/${repo}/pulls?state=open&per_page=100`,env);},
    async checks(ref){return github(`/repos/${owner}/${repo}/commits/${ref}/check-runs?per_page=100`,env);},
    async workflowRuns(){return github(`/repos/${owner}/${repo}/actions/runs?per_page=100`,env);},
    async workflowJobs(runId){return github(`/repos/${owner}/${repo}/actions/runs/${runId}/jobs?per_page=100`,env);},
    async workflowJobLogs(jobId){return github(`/repos/${owner}/${repo}/actions/jobs/${jobId}/logs`,env);},
    async issueComments(number){return github(`/repos/${owner}/${repo}/issues/${number}/comments?per_page=100`,env);}
  };
}

export function assignmentFromPullRequest(pr){
  const workers=[...(pr.labels||[])].map(x=>x.name).filter(name=>name.startsWith("bke-worker:"));
  const worker=workers.length===1?workers[0].slice("bke-worker:".length):null;
  const state=pr.state!=="open"?"CLOSED":workers.length===1?"ASSIGNED":"UNKNOWN";
  return {worker_id:worker,state,pr_number:pr.number,exact_head:pr.head?.sha||null,branch:pr.head?.ref||null};
}

export function resolveSourceShaFromLog(content){
  const match=String(content||"").match(/(?:SOURCE_SHA|PR_HEAD_SHA|EXACT_HEAD)\s*[:=]\s*([0-9a-f]{40})/i);
  return match?.[1]||null;
}

export function firstFailedStep(job){
  return (job.steps||[]).find(s=>normalize(s.conclusion||s.status)==="failure")?.name||null;
}
function normalize(value){return String(value||"").toLowerCase().replaceAll(" ","_");}

export function evidenceFromJob(job,run,resolvedSha=null){
  const failedStep=firstFailedStep(job);
  const source=resolvedSha||run.head_sha||null;
  const required=/required certification/i.test(job.name||"");
  const causal=/cloudflare durable relay|relay/i.test(job.name||"") && !!failedStep;
  return {
    status:job.conclusion||job.status,conclusion:job.conclusion,source_sha:source,required,
    occurred_at:job.completed_at||job.started_at||run.updated_at||run.created_at,
    host:"github_actions",boundary:job.name||run.name||"github_actions",
    stage:/test|verify/i.test(failedStep||"")?"test":/build/i.test(failedStep||"")?"build":"workflow",
    summary:job.conclusion==="failure"?`${job.name}: ${failedStep||"failed"}`:`${job.name}: ${job.conclusion||job.status}`,
    evidence_run_ids:[String(run.id)],evidence:[{type:"job",id:String(job.id),url:job.html_url||run.html_url}],
    url:job.html_url||run.html_url,causal
  };
}

export function commentEvidence(comments,exactHead){
  return comments.filter(c=>c.body?.includes(exactHead)).map(c=>({
    source_sha:exactHead,
    status:/FAIL|FAILED|failure/i.test(c.body)?"failure":/PASS|PASSED|success/i.test(c.body)?"success":"neutral",
    required:/CERTIFIED|REQUIRED CERTIFICATION/i.test(c.body),
    occurred_at:c.updated_at||c.created_at,host:"github",boundary:"github_pr",stage:"certification",
    summary:c.body.split("\n")[0],evidence_run_ids:[String(c.id)],
    evidence:[{type:"comment",id:String(c.id),url:c.html_url||c.url}],url:c.html_url||c.url
  }));
}

export async function collectEvidence(gh,pr,exactHead){
  const [checkData,runData,comments]=await Promise.all([gh.checks(exactHead),gh.workflowRuns(),gh.issueComments(pr.number)]);
  const checks=checkData.check_runs||[],runs=runData.workflow_runs||[];
  const candidateRuns=runs.filter(run =>
    run.head_sha===exactHead ||
    /certification|guard|dispatcher|relay/i.test(run.name||"") ||
    /issue_comment/i.test(run.event||"")
  ).slice(0,12);
  const jobs=[];
  for(const run of candidateRuns){
    let js=[];
    try{js=(await gh.workflowJobs(run.id)).jobs||[]}catch{}
    for(const job of js.slice(0,12)){
      let resolved=run.head_sha===exactHead?exactHead:null;
      if(!resolved){
        try{resolved=resolveSourceShaFromLog((await gh.workflowJobLogs(job.id)).content)}catch{}
      }
      jobs.push(evidenceFromJob(job,run,resolved));
    }
  }
  const commentsEvidence=commentEvidence(comments,exactHead);
  return {checks,workflowRuns:runs,jobs,comments:commentsEvidence,all:[...checks,...jobs,...commentsEvidence]};
}
